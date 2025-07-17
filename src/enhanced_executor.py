#!/usr/bin/env python3
"""Enhanced parallel execution engine using modular checks."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock
from typing import Any, Dict, List, Optional, Set

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Fallback progress indicator
    class tqdm:
        def __init__(self, iterable, **kwargs):
            self.iterable = iterable
            self.total = kwargs.get('total', 0)
            self.desc = kwargs.get('desc', '')
            
        def __iter__(self):
            if self.desc:
                print(f"{self.desc}: {self.total} items")
            return iter(self.iterable)

from check_loader import CheckLoader
from aws_connector import AWSConnector

logger = logging.getLogger(__name__)


class EnhancedExecutor:
    """Executes modular security checks in parallel."""
    
    def __init__(
        self,
        aws_connector: AWSConnector,
        max_workers: int = 20,
        rate_limit_delay: float = 0.05,
        progress_bar: bool = True
    ):
        """Initialize enhanced executor.
        
        Args:
            aws_connector: AWS connector instance
            max_workers: Maximum number of concurrent workers
            rate_limit_delay: Delay between API calls to avoid throttling
            progress_bar: Whether to show progress bar
        """
        self.aws = aws_connector
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.progress_bar = progress_bar
        self.check_loader = CheckLoader()
        self.service_locks: Dict[str, Lock] = {}
        
    def execute_all_checks(
        self,
        regions: Optional[List[str]] = None,
        skip_checks: Optional[List[str]] = None,
        specific_checks: Optional[List[str]] = None,
        min_severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Execute all enabled checks in parallel.
        
        Args:
            regions: Regions to check (None = all regions)
            skip_checks: Check IDs to skip
            specific_checks: Only run these specific check IDs
            min_severity: Minimum severity level
            
        Returns:
            List of check results
        """
        # Get all checks from configuration
        all_checks = self.check_loader.get_all_checks()
        logger.info(f"Loaded {len(all_checks)} total checks from configuration")
        
        # Filter checks
        filtered_checks = self._filter_checks(
            all_checks, 
            skip_checks, 
            specific_checks,
            min_severity
        )
        logger.info(f"Executing {len(filtered_checks)} checks after filtering")
        
        # Group by service for intelligent scheduling
        service_groups = self._group_by_service(filtered_checks)
        
        # Execute checks
        results = []
        failed_checks = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Submit tasks by service group
            for service, checks in service_groups.items():
                # Ensure service lock exists
                if service not in self.service_locks:
                    self.service_locks[service] = Lock()
                
                for check_config in checks:
                    future = executor.submit(
                        self._execute_single_check,
                        check_config,
                        regions,
                        service
                    )
                    futures.append((future, check_config))
            
            # Process results with progress bar
            if self.progress_bar:
                futures_iter = tqdm(
                    as_completed([f[0] for f in futures]),
                    total=len(futures),
                    desc="Executing checks",
                    unit="check"
                )
            else:
                futures_iter = as_completed([f[0] for f in futures])
            
            # Collect results
            for future in futures_iter:
                # Find corresponding check config
                check_config = None
                for f, config in futures:
                    if f == future:
                        check_config = config
                        break
                
                try:
                    result = future.result(timeout=300)  # 5 minute timeout
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Check {check_config['id']} failed: {e}")
                    failed_checks.append({
                        'check_id': check_config['id'],
                        'error': str(e)
                    })
                    
        # Log summary
        logger.info(f"Completed {len(results)} checks successfully")
        if failed_checks:
            logger.warning(f"{len(failed_checks)} checks failed or could not be loaded")
            for failed in failed_checks:
                logger.debug(f"Failed: {failed['check_id']} - {failed['error']}")
                
        return results
    
    def _filter_checks(
        self,
        all_checks: List[Dict[str, Any]],
        skip_checks: Optional[List[str]],
        specific_checks: Optional[List[str]],
        min_severity: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Filter checks based on criteria."""
        filtered = all_checks
        
        # Apply specific checks filter
        if specific_checks:
            filtered = [c for c in filtered if c['id'] in specific_checks]
            
        # Apply skip checks filter
        if skip_checks:
            filtered = [c for c in filtered if c['id'] not in skip_checks]
            
        # Apply severity filter
        if min_severity:
            severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            min_index = severity_order.index(min_severity)
            filtered = [
                c for c in filtered 
                if severity_order.index(c['severity']) >= min_index
            ]
            
        return filtered
    
    def _group_by_service(
        self, 
        checks: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group checks by AWS service."""
        groups = {}
        for check in checks:
            service = check['service']
            if service not in groups:
                groups[service] = []
            groups[service].append(check)
        return groups
    
    def _execute_single_check(
        self,
        check_config: Dict[str, Any],
        regions: Optional[List[str]],
        service: str
    ) -> Optional[Dict[str, Any]]:
        """Execute a single check with rate limiting."""
        check_id = check_config['id']
        
        try:
            # Rate limiting per service
            with self.service_locks[service]:
                time.sleep(self.rate_limit_delay)
            
            # Instantiate check
            check_instance = self.check_loader.instantiate_check(
                check_id,
                self.aws,
                regions
            )
            
            if not check_instance:
                logger.debug(f"Skipping {check_id} - module not implemented")
                return None
            
            # Execute check
            start_time = time.time()
            findings = check_instance.execute()
            execution_time = time.time() - start_time
            
            # Get check result
            result = check_instance.get_check_result()
            result['execution_time'] = execution_time
            result['severity'] = check_config['severity']
            result['service'] = check_config['service']
            result['category'] = check_config['category']
            result['framework'] = check_config.get('framework_source', 'Multiple')
            
            # Add affected resources for backward compatibility
            if findings:
                result['affected_resources'] = [
                    f"{f['type']}:{f['id']}" for f in findings
                ]
            else:
                result['affected_resources'] = []
                
            logger.debug(f"Check {check_id} completed in {execution_time:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Error executing check {check_id}: {e}")
            # Return error result
            return {
                'check_id': check_id,
                'check_name': check_config['name'],
                'status': 'ERROR',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat(),
                'findings': [],
                'affected_resources': [],
                'severity': check_config['severity'],
                'service': check_config['service']
            }