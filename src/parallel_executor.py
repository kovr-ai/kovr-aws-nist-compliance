#!/usr/bin/env python3
"""Parallel execution engine for security checks."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple

from tqdm import tqdm

logger = logging.getLogger(__name__)


@dataclass
class CheckExecutionTask:
    """Represents a check execution task."""
    check_id: str
    check_config: Dict[str, Any]
    regions: List[str]
    priority: int = 0  # Higher priority = execute first


class ParallelCheckExecutor:
    """Executes security checks in parallel with intelligent scheduling."""
    
    def __init__(
        self,
        aws_connector,
        max_workers: int = 10,
        rate_limit_delay: float = 0.1,
        progress_bar: bool = True
    ):
        """Initialize parallel executor.
        
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
        self.results_lock = Lock()
        self.api_call_times: Dict[str, float] = {}
        self.service_locks: Dict[str, Lock] = {}
        
    def execute_checks(
        self,
        checks: List[Dict[str, Any]],
        regions: Optional[List[str]] = None,
        skip_checks: Optional[List[str]] = None,
        specific_checks: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Execute checks in parallel.
        
        Args:
            checks: List of check configurations
            regions: Regions to check (None = all regions)
            skip_checks: Check IDs to skip
            specific_checks: Only run these specific check IDs
            
        Returns:
            List of check results
        """
        # Filter checks
        filtered_checks = self._filter_checks(checks, skip_checks, specific_checks)
        
        # Create execution tasks
        tasks = self._create_tasks(filtered_checks, regions)
        
        # Group tasks by service for intelligent scheduling
        service_groups = self._group_by_service(tasks)
        
        # Execute tasks
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Submit tasks with service-aware scheduling
            for service, service_tasks in service_groups.items():
                # Ensure service lock exists
                if service not in self.service_locks:
                    self.service_locks[service] = Lock()
                
                for task in service_tasks:
                    future = executor.submit(
                        self._execute_single_check,
                        task,
                        service
                    )
                    futures.append((future, task))
            
            # Process results with progress bar
            if self.progress_bar:
                futures_iter = tqdm(
                    as_completed([f[0] for f in futures]),
                    total=len(futures),
                    desc="Running checks"
                )
            else:
                futures_iter = as_completed([f[0] for f in futures])
            
            for completed_future in futures_iter:
                # Find the corresponding task
                task = None
                for future, t in futures:
                    if future == completed_future:
                        task = t
                        break
                
                try:
                    result = completed_future.result()
                    with self.results_lock:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error executing check {task.check_id}: {str(e)}")
                    # Add error result
                    error_result = {
                        "check_id": task.check_id,
                        "check_name": task.check_config.get("name", "Unknown"),
                        "status": "ERROR",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    with self.results_lock:
                        results.append(error_result)
        
        return results
    
    def _filter_checks(
        self,
        checks: List[Dict[str, Any]],
        skip_checks: Optional[List[str]],
        specific_checks: Optional[List[str]]
    ) -> List[Dict[str, Any]]:
        """Filter checks based on skip and specific lists."""
        filtered = []
        
        for check in checks:
            check_id = check["id"]
            
            # Skip if in skip list
            if skip_checks and check_id in skip_checks:
                continue
                
            # Skip if specific checks requested and not in list
            if specific_checks and check_id not in specific_checks:
                continue
                
            filtered.append(check)
        
        return filtered
    
    def _create_tasks(
        self,
        checks: List[Dict[str, Any]],
        regions: Optional[List[str]]
    ) -> List[CheckExecutionTask]:
        """Create execution tasks from checks."""
        tasks = []
        
        for check in checks:
            # Determine priority based on severity
            priority_map = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1
            }
            priority = priority_map.get(check.get("severity", "MEDIUM"), 2)
            
            task = CheckExecutionTask(
                check_id=check["id"],
                check_config=check,
                regions=regions or self.aws.get_all_regions(),
                priority=priority
            )
            tasks.append(task)
        
        # Sort by priority (highest first)
        tasks.sort(key=lambda t: t.priority, reverse=True)
        
        return tasks
    
    def _group_by_service(
        self,
        tasks: List[CheckExecutionTask]
    ) -> Dict[str, List[CheckExecutionTask]]:
        """Group tasks by AWS service."""
        groups = {}
        
        for task in tasks:
            service = task.check_config.get("service", "unknown")
            if service not in groups:
                groups[service] = []
            groups[service].append(task)
        
        return groups
    
    def _execute_single_check(
        self,
        task: CheckExecutionTask,
        service: str
    ) -> Dict[str, Any]:
        """Execute a single check with rate limiting."""
        from src.aws_connector import SecurityCheck
        
        # Apply rate limiting per service
        with self.service_locks[service]:
            # Check last API call time for this service
            last_call = self.api_call_times.get(service, 0)
            time_since_last = time.time() - last_call
            
            if time_since_last < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - time_since_last)
            
            # Update last call time
            self.api_call_times[service] = time.time()
        
        # Execute the check
        security_check = SecurityCheck(self.aws)
        result = security_check.run_check(task.check_config)
        
        return result
    
    def estimate_execution_time(
        self,
        num_checks: int,
        num_regions: int
    ) -> Tuple[float, float]:
        """Estimate execution time for checks.
        
        Args:
            num_checks: Number of checks to run
            num_regions: Number of regions to check
            
        Returns:
            Tuple of (min_time, max_time) in seconds
        """
        # Assume average check time of 2-5 seconds per region
        avg_check_time_min = 2
        avg_check_time_max = 5
        
        # Calculate total operations
        total_operations = num_checks * num_regions
        
        # With parallel execution
        parallel_factor = min(self.max_workers, total_operations)
        
        min_time = (total_operations * avg_check_time_min) / parallel_factor
        max_time = (total_operations * avg_check_time_max) / parallel_factor
        
        # Add overhead for rate limiting
        rate_limit_overhead = total_operations * self.rate_limit_delay / parallel_factor
        
        return (
            min_time + rate_limit_overhead,
            max_time + rate_limit_overhead
        )


class BatchCheckExecutor:
    """Executes checks in batches for very large environments."""
    
    def __init__(
        self,
        aws_connector,
        batch_size: int = 50,
        max_workers: int = 10
    ):
        """Initialize batch executor.
        
        Args:
            aws_connector: AWS connector instance
            batch_size: Number of checks per batch
            max_workers: Maximum concurrent workers per batch
        """
        self.aws = aws_connector
        self.batch_size = batch_size
        self.executor = ParallelCheckExecutor(
            aws_connector,
            max_workers=max_workers
        )
    
    def execute_checks_in_batches(
        self,
        checks: List[Dict[str, Any]],
        regions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Execute checks in batches.
        
        Args:
            checks: List of check configurations
            regions: Regions to check
            
        Returns:
            Combined results from all batches
        """
        all_results = []
        
        # Split checks into batches
        for i in range(0, len(checks), self.batch_size):
            batch = checks[i:i + self.batch_size]
            
            logger.info(f"Executing batch {i//self.batch_size + 1} of {len(checks)//self.batch_size + 1}")
            
            # Execute batch
            batch_results = self.executor.execute_checks(batch, regions)
            all_results.extend(batch_results)
            
            # Brief pause between batches
            if i + self.batch_size < len(checks):
                time.sleep(2)
        
        return all_results