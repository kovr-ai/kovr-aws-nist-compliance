"""Parallel execution framework for security checks."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Callable, Set
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


@dataclass
class CheckGroup:
    """Group of related checks that can share resources."""
    name: str
    checks: List[Dict[str, Any]]
    dependencies: Set[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = set()


class ParallelExecutor:
    """Executes security checks in parallel with dependency management."""
    
    def __init__(self, max_workers: int = 10):
        """Initialize parallel executor."""
        self.max_workers = max_workers
        self.results = {}
        self.lock = threading.Lock()
        self.completed_checks = set()
        
    def group_checks_by_service(self, checks: List[Dict[str, Any]]) -> List[CheckGroup]:
        """Group checks by AWS service to optimize API calls."""
        service_groups = {}
        
        for check in checks:
            service = check.get('service', 'other')
            if service not in service_groups:
                service_groups[service] = []
            service_groups[service].append(check)
        
        # Create check groups
        groups = []
        for service, service_checks in service_groups.items():
            group = CheckGroup(
                name=f"{service}_checks",
                checks=service_checks
            )
            groups.append(group)
            
        return groups
    
    def identify_dependencies(self, checks: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """Identify dependencies between checks."""
        dependencies = {}
        
        # Define known dependencies
        dependency_map = {
            # Example dependencies
            'CHECK-084': {'CHECK-041'},  # Device Auth depends on EC2 malware check
            'CHECK-100': {'CHECK-017', 'CHECK-020'},  # Advanced monitoring depends on GuardDuty & Security Hub
            # Add more dependencies as needed
        }
        
        for check in checks:
            check_id = check['id']
            dependencies[check_id] = dependency_map.get(check_id, set())
            
        return dependencies
    
    def can_execute_check(self, check_id: str, dependencies: Dict[str, Set[str]]) -> bool:
        """Check if a check can be executed based on its dependencies."""
        check_deps = dependencies.get(check_id, set())
        with self.lock:
            return check_deps.issubset(self.completed_checks)
    
    def execute_check_group(self, 
                          group: CheckGroup, 
                          security_checker: Any,
                          progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Execute a group of checks in parallel."""
        results = []
        
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(group.checks))) as executor:
            # Submit all checks in the group
            future_to_check = {}
            
            for check in group.checks:
                future = executor.submit(security_checker.run_check, check)
                future_to_check[future] = check
            
            # Process completed checks
            for future in as_completed(future_to_check):
                check = future_to_check[future]
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Mark check as completed
                    with self.lock:
                        self.completed_checks.add(check['id'])
                    
                    # Call progress callback if provided
                    if progress_callback:
                        progress_callback(check['id'], result)
                        
                except Exception as e:
                    logger.error(f"Error executing check {check['id']}: {str(e)}")
                    # Create error result
                    error_result = {
                        'check_id': check['id'],
                        'check_name': check['name'],
                        'status': 'ERROR',
                        'error': str(e),
                        'timestamp': time.time()
                    }
                    results.append(error_result)
                    
        return results
    
    def execute_checks_parallel(self, 
                              checks: List[Dict[str, Any]], 
                              security_checker: Any,
                              progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Execute all checks in parallel with smart grouping."""
        # Group checks by service
        groups = self.group_checks_by_service(checks)
        
        # Identify dependencies
        dependencies = self.identify_dependencies(checks)
        
        # Sort groups by dependency order
        groups = self._sort_groups_by_dependencies(groups, dependencies)
        
        all_results = []
        total_checks = len(checks)
        completed = 0
        
        logger.info(f"Executing {total_checks} checks across {len(groups)} groups")
        
        # Execute groups in dependency order
        for group in groups:
            logger.info(f"Executing group: {group.name} with {len(group.checks)} checks")
            
            # Wait for dependencies if needed
            self._wait_for_dependencies(group, dependencies)
            
            # Execute the group
            start_time = time.time()
            group_results = self.execute_check_group(group, security_checker, progress_callback)
            execution_time = time.time() - start_time
            
            all_results.extend(group_results)
            completed += len(group_results)
            
            logger.info(f"Completed {group.name} in {execution_time:.2f}s "
                       f"({completed}/{total_checks} total)")
        
        return all_results
    
    def _sort_groups_by_dependencies(self, 
                                   groups: List[CheckGroup], 
                                   dependencies: Dict[str, Set[str]]) -> List[CheckGroup]:
        """Sort groups to respect dependencies."""
        # Simple topological sort - can be enhanced
        # For now, just ensure groups with no dependencies run first
        
        def has_external_dependencies(group: CheckGroup) -> bool:
            group_check_ids = {check['id'] for check in group.checks}
            for check in group.checks:
                check_deps = dependencies.get(check['id'], set())
                if check_deps - group_check_ids:  # Has deps outside the group
                    return True
            return False
        
        # Sort groups: those without external dependencies first
        return sorted(groups, key=lambda g: has_external_dependencies(g))
    
    def _wait_for_dependencies(self, 
                             group: CheckGroup, 
                             dependencies: Dict[str, Set[str]]) -> None:
        """Wait for all dependencies of a group to complete."""
        # Collect all dependencies for the group
        group_deps = set()
        for check in group.checks:
            group_deps.update(dependencies.get(check['id'], set()))
        
        # Wait for dependencies
        while not group_deps.issubset(self.completed_checks):
            time.sleep(0.1)  # Short sleep to avoid busy waiting
            
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        return {
            'completed_checks': len(self.completed_checks),
            'max_workers': self.max_workers
        }


class CheckExecutionOptimizer:
    """Optimizes check execution based on resource usage patterns."""
    
    def __init__(self):
        """Initialize optimizer."""
        self.execution_times = {}
        self.resource_usage = {}
        
    def record_execution(self, check_id: str, execution_time: float, api_calls: int) -> None:
        """Record execution metrics for a check."""
        self.execution_times[check_id] = execution_time
        self.resource_usage[check_id] = api_calls
        
    def suggest_grouping(self, checks: List[Dict[str, Any]]) -> List[CheckGroup]:
        """Suggest optimal grouping based on historical data."""
        # Group checks that use similar resources together
        # This is a simplified version - can be enhanced with ML
        
        resource_groups = {}
        
        for check in checks:
            # Group by service and estimated execution time
            service = check.get('service', 'other')
            severity = check.get('severity', 'MEDIUM')
            
            # Create a grouping key
            group_key = f"{service}_{severity}"
            
            if group_key not in resource_groups:
                resource_groups[group_key] = []
            resource_groups[group_key].append(check)
        
        # Convert to CheckGroups
        groups = []
        for key, group_checks in resource_groups.items():
            groups.append(CheckGroup(name=key, checks=group_checks))
            
        return groups
    
    def estimate_total_time(self, checks: List[Dict[str, Any]], parallel_factor: int) -> float:
        """Estimate total execution time based on historical data."""
        total_serial_time = 0
        
        for check in checks:
            check_id = check['id']
            # Use historical data or estimate
            estimated_time = self.execution_times.get(check_id, 5.0)  # Default 5 seconds
            total_serial_time += estimated_time
        
        # Estimate parallel execution time
        # This is simplified - actual time depends on grouping and dependencies
        estimated_parallel_time = total_serial_time / parallel_factor
        
        # Add overhead for coordination
        overhead = len(checks) * 0.1  # 0.1 second per check overhead
        
        return estimated_parallel_time + overhead 