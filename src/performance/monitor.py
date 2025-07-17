"""Performance monitoring for compliance checks."""

import time
import psutil
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Monitor and track performance metrics for compliance checks."""
    
    def __init__(self):
        """Initialize performance monitor."""
        self.metrics = defaultdict(dict)
        self.start_times = {}
        self.api_call_counts = defaultdict(int)
        self.lock = threading.Lock()
        
        # System metrics at start
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.start_time = time.time()
        
    def start_check(self, check_id: str) -> None:
        """Mark the start of a check execution."""
        with self.lock:
            self.start_times[check_id] = {
                'start': time.time(),
                'api_calls': 0,
                'memory_start': psutil.Process().memory_info().rss / 1024 / 1024
            }
    
    def end_check(self, check_id: str, status: str = 'SUCCESS') -> None:
        """Mark the end of a check execution."""
        with self.lock:
            if check_id not in self.start_times:
                logger.warning(f"No start time recorded for check {check_id}")
                return
                
            start_data = self.start_times[check_id]
            end_time = time.time()
            memory_end = psutil.Process().memory_info().rss / 1024 / 1024
            
            self.metrics[check_id] = {
                'execution_time': end_time - start_data['start'],
                'api_calls': start_data['api_calls'],
                'memory_used': memory_end - start_data['memory_start'],
                'status': status,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            del self.start_times[check_id]
    
    def record_api_call(self, check_id: str, service: str, operation: str) -> None:
        """Record an API call for a check."""
        with self.lock:
            if check_id in self.start_times:
                self.start_times[check_id]['api_calls'] += 1
            
            # Track global API calls
            api_key = f"{service}.{operation}"
            self.api_call_counts[api_key] += 1
    
    def get_check_metrics(self, check_id: str) -> Optional[Dict[str, Any]]:
        """Get metrics for a specific check."""
        return self.metrics.get(check_id)
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for all checks."""
        with self.lock:
            if not self.metrics:
                return {}
            
            execution_times = [m['execution_time'] for m in self.metrics.values()]
            api_calls = [m['api_calls'] for m in self.metrics.values()]
            memory_usage = [m['memory_used'] for m in self.metrics.values()]
            
            total_time = time.time() - self.start_time
            current_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            return {
                'total_checks': len(self.metrics),
                'total_execution_time': total_time,
                'average_check_time': sum(execution_times) / len(execution_times),
                'min_check_time': min(execution_times),
                'max_check_time': max(execution_times),
                'total_api_calls': sum(api_calls),
                'average_api_calls_per_check': sum(api_calls) / len(api_calls),
                'memory_used_mb': current_memory - self.start_memory,
                'peak_memory_mb': max(memory_usage) if memory_usage else 0,
                'checks_per_second': len(self.metrics) / total_time if total_time > 0 else 0
            }
    
    def get_api_call_summary(self) -> Dict[str, int]:
        """Get summary of API calls by service and operation."""
        with self.lock:
            return dict(self.api_call_counts)
    
    def get_slow_checks(self, threshold_seconds: float = 10.0) -> List[Dict[str, Any]]:
        """Get checks that took longer than threshold."""
        slow_checks = []
        
        for check_id, metrics in self.metrics.items():
            if metrics['execution_time'] > threshold_seconds:
                slow_checks.append({
                    'check_id': check_id,
                    'execution_time': metrics['execution_time'],
                    'api_calls': metrics['api_calls']
                })
        
        return sorted(slow_checks, key=lambda x: x['execution_time'], reverse=True)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate a comprehensive performance report."""
        summary = self.get_summary_stats()
        
        # Add additional analysis
        if self.metrics:
            # Group checks by status
            status_counts = defaultdict(int)
            for metrics in self.metrics.values():
                status_counts[metrics['status']] += 1
            
            # Identify bottlenecks
            api_summary = self.get_api_call_summary()
            top_api_calls = sorted(
                api_summary.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
            
            slow_checks = self.get_slow_checks()
            
            return {
                'summary': summary,
                'status_breakdown': dict(status_counts),
                'slow_checks': slow_checks[:10],
                'top_api_calls': top_api_calls,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return {'summary': summary, 'timestamp': datetime.utcnow().isoformat()}


class ProgressTracker:
    """Track and display progress for long-running operations."""
    
    def __init__(self, total_items: int, update_interval: int = 10):
        """Initialize progress tracker."""
        self.total_items = total_items
        self.completed_items = 0
        self.update_interval = update_interval
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.last_update = 0
        
    def update(self, completed: int = 1) -> None:
        """Update progress."""
        with self.lock:
            self.completed_items += completed
            
            # Only log every N items or at completion
            if (self.completed_items % self.update_interval == 0 or 
                self.completed_items == self.total_items):
                self._log_progress()
    
    def _log_progress(self) -> None:
        """Log current progress."""
        elapsed = time.time() - self.start_time
        progress_pct = (self.completed_items / self.total_items) * 100
        
        if self.completed_items > 0:
            avg_time = elapsed / self.completed_items
            remaining = self.total_items - self.completed_items
            eta = remaining * avg_time
            
            logger.info(
                f"Progress: {self.completed_items}/{self.total_items} "
                f"({progress_pct:.1f}%) - "
                f"Elapsed: {elapsed:.1f}s - "
                f"ETA: {eta:.1f}s"
            )
        else:
            logger.info(f"Starting processing of {self.total_items} items...")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current progress statistics."""
        with self.lock:
            elapsed = time.time() - self.start_time
            progress_pct = (self.completed_items / self.total_items) * 100
            
            stats = {
                'completed': self.completed_items,
                'total': self.total_items,
                'progress_percentage': progress_pct,
                'elapsed_seconds': elapsed
            }
            
            if self.completed_items > 0:
                avg_time = elapsed / self.completed_items
                remaining = self.total_items - self.completed_items
                stats['average_time_per_item'] = avg_time
                stats['estimated_time_remaining'] = remaining * avg_time
                stats['estimated_total_time'] = self.total_items * avg_time
                
            return stats 