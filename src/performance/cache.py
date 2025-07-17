"""Caching system for AWS API responses to optimize performance."""

import json
import time
from typing import Any, Dict, Optional, Tuple
from functools import wraps
import hashlib
import logging
from threading import Lock

logger = logging.getLogger(__name__)


class ResourceCache:
    """Thread-safe cache for AWS resource data."""
    
    def __init__(self, ttl_seconds: int = 300):
        """Initialize cache with time-to-live in seconds."""
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.ttl = ttl_seconds
        self.lock = Lock()
        self.hit_count = 0
        self.miss_count = 0
        
    def _make_key(self, service: str, operation: str, params: Dict[str, Any]) -> str:
        """Generate a unique cache key for the operation."""
        # Create a deterministic key from service, operation, and parameters
        key_data = {
            'service': service,
            'operation': operation,
            'params': params
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, service: str, operation: str, params: Dict[str, Any]) -> Optional[Any]:
        """Get cached data if available and not expired."""
        key = self._make_key(service, operation, params)
        
        with self.lock:
            if key in self.cache:
                data, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    self.hit_count += 1
                    logger.debug(f"Cache hit for {service}.{operation}")
                    return data
                else:
                    # Expired entry
                    del self.cache[key]
                    
            self.miss_count += 1
            return None
    
    def set(self, service: str, operation: str, params: Dict[str, Any], data: Any) -> None:
        """Store data in cache with current timestamp."""
        key = self._make_key(service, operation, params)
        
        with self.lock:
            self.cache[key] = (data, time.time())
            logger.debug(f"Cached {service}.{operation}")
    
    def clear(self) -> None:
        """Clear all cached data."""
        with self.lock:
            self.cache.clear()
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hit_count + self.miss_count
        hit_rate = (self.hit_count / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hit_count': self.hit_count,
            'miss_count': self.miss_count,
            'hit_rate': hit_rate,
            'cache_size': len(self.cache)
        }


class CacheManager:
    """Manages multiple caches for different resource types."""
    
    def __init__(self):
        """Initialize cache manager with separate caches for different TTLs."""
        # Different TTLs for different resource types
        self.caches = {
            'static': ResourceCache(ttl_seconds=600),      # 10 min for static resources
            'dynamic': ResourceCache(ttl_seconds=300),     # 5 min for dynamic resources  
            'frequent': ResourceCache(ttl_seconds=60),     # 1 min for frequently changing
        }
        
        # Mapping of operations to cache types
        self.cache_mapping = {
            # Static resources (change infrequently)
            'describe_regions': 'static',
            'describe_availability_zones': 'static',
            'get_account_summary': 'static',
            'list_roles': 'static',
            'list_users': 'static',
            'list_policies': 'static',
            
            # Dynamic resources (change occasionally)
            'describe_instances': 'dynamic',
            'describe_security_groups': 'dynamic',
            'describe_vpcs': 'dynamic',
            'describe_subnets': 'dynamic',
            'list_buckets': 'dynamic',
            'describe_db_instances': 'dynamic',
            'describe_volumes': 'dynamic',
            
            # Frequently changing resources
            'describe_alarms': 'frequent',
            'get_metric_statistics': 'frequent',
            'describe_trails': 'frequent',
        }
        
    def get_cache_for_operation(self, operation: str) -> ResourceCache:
        """Get the appropriate cache for an operation."""
        cache_type = self.cache_mapping.get(operation, 'dynamic')
        return self.caches[cache_type]
    
    def cached_boto3_call(self, client: Any, operation: str, **params) -> Any:
        """Execute a boto3 call with caching."""
        service = client._service_model.service_name
        cache = self.get_cache_for_operation(operation)
        
        # Check cache first
        cached_result = cache.get(service, operation, params)
        if cached_result is not None:
            return cached_result
        
        # Execute the actual call
        method = getattr(client, operation)
        result = method(**params)
        
        # Cache the result
        cache.set(service, operation, params, result)
        
        return result
    
    def clear_all(self) -> None:
        """Clear all caches."""
        for cache in self.caches.values():
            cache.clear()
            
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all caches."""
        stats = {}
        for name, cache in self.caches.items():
            stats[name] = cache.get_stats()
        return stats


def with_cache(cache_type: str = 'dynamic'):
    """Decorator for caching AWS API calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Extract client and operation info from function
            # This is a simplified example - real implementation would be more sophisticated
            if hasattr(self, '_cache_manager'):
                # Use caching logic
                return self._cache_manager.cached_boto3_call(*args, **kwargs)
            else:
                # No cache manager, execute normally
                return func(self, *args, **kwargs)
        return wrapper
    return decorator 