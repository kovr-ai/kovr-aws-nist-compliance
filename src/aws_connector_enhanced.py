#!/usr/bin/env python3
"""Enhanced AWS Connector with performance optimization."""

import logging
from typing import Any, Dict, List, Optional

from aws_connector import AWSConnector as BaseAWSConnector, SecurityCheck as BaseSecurityCheck
from performance.cache import CacheManager

logger = logging.getLogger(__name__)


class EnhancedAWSConnector(BaseAWSConnector):
    """AWS Connector with caching and performance optimizations."""
    
    def __init__(self, *args, **kwargs):
        """Initialize enhanced connector with cache manager."""
        super().__init__(*args, **kwargs)
        self.cache_manager = CacheManager()
        self._regions_cache = None
        
    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """Get boto3 client with potential caching wrapper."""
        client = super().get_client(service_name, region)
        # Wrap client methods with caching
        return CachedClient(client, self.cache_manager)
    
    def get_all_regions(self) -> List[str]:
        """Get all available AWS regions with caching."""
        if self._regions_cache is not None:
            return self._regions_cache
            
        self._regions_cache = super().get_all_regions()
        return self._regions_cache
    
    def clear_cache(self) -> None:
        """Clear all caches."""
        self.cache_manager.clear_all()
        self._regions_cache = None


class CachedClient:
    """Wrapper for boto3 clients that adds caching."""
    
    def __init__(self, client: Any, cache_manager: CacheManager):
        """Initialize cached client wrapper."""
        self._client = client
        self._cache_manager = cache_manager
        
    def __getattr__(self, name: str) -> Any:
        """Intercept method calls and add caching where appropriate."""
        original_method = getattr(self._client, name)
        
        # Check if this method should be cached
        cacheable_methods = {
            'describe_instances', 'describe_security_groups', 'describe_vpcs',
            'describe_subnets', 'list_buckets', 'describe_db_instances',
            'describe_volumes', 'describe_regions', 'list_users', 'list_roles',
            'describe_trails', 'describe_alarms', 'get_account_summary'
        }
        
        if name in cacheable_methods:
            def cached_method(**kwargs):
                return self._cache_manager.cached_boto3_call(
                    self._client, name, **kwargs
                )
            return cached_method
        
        return original_method


class EnhancedSecurityCheck(BaseSecurityCheck):
    """Security check with performance enhancements."""
    
    def __init__(self, aws_connector: EnhancedAWSConnector):
        """Initialize enhanced security check."""
        super().__init__(aws_connector)
        self.aws = aws_connector  # Ensure we use enhanced connector
        
    def run_check(self, check_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run check with performance tracking."""
        # The performance monitoring is handled by main.py
        # This could be extended to track per-check metrics
        return super().run_check(check_config)
    
    # Override methods that can benefit from batch operations
    def check_multiple_resources_batch(self, 
                                     resource_type: str,
                                     check_function: callable,
                                     regions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Check multiple resources across regions with optimized batching."""
        findings = []
        
        if regions is None:
            regions = self.aws.get_all_regions()
        
        # Group regions into batches for parallel processing
        # This is a placeholder - actual implementation would use ThreadPoolExecutor
        for region in regions:
            try:
                region_findings = check_function(region)
                findings.extend(region_findings)
            except Exception as e:
                logger.error(f"Error checking {resource_type} in {region}: {str(e)}")
                
        return findings 