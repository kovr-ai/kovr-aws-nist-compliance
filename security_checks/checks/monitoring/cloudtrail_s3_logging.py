#!/usr/bin/env python3
"""Check CloudTrail S3 bucket logging configuration."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class CloudTrailS3LoggingCheck(BaseSecurityCheck):
    """Check that CloudTrail S3 buckets have access logging enabled."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-067"
    
    @property
    def description(self) -> str:
        return "Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["3.6"],
            "nist_800_53": ["AU-2", "AU-3", "AU-12"],
            "nist_800_171": ["3.3.1", "3.3.2"],
            "mitre_attack": ["T1530"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the CloudTrail S3 bucket logging check."""
        cloudtrail_buckets = set()
        
        # First, find all CloudTrail S3 buckets
        for region in self.regions:
            try:
                cloudtrail_client = self.aws.get_client('cloudtrail', region)
                
                # List all trails
                trails = cloudtrail_client.list_trails()
                
                for trail_info in trails.get('Trails', []):
                    trail_name = trail_info['Name']
                    
                    # Get trail details
                    trail = cloudtrail_client.describe_trails(trailNameList=[trail_name])
                    
                    for trail_detail in trail.get('trailList', []):
                        if 'S3BucketName' in trail_detail:
                            cloudtrail_buckets.add(trail_detail['S3BucketName'])
                            
            except Exception as e:
                self.handle_error(e, f"listing CloudTrails in {region}")
        
        # Now check logging on CloudTrail buckets
        if cloudtrail_buckets:
            s3_client = self.aws.get_client('s3', 'us-east-1')
            
            for bucket_name in cloudtrail_buckets:
                try:
                    # Get bucket logging configuration
                    logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                    
                    if 'LoggingEnabled' not in logging_config:
                        # Get bucket location for region info
                        location = s3_client.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location.get('LocationConstraint', 'us-east-1')
                        if bucket_region is None:
                            bucket_region = 'us-east-1'
                        
                        self.add_finding(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            region=bucket_region,
                            severity="MEDIUM",
                            details=f"CloudTrail S3 bucket '{bucket_name}' does not have access logging enabled",
                            recommendation="Enable S3 access logging on CloudTrail buckets to track access to audit logs.",
                            evidence={
                                "bucket_purpose": "CloudTrail logs",
                                "logging_enabled": False
                            }
                        )
                        
                except Exception as e:
                    if 'AccessDenied' not in str(e):
                        self.handle_error(e, f"checking logging for CloudTrail bucket {bucket_name}")
                        
        return self.findings