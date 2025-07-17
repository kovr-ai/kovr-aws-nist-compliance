#!/usr/bin/env python3
"""Check S3 bucket versioning configuration."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class S3VersioningCheck(BaseSecurityCheck):
    """Check that S3 buckets have versioning enabled."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-064"
    
    @property
    def description(self) -> str:
        return "Ensure S3 buckets have versioning enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["2.1.3"],
            "nist_800_53": ["CP-10", "SC-16"],
            "nist_800_171": ["3.8.9", "3.13.11"],
            "aws_well_architected": ["REL-9"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the S3 versioning check."""
        for region in self.regions:
            try:
                s3_client = self.aws.get_client('s3', region)
                
                # List all buckets
                if region == self.regions[0]:  # Only list buckets once
                    buckets = s3_client.list_buckets()
                    
                    for bucket in buckets.get('Buckets', []):
                        bucket_name = bucket['Name']
                        
                        try:
                            # Get bucket location to ensure we check in the right region
                            location = s3_client.get_bucket_location(Bucket=bucket_name)
                            bucket_region = location.get('LocationConstraint', 'us-east-1')
                            if bucket_region is None:
                                bucket_region = 'us-east-1'
                            
                            if bucket_region != region and region != 'us-east-1':
                                continue
                            
                            # Get versioning configuration
                            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                            
                            # Check if versioning is enabled
                            if versioning.get('Status') != 'Enabled':
                                self.add_finding(
                                    resource_type="AWS::S3::Bucket",
                                    resource_id=bucket_name,
                                    region=bucket_region,
                                    severity="MEDIUM",
                                    details=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                                    recommendation="Enable versioning on the S3 bucket to protect against accidental deletion and provide data recovery capabilities.",
                                    evidence={
                                        "versioning_status": versioning.get('Status', 'Disabled'),
                                        "mfa_delete": versioning.get('MFADelete', 'Disabled')
                                    }
                                )
                                
                        except Exception as e:
                            if 'AccessDenied' not in str(e):
                                self.handle_error(e, f"checking versioning for bucket {bucket_name}")
                                
            except Exception as e:
                self.handle_error(e, f"listing S3 buckets in {region}")
                
        return self.findings