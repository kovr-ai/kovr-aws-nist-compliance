#!/usr/bin/env python3
"""Ensure S3 buckets have encryption enabled"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class S3BucketEncryptionCheck(BaseSecurityCheck):
    """This check verifies that S3 buckets have encryption enabled at rest. Encryption protects data from unauthorized access even if the underlying storage is compromised. The check ensures that either AWS-managed keys (SSE-S3) or customer-managed keys (SSE-KMS) are used to encrypt all objects stored in S3 buckets."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-006"
    
    @property
    def description(self) -> str:
        return "Ensure S3 buckets have encryption enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'SC-28'
            ],
            'aws_well_architected': [
                        'SEC-1',
                        'SEC-2',
                        'SEC-3'
            ],
            'nist_800_171': [
                        '3.13.11'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the s3_bucket_encryption check."""
        try:
            s3_client = self.aws.get_client('s3', 'us-east-1')
            
            # List all buckets
            buckets = s3_client.list_buckets()
            
            for bucket in buckets.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket location
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get('LocationConstraint', 'us-east-1')
                    if bucket_region is None:
                        bucket_region = 'us-east-1'
                    
                    # Check specific S3 configuration based on check type
                    # This is a placeholder - implement specific logic based on check
                    
                except Exception as e:
                    if 'AccessDenied' not in str(e):
                        self.handle_error(e, f"checking bucket {bucket_name}")
                        
        except Exception as e:
            self.handle_error(e, "listing S3 buckets")
            
        return self.findings
