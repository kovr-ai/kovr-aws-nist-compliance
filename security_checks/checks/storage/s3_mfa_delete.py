#!/usr/bin/env python3
"""Check S3 bucket MFA delete configuration."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class S3MFADeleteCheck(BaseSecurityCheck):
    """Check that S3 buckets with versioning have MFA delete enabled."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-065"
    
    @property
    def description(self) -> str:
        return "Ensure S3 buckets have MFA delete enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["2.1.2"],
            "nist_800_53": ["AC-2", "SC-28", "IA-2"],
            "nist_800_171": ["3.5.3", "3.13.11"],
            "owasp_cloud": ["OCST-3.1"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the S3 MFA delete check."""
        for region in self.regions:
            try:
                s3_client = self.aws.get_client('s3', region)
                
                # List all buckets
                if region == self.regions[0]:  # Only list buckets once
                    buckets = s3_client.list_buckets()
                    
                    for bucket in buckets.get('Buckets', []):
                        bucket_name = bucket['Name']
                        
                        try:
                            # Get bucket location
                            location = s3_client.get_bucket_location(Bucket=bucket_name)
                            bucket_region = location.get('LocationConstraint', 'us-east-1')
                            if bucket_region is None:
                                bucket_region = 'us-east-1'
                            
                            if bucket_region != region and region != 'us-east-1':
                                continue
                            
                            # Get versioning configuration
                            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                            
                            # Only check MFA delete if versioning is enabled
                            if versioning.get('Status') == 'Enabled':
                                if versioning.get('MFADelete') != 'Enabled':
                                    self.add_finding(
                                        resource_type="AWS::S3::Bucket",
                                        resource_id=bucket_name,
                                        region=bucket_region,
                                        severity="HIGH",
                                        details=f"S3 bucket '{bucket_name}' has versioning enabled but MFA delete is not configured",
                                        recommendation="Enable MFA delete on versioned S3 buckets to protect against accidental or malicious deletion of object versions.",
                                        evidence={
                                            "versioning_status": versioning.get('Status'),
                                            "mfa_delete_status": versioning.get('MFADelete', 'Disabled')
                                        }
                                    )
                                    
                        except Exception as e:
                            if 'AccessDenied' not in str(e):
                                self.handle_error(e, f"checking MFA delete for bucket {bucket_name}")
                                
            except Exception as e:
                self.handle_error(e, f"listing S3 buckets in {region}")
                
        return self.findings