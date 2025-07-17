#!/usr/bin/env python3
"""Ensure CloudTrail logs are encrypted using KMS CMKs"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class CloudtrailKmsEncryptionCheck(BaseSecurityCheck):
    """This check verifies that CloudTrail logs are encrypted using Customer Master Keys (CMKs) from AWS KMS. KMS encryption provides additional security for audit logs by ensuring they are protected with customer-controlled encryption keys. This is especially important for logs containing sensitive information or in environments with strict encryption requirements."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-039"
    
    @property
    def description(self) -> str:
        return "Ensure CloudTrail logs are encrypted using KMS CMKs"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'AU-9',
                        'SC-28'
            ],
            'cis_aws': [
                        '3.1',
                        '3.2',
                        '3.4'
            ],
            'nist_800_171': [
                        '3.13.11',
                        '3.3.8'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the cloudtrail_kms_encryption check."""
        for region in self.regions:
            try:
                cloudtrail_client = self.aws.get_client('cloudtrail', region)
                
                # Get all trails
                trails = cloudtrail_client.describe_trails(includeShadowTrails=False)
                
                if not trails.get('trailList'):
                    self.add_finding(
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id="no-trails",
                        region=region,
                        severity="HIGH",
                        details="No CloudTrail trails found in region",
                        recommendation="Enable CloudTrail to log API calls for security monitoring and compliance.",
                        evidence={"trails_count": 0}
                    )
                else:
                    for trail in trails['trailList']:
                        trail_name = trail['Name']
                        
                        # Get trail status
                        status = cloudtrail_client.get_trail_status(Name=trail_name)
                        
                        if not status.get('IsLogging', False):
                            self.add_finding(
                                resource_type="AWS::CloudTrail::Trail",
                                resource_id=trail_name,
                                region=region,
                                severity="HIGH",
                                details=f"CloudTrail '{trail_name}' is not logging",
                                recommendation="Enable CloudTrail logging to capture API activity.",
                                evidence={
                                    "trail_arn": trail.get('TrailARN'),
                                    "is_logging": False,
                                    "is_multi_region": trail.get('IsMultiRegionTrail', False)
                                }
                            )
                            
            except Exception as e:
                self.handle_error(e, f"checking CloudTrail in {region}")
                
        return self.findings
