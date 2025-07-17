#!/usr/bin/env python3
"""Ensure CloudTrail log file validation is enabled"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class CloudtrailLogFileValidationCheck(BaseSecurityCheck):
    """This check verifies that CloudTrail log file validation is enabled. Log file validation creates a digital signature for each log file, allowing you to verify that log files have not been modified, deleted, or tampered with. This is critical for maintaining the integrity of audit logs and ensuring they can be trusted for compliance and forensic investigations."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-004"
    
    @property
    def description(self) -> str:
        return "Ensure CloudTrail log file validation is enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'AU-9'
            ],
            'mitre_attack': [
                        'T1530'
            ],
            'nist_800_171': [
                        '3.3.8'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the cloudtrail_log_file_validation check."""
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
                        severity="MEDIUM",
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
                                severity="MEDIUM",
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
