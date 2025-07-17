#!/usr/bin/env python3
"""Ensure CloudTrail is enabled in all regions"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class CloudtrailEnabledCheck(BaseSecurityCheck):
    """This check verifies that AWS CloudTrail is enabled and configured to log API calls across all AWS regions. CloudTrail provides a comprehensive audit trail of all API activity, including who made the request, when it was made, what resources were accessed, and from where. This is essential for security monitoring, compliance auditing, and incident response."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-003"
    
    @property
    def description(self) -> str:
        return "Ensure CloudTrail is enabled in all regions"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'AU-2',
                        'AU-3'
            ],
            'cis_aws': [
                        '3.1',
                        '3.2',
                        '3.4'
            ],
            'nist_800_171': [
                        '3.3.1',
                        '3.3.2'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the cloudtrail_enabled check."""
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
