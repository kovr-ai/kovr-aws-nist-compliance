#!/usr/bin/env python3
"""Check for account manipulation detection capabilities."""

from typing import Any, Dict, List
from datetime import datetime, timedelta

from security_checks.base import BaseSecurityCheck


class AccountManipulationDetectionCheck(BaseSecurityCheck):
    """Check for monitoring of unauthorized IAM policy changes."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-071"
    
    @property
    def description(self) -> str:
        return "Monitor for unauthorized IAM policy changes"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "mitre_attack": ["T1098", "T1136"],
            "nist_800_53": ["AC-2", "AU-6", "SI-4"],
            "nist_800_171": ["3.1.1", "3.3.8", "3.14.6"],
            "zero_trust": ["ZT-3.2"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the account manipulation detection check."""
        critical_iam_actions = [
            'AttachUserPolicy',
            'DeleteUserPolicy',
            'DetachUserPolicy',
            'PutUserPolicy',
            'AttachRolePolicy',
            'DeleteRolePolicy',
            'DetachRolePolicy',
            'PutRolePolicy',
            'CreatePolicy',
            'DeletePolicy',
            'CreatePolicyVersion',
            'DeletePolicyVersion',
            'AttachGroupPolicy',
            'DeleteGroupPolicy',
            'DetachGroupPolicy',
            'PutGroupPolicy'
        ]
        
        for region in ['us-east-1']:  # CloudWatch alarms are typically in us-east-1
            try:
                cloudwatch_client = self.aws.get_client('cloudwatch', region)
                cloudtrail_client = self.aws.get_client('cloudtrail', region)
                
                # Check if there's a multi-region trail
                trails = cloudtrail_client.list_trails()
                multi_region_trail_exists = False
                
                for trail in trails.get('Trails', []):
                    trail_name = trail['Name']
                    trail_details = cloudtrail_client.describe_trails(trailNameList=[trail_name])
                    
                    for detail in trail_details.get('trailList', []):
                        if detail.get('IsMultiRegionTrail', False):
                            multi_region_trail_exists = True
                            break
                
                if not multi_region_trail_exists:
                    self.add_finding(
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id="account-trails",
                        region=region,
                        severity="HIGH",
                        details="No multi-region CloudTrail trail found for monitoring IAM changes",
                        recommendation="Create a multi-region CloudTrail trail to capture IAM API calls across all regions.",
                        evidence={"multi_region_trail": False}
                    )
                
                # Check for CloudWatch alarms on IAM policy changes
                metric_alarms = cloudwatch_client.describe_alarms()
                
                iam_policy_alarms = []
                for alarm in metric_alarms.get('MetricAlarms', []):
                    # Check if alarm monitors CloudTrail metrics
                    if alarm.get('Namespace') == 'CloudTrailMetrics':
                        # Check if it monitors IAM policy changes
                        for dimension in alarm.get('Dimensions', []):
                            if dimension.get('Name') == 'MetricName' and any(
                                action in dimension.get('Value', '') 
                                for action in critical_iam_actions
                            ):
                                iam_policy_alarms.append(alarm['AlarmName'])
                
                if not iam_policy_alarms:
                    self.add_finding(
                        resource_type="AWS::CloudWatch::Alarm",
                        resource_id="iam-policy-change-alarms",
                        region=region,
                        severity="HIGH",
                        details="No CloudWatch alarms configured for IAM policy changes",
                        recommendation="Create CloudWatch metric filters and alarms to monitor critical IAM policy modifications.",
                        evidence={
                            "monitored_actions": critical_iam_actions,
                            "alarms_found": []
                        }
                    )
                    
            except Exception as e:
                self.handle_error(e, f"checking account manipulation detection in {region}")
                
        return self.findings