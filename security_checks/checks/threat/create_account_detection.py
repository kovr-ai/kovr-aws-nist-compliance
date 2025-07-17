#!/usr/bin/env python3
"""Check for new account creation detection."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class CreateAccountDetectionCheck(BaseSecurityCheck):
    """Check for monitoring of new IAM user/role creation."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-072"
    
    @property
    def description(self) -> str:
        return "Alert on new IAM user/role creation"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "mitre_attack": ["T1136", "T1078"],
            "nist_800_53": ["AC-2", "AU-6", "SI-4"],
            "nist_800_171": ["3.1.1", "3.3.8", "3.14.6"],
            "csa_ccm": ["IAM-12"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the create account detection check."""
        account_creation_actions = [
            'CreateUser',
            'CreateRole',
            'CreateAccessKey',
            'CreateLoginProfile',
            'CreateServiceSpecificCredential',
            'CreateGroup'
        ]
        
        for region in ['us-east-1']:  # CloudWatch alarms are typically in us-east-1
            try:
                cloudwatch_client = self.aws.get_client('cloudwatch', region)
                logs_client = self.aws.get_client('logs', region)
                
                # Check for CloudWatch log groups that might contain CloudTrail events
                log_groups = logs_client.describe_log_groups()
                cloudtrail_log_group = None
                
                for lg in log_groups.get('logGroups', []):
                    if 'cloudtrail' in lg['logGroupName'].lower():
                        cloudtrail_log_group = lg['logGroupName']
                        break
                
                if not cloudtrail_log_group:
                    self.add_finding(
                        resource_type="AWS::Logs::LogGroup",
                        resource_id="cloudtrail-logs",
                        region=region,
                        severity="MEDIUM",
                        details="No CloudTrail log group found for monitoring account creation",
                        recommendation="Configure CloudTrail to send logs to CloudWatch Logs for real-time monitoring.",
                        evidence={"cloudtrail_log_group": None}
                    )
                else:
                    # Check for metric filters on account creation
                    metric_filters = logs_client.describe_metric_filters(
                        logGroupName=cloudtrail_log_group
                    )
                    
                    creation_filters = []
                    for mf in metric_filters.get('metricFilters', []):
                        filter_pattern = mf.get('filterPattern', '')
                        if any(action in filter_pattern for action in account_creation_actions):
                            creation_filters.append(mf['filterName'])
                    
                    if not creation_filters:
                        self.add_finding(
                            resource_type="AWS::Logs::MetricFilter",
                            resource_id=f"{cloudtrail_log_group}-creation-filters",
                            region=region,
                            severity="MEDIUM",
                            details="No metric filters configured for account creation events",
                            recommendation="Create CloudWatch metric filters to detect IAM user and role creation events.",
                            evidence={
                                "log_group": cloudtrail_log_group,
                                "monitored_actions": account_creation_actions,
                                "filters_found": []
                            }
                        )
                    else:
                        # Check if there are alarms for these metrics
                        metric_alarms = cloudwatch_client.describe_alarms()
                        
                        creation_alarms = []
                        for alarm in metric_alarms.get('MetricAlarms', []):
                            if alarm.get('Namespace') == 'CloudTrailMetrics':
                                for creation_filter in creation_filters:
                                    if creation_filter in str(alarm):
                                        creation_alarms.append(alarm['AlarmName'])
                        
                        if not creation_alarms:
                            self.add_finding(
                                resource_type="AWS::CloudWatch::Alarm",
                                resource_id="account-creation-alarms",
                                region=region,
                                severity="MEDIUM",
                                details="Metric filters exist but no alarms configured for account creation",
                                recommendation="Create CloudWatch alarms for account creation metric filters to enable notifications.",
                                evidence={
                                    "metric_filters": creation_filters,
                                    "alarms_found": []
                                }
                            )
                            
            except Exception as e:
                self.handle_error(e, f"checking account creation detection in {region}")
                
        return self.findings