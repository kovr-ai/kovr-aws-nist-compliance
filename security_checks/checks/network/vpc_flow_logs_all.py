#!/usr/bin/env python3
"""Check VPC flow logs configuration for all VPCs."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class VPCFlowLogsAllCheck(BaseSecurityCheck):
    """Check that all VPCs have flow logs enabled."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-069"
    
    @property
    def description(self) -> str:
        return "Ensure VPC flow logging is enabled in all VPCs"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["3.9"],
            "nist_800_53": ["AU-2", "AU-3", "AU-12", "SI-4"],
            "nist_800_171": ["3.3.1", "3.3.2", "3.14.6"],
            "csf": ["DE.AE-3"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the VPC flow logs check."""
        for region in self.regions:
            try:
                ec2_client = self.aws.get_client('ec2', region)
                
                # Get all VPCs
                vpcs = ec2_client.describe_vpcs()
                
                for vpc in vpcs.get('Vpcs', []):
                    vpc_id = vpc['VpcId']
                    
                    # Check if VPC has flow logs enabled
                    flow_logs = ec2_client.describe_flow_logs(
                        Filters=[
                            {
                                'Name': 'resource-id',
                                'Values': [vpc_id]
                            }
                        ]
                    )
                    
                    active_flow_logs = [
                        fl for fl in flow_logs.get('FlowLogs', [])
                        if fl.get('FlowLogStatus') == 'ACTIVE'
                    ]
                    
                    if not active_flow_logs:
                        vpc_name = 'N/A'
                        for tag in vpc.get('Tags', []):
                            if tag['Key'] == 'Name':
                                vpc_name = tag['Value']
                                break
                        
                        self.add_finding(
                            resource_type="AWS::EC2::VPC",
                            resource_id=vpc_id,
                            region=region,
                            severity="MEDIUM",
                            details=f"VPC does not have flow logs enabled",
                            recommendation="Enable VPC Flow Logs to capture network traffic information for security analysis and compliance.",
                            evidence={
                                "vpc_name": vpc_name,
                                "is_default": vpc.get('IsDefault', False),
                                "cidr_block": vpc.get('CidrBlock'),
                                "flow_logs_count": len(flow_logs.get('FlowLogs', []))
                            }
                        )
                        
            except Exception as e:
                self.handle_error(e, f"checking VPC flow logs in {region}")
                
        return self.findings