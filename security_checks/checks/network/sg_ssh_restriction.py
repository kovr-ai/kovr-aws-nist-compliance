#!/usr/bin/env python3
"""Check security group SSH access restrictions."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class SecurityGroupSSHRestrictionCheck(BaseSecurityCheck):
    """Check that security groups don't allow unrestricted SSH access."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-070"
    
    @property
    def description(self) -> str:
        return "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["5.2"],
            "nist_800_53": ["AC-4", "SC-7", "CM-7"],
            "nist_800_171": ["3.1.3", "3.13.1", "3.4.6"],
            "mitre_attack": ["T1021.004"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the security group SSH restriction check."""
        for region in self.regions:
            try:
                ec2_client = self.aws.get_client('ec2', region)
                
                # Get all security groups
                paginator = ec2_client.get_paginator('describe_security_groups')
                
                for page in paginator.paginate():
                    for sg in page.get('SecurityGroups', []):
                        sg_id = sg['GroupId']
                        sg_name = sg.get('GroupName', 'N/A')
                        
                        # Check ingress rules
                        for rule in sg.get('IpPermissions', []):
                            # Check if this rule affects SSH port (22)
                            if (rule.get('IpProtocol') in ['-1', 'tcp'] and
                                (rule.get('FromPort') is None or rule.get('FromPort') <= 22) and
                                (rule.get('ToPort') is None or rule.get('ToPort') >= 22)):
                                
                                # Check for unrestricted access
                                unrestricted_ipv4 = any(
                                    ip_range.get('CidrIp') == '0.0.0.0/0'
                                    for ip_range in rule.get('IpRanges', [])
                                )
                                
                                unrestricted_ipv6 = any(
                                    ip_range.get('CidrIpv6') == '::/0'
                                    for ip_range in rule.get('Ipv6Ranges', [])
                                )
                                
                                if unrestricted_ipv4 or unrestricted_ipv6:
                                    self.add_finding(
                                        resource_type="AWS::EC2::SecurityGroup",
                                        resource_id=sg_id,
                                        region=region,
                                        severity="HIGH",
                                        details=f"Security group allows unrestricted SSH access from the internet",
                                        recommendation="Restrict SSH access to specific IP ranges or use Systems Manager Session Manager for secure access.",
                                        evidence={
                                            "group_name": sg_name,
                                            "vpc_id": sg.get('VpcId'),
                                            "unrestricted_ipv4": unrestricted_ipv4,
                                            "unrestricted_ipv6": unrestricted_ipv6,
                                            "rule_protocol": rule.get('IpProtocol'),
                                            "from_port": rule.get('FromPort'),
                                            "to_port": rule.get('ToPort')
                                        }
                                    )
                                    break  # Only report once per security group
                                    
            except Exception as e:
                self.handle_error(e, f"checking security groups in {region}")
                
        return self.findings