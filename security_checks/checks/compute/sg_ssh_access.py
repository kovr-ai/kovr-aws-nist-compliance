#!/usr/bin/env python3
"""Ensure no security groups allow unrestricted SSH access"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class SecurityGroupSshAccessCheck(BaseSecurityCheck):
    """This check verifies that security groups do not allow unrestricted SSH access (port 22) from the internet (0.0.0.0/0). Unrestricted SSH access increases the attack surface and makes instances vulnerable to brute force attacks. SSH access should be restricted to specific IP ranges or VPN endpoints."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-008"
    
    @property
    def description(self) -> str:
        return "Ensure no security groups allow unrestricted SSH access"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'SC-7',
                        'AC-3'
            ],
            'cis_aws': [
                        '5.1',
                        '5.2',
                        '5.3'
            ],
            'nist_800_171': [
                        '3.1.2',
                        '3.13.5',
                        '3.1.1',
                        '3.13.1'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the security_group_ssh_access check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for ec2
                # client = self.aws.get_client('ec2', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking ec2 in {region}")
                
        return self.findings
