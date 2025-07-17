#!/usr/bin/env python3
"""Ensure Network ACLs do not allow unrestricted access"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class NetworkAclRulesCheck(BaseSecurityCheck):
    """This check verifies that Network ACLs (NACLs) are properly configured and do not allow unrestricted access to resources. NACLs provide an additional layer of network security by controlling traffic at the subnet level. Proper NACL configuration helps prevent unauthorized access and reduces the attack surface."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-029"
    
    @property
    def description(self) -> str:
        return "Ensure Network ACLs do not allow unrestricted access"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'SC-7',
                        'AC-4'
            ],
            'nist_800_171': [
                        '3.13.5',
                        '3.13.1'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the network_acl_rules check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for ec2
                # client = self.aws.get_client('ec2', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking ec2 in {region}")
                
        return self.findings
