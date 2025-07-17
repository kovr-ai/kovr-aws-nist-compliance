#!/usr/bin/env python3
"""Ensure IMDSv2 is enforced on EC2 instances"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class Ec2InstanceMetadataServiceV2Check(BaseSecurityCheck):
    """This check verifies that EC2 instances are configured to use IMDSv2 (Instance Metadata Service version 2) instead of IMDSv1. IMDSv2 provides enhanced security by requiring session authentication tokens, protecting against SSRF attacks that could access sensitive instance metadata. This is especially important for instances that may be exposed to untrusted input."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-012"
    
    @property
    def description(self) -> str:
        return "Ensure IMDSv2 is enforced on EC2 instances"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'AC-3',
                        'CM-7'
            ],
            'nist_800_171': [
                        '3.1.2',
                        '3.4.6',
                        '3.1.1',
                        '3.4.7'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the ec2_instance_metadata_service_v2 check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for ec2
                # client = self.aws.get_client('ec2', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking ec2 in {region}")
                
        return self.findings
