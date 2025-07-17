#!/usr/bin/env python3
"""Ensure VPC endpoints are used for AWS services"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class VpcEndpointUsageCheck(BaseSecurityCheck):
    """This check verifies that VPC endpoints are configured for AWS services to enable private communication between VPC resources and AWS services without requiring internet gateway access. VPC endpoints enhance security by keeping traffic within the AWS network and reduce exposure to potential internet-based attacks."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-025"
    
    @property
    def description(self) -> str:
        return "Ensure VPC endpoints are used for AWS services"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'SC-7',
                        'AC-4'
            ],
            'aws_well_architected': [
                        'SEC-1',
                        'SEC-2',
                        'SEC-3'
            ],
            'nist_800_171': [
                        '3.13.5',
                        '3.13.1'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the vpc_endpoint_usage check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for ec2
                # client = self.aws.get_client('ec2', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking ec2 in {region}")
                
        return self.findings
