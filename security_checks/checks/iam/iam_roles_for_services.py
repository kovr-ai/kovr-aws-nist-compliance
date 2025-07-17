#!/usr/bin/env python3
"""Ensure EC2 instances use IAM roles instead of hardcoded credentials"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class IamRolesForServiceAccountsCheck(BaseSecurityCheck):
    """This check verifies that EC2 instances use IAM roles for accessing AWS services instead of hardcoded access keys. IAM roles provide temporary credentials that are automatically rotated, eliminating the security risk of hardcoded credentials that could be exposed or forgotten. This follows the principle of least privilege and reduces credential management overhead."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-032"
    
    @property
    def description(self) -> str:
        return "Ensure EC2 instances use IAM roles instead of hardcoded credentials"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'AC-2',
                        'IA-2'
            ],
            'nist_800_171': [
                        '3.5.1',
                        '3.1.1',
                        '3.1.2',
                        '3.5.2',
                        '3.5.3'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the iam_roles_for_service_accounts check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for iam
                # client = self.aws.get_client('iam', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking iam in {region}")
                
        return self.findings
