#!/usr/bin/env python3
"""Ensure RDS databases are encrypted at rest"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class RdsEncryptionCheck(BaseSecurityCheck):
    """This check verifies that RDS database instances are encrypted at rest. Database encryption protects sensitive data stored in databases from unauthorized access, even if the underlying storage is compromised. This is especially important for databases containing personally identifiable information (PII) or other sensitive data."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-014"
    
    @property
    def description(self) -> str:
        return "Ensure RDS databases are encrypted at rest"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'SC-28'
            ],
            'nist_800_171': [
                        '3.13.11'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the rds_encryption check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for rds
                # client = self.aws.get_client('rds', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking rds in {region}")
                
        return self.findings
