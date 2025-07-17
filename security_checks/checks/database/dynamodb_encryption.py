#!/usr/bin/env python3
"""Ensure DynamoDB tables are encrypted at rest"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class DynamodbEncryptionCheck(BaseSecurityCheck):
    """This check verifies that DynamoDB tables are encrypted at rest. DynamoDB encryption protects data stored in NoSQL databases from unauthorized access, ensuring that sensitive information remains secure even if the underlying storage is compromised. This is critical for databases containing PII or other sensitive data."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-027"
    
    @property
    def description(self) -> str:
        return "Ensure DynamoDB tables are encrypted at rest"
    
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
        """Execute the dynamodb_encryption check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for dynamodb
                # client = self.aws.get_client('dynamodb', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking dynamodb in {region}")
                
        return self.findings
