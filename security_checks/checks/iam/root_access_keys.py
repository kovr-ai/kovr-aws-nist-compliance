#!/usr/bin/env python3
"""Check for root account access keys."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class RootAccessKeysCheck(BaseSecurityCheck):
    """Check that root account has no access keys."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-061"
    
    @property
    def description(self) -> str:
        return "Ensure no root account access keys exist"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["1.4"],
            "nist_800_53": ["AC-2", "AC-3", "AC-6"],
            "nist_800_171": ["3.1.1", "3.1.2", "3.1.5"],
            "mitre_attack": ["T1078"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the root access keys check."""
        try:
            # Get credential report
            iam_client = self.aws.get_client('iam', 'us-east-1')
            
            # Generate credential report
            iam_client.generate_credential_report()
            
            # Get the credential report
            response = iam_client.get_credential_report()
            
            # Parse CSV content
            import csv
            import io
            
            csv_content = response['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_content))
            
            for row in reader:
                if row['user'] == '<root_account>':
                    # Check for access keys
                    if row.get('access_key_1_active') == 'true' or row.get('access_key_2_active') == 'true':
                        self.add_finding(
                            resource_type="AWS::IAM::RootAccount",
                            resource_id="root-account",
                            region="global",
                            severity="CRITICAL",
                            details="Root account has active access keys",
                            recommendation="Delete all root account access keys immediately. Use IAM users with appropriate permissions instead.",
                            evidence={
                                "access_key_1_active": row.get('access_key_1_active', 'false'),
                                "access_key_2_active": row.get('access_key_2_active', 'false')
                            }
                        )
                    break
                    
        except Exception as e:
            self.handle_error(e, "checking root access keys")
            
        return self.findings