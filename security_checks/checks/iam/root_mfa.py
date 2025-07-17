#!/usr/bin/env python3
"""Check for MFA on root account."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class RootMFACheck(BaseSecurityCheck):
    """Check that MFA is enabled for root account."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-002"
    
    @property
    def description(self) -> str:
        return "Ensure MFA is enabled for root account"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["IA-2"],
            "nist_800_171": ["3.5.1", "3.5.2", "3.5.3"],
            "cis_aws": ["1.5", "1.6"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the root MFA check."""
        try:
            iam_client = self.aws.get_client('iam', 'us-east-1')
            
            # Get account summary
            summary = iam_client.get_account_summary()
            summary_map = summary['SummaryMap']
            
            # Check if MFA is enabled for root
            if summary_map.get('AccountMFAEnabled', 0) == 0:
                self.add_finding(
                    resource_type="AWS::IAM::RootAccount",
                    resource_id="root-account",
                    region="global",
                    severity="CRITICAL",
                    details="Root account does not have MFA enabled",
                    recommendation="Enable MFA for the root account immediately to add an extra layer of security.",
                    evidence={"mfa_enabled": False}
                )
                
        except Exception as e:
            self.handle_error(e, "checking root MFA")
            
        return self.findings