#!/usr/bin/env python3
"""Check IAM password policy requirements."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class PasswordPolicyUppercaseCheck(BaseSecurityCheck):
    """Check that IAM password policy requires uppercase letters."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-062"
    
    @property
    def description(self) -> str:
        return "Ensure IAM password policy requires uppercase letters"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["1.8"],
            "nist_800_53": ["IA-5", "AC-2"],
            "nist_800_171": ["3.5.7", "3.5.8"],
            "owasp_cloud": ["OCST-1.2"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the password policy uppercase check."""
        try:
            iam_client = self.aws.get_client('iam', 'us-east-1')
            
            # Get account password policy
            response = iam_client.get_account_password_policy()
            policy = response['PasswordPolicy']
            
            # Check if uppercase is required
            if not policy.get('RequireUppercaseCharacters', False):
                self.add_finding(
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_id="account-password-policy",
                    region="global",
                    severity="MEDIUM",
                    details="IAM password policy does not require uppercase letters",
                    recommendation="Update the password policy to require at least one uppercase letter for stronger password complexity.",
                    evidence={
                        "require_uppercase": policy.get('RequireUppercaseCharacters', False),
                        "require_lowercase": policy.get('RequireLowercaseCharacters', False),
                        "require_numbers": policy.get('RequireNumbers', False),
                        "require_symbols": policy.get('RequireSymbols', False),
                        "minimum_length": policy.get('MinimumPasswordLength', 0)
                    }
                )
                
        except Exception as e:
            if 'NoSuchEntity' in str(e):
                self.add_finding(
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_id="account-password-policy",
                    region="global",
                    severity="HIGH",
                    details="No IAM password policy is configured",
                    recommendation="Create an IAM password policy with strong complexity requirements including uppercase letters.",
                    evidence={"policy_exists": False}
                )
            else:
                self.handle_error(e, "checking password policy")
                
        return self.findings