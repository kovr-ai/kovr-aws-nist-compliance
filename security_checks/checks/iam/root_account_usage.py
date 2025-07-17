#!/usr/bin/env python3
"""Check for root account usage."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class RootAccountUsageCheck(BaseSecurityCheck):
    """Check that root account is not used for daily operations."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-001"
    
    @property
    def description(self) -> str:
        return "Ensure root account is not used for daily operations"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["AC-2", "AC-6"],
            "nist_800_171": ["3.1.1", "3.1.2", "3.1.5", "3.1.6"],
            "cis_aws": ["1.1"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the root account usage check."""
        try:
            # Get credential report
            iam_client = self.aws.get_client('iam', 'us-east-1')
            
            # Generate credential report (might take a moment)
            try:
                iam_client.generate_credential_report()
            except:
                pass  # Report might already be generating
            
            # Get the credential report
            import time
            response = None
            for _ in range(5):  # Try up to 5 times
                try:
                    response = iam_client.get_credential_report()
                    break
                except iam_client.exceptions.CredentialReportNotPresentException:
                    time.sleep(1)
                except:
                    break
            
            if not response:
                return self.findings
            
            # Parse CSV content
            import csv
            import io
            
            csv_content = response['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_content))
            
            for row in reader:
                if row['user'] == '<root_account>':
                    # Check for recent password usage
                    if row.get('password_last_used') and row['password_last_used'] != 'N/A':
                        last_used = datetime.fromisoformat(row['password_last_used'].replace('+00:00', '+00:00'))
                        days_ago = (datetime.now(timezone.utc) - last_used).days
                        
                        if days_ago < 30:
                            self.add_finding(
                                resource_type="AWS::IAM::RootAccount",
                                resource_id="root-account",
                                region="global",
                                severity="CRITICAL",
                                details=f"Root account was used {days_ago} days ago",
                                recommendation="Use IAM users with appropriate permissions instead of root account for daily operations.",
                                evidence={
                                    "password_last_used": row['password_last_used'],
                                    "days_since_use": days_ago
                                }
                            )
                    
                    # Check for access keys
                    if row.get('access_key_1_active') == 'true':
                        # Check when key was last used
                        key_last_used = row.get('access_key_1_last_used_date', 'N/A')
                        self.add_finding(
                            resource_type="AWS::IAM::RootAccount",
                            resource_id="root-account-key-1",
                            region="global",
                            severity="CRITICAL",
                            details="Root account has active access key 1",
                            recommendation="Delete root account access keys immediately. Use IAM users instead.",
                            evidence={
                                "access_key_1_active": True,
                                "access_key_1_last_used": key_last_used
                            }
                        )
                    
                    if row.get('access_key_2_active') == 'true':
                        key_last_used = row.get('access_key_2_last_used_date', 'N/A')
                        self.add_finding(
                            resource_type="AWS::IAM::RootAccount",
                            resource_id="root-account-key-2",
                            region="global",
                            severity="CRITICAL",
                            details="Root account has active access key 2",
                            recommendation="Delete root account access keys immediately. Use IAM users instead.",
                            evidence={
                                "access_key_2_active": True,
                                "access_key_2_last_used": key_last_used
                            }
                        )
                    break
                    
        except Exception as e:
            self.handle_error(e, "checking root account usage")
            
        return self.findings