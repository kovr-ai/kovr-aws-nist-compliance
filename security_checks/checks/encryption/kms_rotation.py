#!/usr/bin/env python3
"""Check KMS key rotation configuration."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class KMSKeyRotationCheck(BaseSecurityCheck):
    """Check that customer-managed KMS keys have rotation enabled."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-068"
    
    @property
    def description(self) -> str:
        return "Ensure rotation for customer-created KMS keys is enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["3.8"],
            "nist_800_53": ["SC-12", "SC-13"],
            "nist_800_171": ["3.13.10", "3.13.11"],
            "pci_dss": ["3.6.4"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the KMS key rotation check."""
        for region in self.regions:
            try:
                kms_client = self.aws.get_client('kms', region)
                
                # List all KMS keys
                paginator = kms_client.get_paginator('list_keys')
                
                for page in paginator.paginate():
                    for key in page.get('Keys', []):
                        key_id = key['KeyId']
                        
                        try:
                            # Get key metadata
                            key_metadata = kms_client.describe_key(KeyId=key_id)
                            key_info = key_metadata['KeyMetadata']
                            
                            # Skip AWS managed keys and keys pending deletion
                            if (key_info.get('KeyManager') == 'AWS' or 
                                key_info.get('KeyState') != 'Enabled'):
                                continue
                            
                            # Check rotation status for customer managed keys
                            rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)
                            
                            if not rotation_status.get('KeyRotationEnabled', False):
                                self.add_finding(
                                    resource_type="AWS::KMS::Key",
                                    resource_id=key_id,
                                    region=region,
                                    severity="MEDIUM",
                                    details=f"Customer-managed KMS key does not have automatic rotation enabled",
                                    recommendation="Enable automatic key rotation to limit the amount of data encrypted under a single key version.",
                                    evidence={
                                        "key_arn": key_info.get('Arn'),
                                        "key_usage": key_info.get('KeyUsage'),
                                        "creation_date": key_info.get('CreationDate').isoformat() if key_info.get('CreationDate') else None,
                                        "rotation_enabled": False
                                    }
                                )
                                
                        except Exception as e:
                            if 'AccessDenied' not in str(e):
                                self.handle_error(e, f"checking rotation for key {key_id}")
                                
            except Exception as e:
                self.handle_error(e, f"listing KMS keys in {region}")
                
        return self.findings