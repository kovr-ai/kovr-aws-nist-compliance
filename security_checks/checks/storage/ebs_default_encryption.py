#!/usr/bin/env python3
"""Check EBS default encryption configuration."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class EBSDefaultEncryptionCheck(BaseSecurityCheck):
    """Check that EBS default encryption is enabled."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-066"
    
    @property
    def description(self) -> str:
        return "Ensure EBS default encryption is enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "cis_aws": ["2.2.1"],
            "nist_800_53": ["SC-28", "SC-13"],
            "nist_800_171": ["3.13.11", "3.13.10"],
            "hipaa": ["164.312(a)(2)(iv)"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the EBS default encryption check."""
        for region in self.regions:
            try:
                ec2_client = self.aws.get_client('ec2', region)
                
                # Get EBS encryption by default status
                response = ec2_client.get_ebs_encryption_by_default()
                
                if not response.get('EbsEncryptionByDefault', False):
                    self.add_finding(
                        resource_type="AWS::EC2::EBSDefaultEncryption",
                        resource_id=f"ebs-default-encryption-{region}",
                        region=region,
                        severity="HIGH",
                        details=f"EBS default encryption is not enabled in region {region}",
                        recommendation="Enable EBS encryption by default to ensure all new EBS volumes are automatically encrypted.",
                        evidence={
                            "encryption_by_default": False,
                            "region": region
                        }
                    )
                else:
                    # Also check the default KMS key
                    try:
                        default_key = ec2_client.get_ebs_default_kms_key_id()
                        self.check_metadata[f"ebs_default_key_{region}"] = default_key.get('KmsKeyId')
                    except Exception:
                        pass
                        
            except Exception as e:
                self.handle_error(e, f"checking EBS default encryption in {region}")
                
        return self.findings