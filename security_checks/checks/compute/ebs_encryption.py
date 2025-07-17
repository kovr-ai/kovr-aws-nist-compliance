#!/usr/bin/env python3
"""Ensure EBS volumes are encrypted"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class EbsVolumeEncryptionCheck(BaseSecurityCheck):
    """This check verifies that all EBS volumes are encrypted at rest. EBS encryption provides data protection for EC2 instances by encrypting data stored on attached volumes. This ensures that data remains secure even if the underlying storage infrastructure is compromised or if volumes are detached and moved."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-007"
    
    @property
    def description(self) -> str:
        return "Ensure EBS volumes are encrypted"
    
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
        """Execute the ebs_volume_encryption check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for ec2
                # client = self.aws.get_client('ec2', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking ec2 in {region}")
                
        return self.findings
