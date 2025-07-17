#!/usr/bin/env python3
"""Check for immutable backup configurations."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class ImmutableBackupsCheck(BaseSecurityCheck):
    """Check that critical data has immutable backup protection."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-074"
    
    @property
    def description(self) -> str:
        return "Implement immutable backups"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "mitre_attack": ["T1485", "T1486", "T1490"],
            "nist_800_53": ["CP-9", "SC-28", "SI-12"],
            "nist_800_171": ["3.8.9", "3.13.11", "3.14.2"],
            "ransomware": ["RAN-1.1"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the immutable backups check."""
        for region in self.regions:
            try:
                # Check AWS Backup vault locks
                self._check_backup_vault_locks(region)
                
                # Check S3 Object Lock
                self._check_s3_object_lock(region)
                
            except Exception as e:
                self.handle_error(e, f"checking immutable backups in {region}")
                
        return self.findings
    
    def _check_backup_vault_locks(self, region: str) -> None:
        """Check AWS Backup vault lock configuration."""
        try:
            backup_client = self.aws.get_client('backup', region)
            
            # List backup vaults
            vaults = backup_client.list_backup_vaults()
            
            for vault in vaults.get('BackupVaultList', []):
                vault_name = vault['BackupVaultName']
                
                # Skip default vault as it can't be locked
                if vault_name == 'Default':
                    continue
                
                # Check vault lock status
                try:
                    vault_lock = backup_client.describe_backup_vault(
                        BackupVaultName=vault_name
                    )
                    
                    # Check if vault has lock configuration
                    if not vault_lock.get('Locked', False):
                        # Check if this vault contains any recovery points
                        recovery_points = backup_client.list_recovery_points_by_backup_vault(
                            BackupVaultName=vault_name,
                            MaxResults=1
                        )
                        
                        if recovery_points.get('RecoveryPoints'):
                            self.add_finding(
                                resource_type="AWS::Backup::BackupVault",
                                resource_id=vault_name,
                                region=region,
                                severity="HIGH",
                                details=f"Backup vault '{vault_name}' contains recovery points but is not locked",
                                recommendation="Enable vault lock to make backups immutable and protect against ransomware.",
                                evidence={
                                    "vault_arn": vault.get('BackupVaultArn'),
                                    "locked": False,
                                    "has_recovery_points": True,
                                    "min_retention_days": vault_lock.get('MinRetentionDays'),
                                    "max_retention_days": vault_lock.get('MaxRetentionDays')
                                }
                            )
                            
                except Exception as e:
                    if 'ResourceNotFoundException' not in str(e):
                        self.handle_error(e, f"checking vault lock for {vault_name}")
                        
        except Exception as e:
            self.handle_error(e, f"checking backup vault locks in {region}")
    
    def _check_s3_object_lock(self, region: str) -> None:
        """Check S3 Object Lock configuration."""
        try:
            s3_client = self.aws.get_client('s3', region)
            
            # List buckets (only once)
            if region == self.regions[0]:
                buckets = s3_client.list_buckets()
                
                for bucket in buckets.get('Buckets', []):
                    bucket_name = bucket['Name']
                    
                    try:
                        # Check bucket location
                        location = s3_client.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location.get('LocationConstraint', 'us-east-1')
                        if bucket_region is None:
                            bucket_region = 'us-east-1'
                        
                        if bucket_region != region and region != 'us-east-1':
                            continue
                        
                        # Check if bucket has important data (by tags or name patterns)
                        is_critical = False
                        try:
                            tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
                            for tag in tags.get('TagSet', []):
                                if tag['Key'].lower() in ['backup', 'critical', 'production']:
                                    is_critical = True
                                    break
                        except:
                            # Check name patterns
                            if any(pattern in bucket_name.lower() for pattern in ['backup', 'archive', 'critical']):
                                is_critical = True
                        
                        if is_critical:
                            # Check Object Lock configuration
                            try:
                                object_lock = s3_client.get_object_lock_configuration(
                                    Bucket=bucket_name
                                )
                                
                                if object_lock.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') != 'Enabled':
                                    raise Exception("Object Lock not enabled")
                                    
                            except:
                                self.add_finding(
                                    resource_type="AWS::S3::Bucket",
                                    resource_id=bucket_name,
                                    region=bucket_region,
                                    severity="HIGH",
                                    details=f"Critical S3 bucket '{bucket_name}' does not have Object Lock enabled",
                                    recommendation="Enable S3 Object Lock in compliance mode to create immutable backups.",
                                    evidence={
                                        "bucket_name": bucket_name,
                                        "identified_as_critical": True,
                                        "object_lock_enabled": False
                                    }
                                )
                                
                    except Exception as e:
                        if 'AccessDenied' not in str(e) and 'NoSuchBucket' not in str(e):
                            self.handle_error(e, f"checking Object Lock for bucket {bucket_name}")
                            
        except Exception as e:
            self.handle_error(e, f"checking S3 Object Lock in {region}")