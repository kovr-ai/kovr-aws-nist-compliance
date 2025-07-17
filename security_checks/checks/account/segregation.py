#!/usr/bin/env python3
"""Ensure production accounts are separated"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class SegregationOfProductionCheck(BaseSecurityCheck):
    """This check verifies that production workloads are isolated in separate AWS accounts from development and testing environments. Account separation provides strong security boundaries and prevents accidental or intentional cross-environment access."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-076"
    
    @property
    def description(self) -> str:
        return "Ensure production accounts are separated"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'aws_well_architected': [
                        'SEC-1'
            ],
            'nist_800_53': [
                        'SC-32'
            ],
            'nist_800_171': [
                        '3.13.2'
            ],
            'zero_trust': [
                        'ZT-4.4'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the segregation_of_production check."""
        try:
            # Check Organizations service
            org_client = self.aws.get_client('organizations', 'us-east-1')
            
            # Check if Organizations is enabled
            try:
                org_info = org_client.describe_organization()
                organization = org_info['Organization']
                
                # Check for organizational units
                roots = org_client.list_roots()
                root_id = roots['Roots'][0]['Id']
                
                # List OUs
                ous = org_client.list_organizational_units_for_parent(ParentId=root_id)
                
                # Look for production/non-production separation
                ou_names = [ou['Name'].lower() for ou in ous.get('OrganizationalUnits', [])]
                
                has_prod_ou = any('prod' in name for name in ou_names)
                has_dev_ou = any(name in ['dev', 'development', 'test', 'staging'] for name in ou_names)
                
                if not (has_prod_ou and has_dev_ou):
                    # Check account tags for environment separation
                    accounts = org_client.list_accounts()
                    
                    prod_accounts = 0
                    non_prod_accounts = 0
                    
                    for account in accounts.get('Accounts', []):
                        # Get account tags
                        try:
                            tags = org_client.list_tags_for_resource(
                                ResourceId=account['Id']
                            )
                            
                            for tag in tags.get('Tags', []):
                                if tag['Key'].lower() in ['environment', 'env']:
                                    if 'prod' in tag['Value'].lower():
                                        prod_accounts += 1
                                    else:
                                        non_prod_accounts += 1
                                    break
                        except:
                            pass
                    
                    if prod_accounts == 0 or non_prod_accounts == 0:
                        self.add_finding(
                            resource_type="AWS::Organizations::Account",
                            resource_id=self.aws.account_id,
                            region="global",
                            severity="HIGH",
                            details="No clear separation between production and non-production accounts detected",
                            recommendation="Implement account separation strategy using Organizations OUs or consistent tagging to isolate production workloads.",
                            evidence={
                                "organization_enabled": True,
                                "ou_count": len(ous.get('OrganizationalUnits', [])),
                                "has_production_ou": has_prod_ou,
                                "has_development_ou": has_dev_ou,
                                "tagged_prod_accounts": prod_accounts,
                                "tagged_nonprod_accounts": non_prod_accounts
                            }
                        )
                        
            except Exception as e:
                if 'AWSOrganizationsNotInUseException' in str(e):
                    # Check if this is a production account without Organizations
                    # Look for production indicators
                    ec2_client = self.aws.get_client('ec2', self.regions[0])
                    
                    instances = ec2_client.describe_instances()
                    has_production_resources = False
                    
                    for reservation in instances.get('Reservations', []):
                        for instance in reservation.get('Instances', []):
                            for tag in instance.get('Tags', []):
                                if tag['Key'].lower() in ['environment', 'env'] and 'prod' in tag['Value'].lower():
                                    has_production_resources = True
                                    break
                    
                    if has_production_resources:
                        self.add_finding(
                            resource_type="AWS::Organizations::Account",
                            resource_id=self.aws.account_id,
                            region="global",
                            severity="HIGH",
                            details="Production resources found but AWS Organizations not enabled for account separation",
                            recommendation="Enable AWS Organizations and implement a multi-account strategy to separate production from non-production workloads.",
                            evidence={
                                "organization_enabled": False,
                                "has_production_resources": True
                            }
                        )
                else:
                    raise
                    
        except Exception as e:
            self.handle_error(e, "checking account segregation")
            
        return self.findings
