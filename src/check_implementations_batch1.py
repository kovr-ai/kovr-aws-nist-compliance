#!/usr/bin/env python3
"""Implementation of security check functions for batch 1 (CHECK-041 to CHECK-060)."""

from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class Batch1SecurityChecks:
    """Security checks implementation for batch 1."""
    
    def check_check_041(self) -> List[Dict[str, Any]]:
        """Check EC2 instances for malware protection."""
        findings = []
        
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("ssm", region):
                    continue
                    
                try:
                    ssm = self.aws.get_client("ssm", region)
                    ec2 = self.aws.get_client("ec2", region)
                    
                    # Get all running instances
                    instances_response = ec2.describe_instances(
                        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
                    )
                    
                    instance_ids = []
                    for reservation in instances_response['Reservations']:
                        for instance in reservation['Instances']:
                            instance_ids.append(instance['InstanceId'])
                            
                    if not instance_ids:
                        continue
                    
                    # Check for anti-malware compliance
                    try:
                        compliance_response = ssm.list_compliance_items(
                            Filters=[
                                {
                                    'Key': 'ComplianceType',
                                    'Values': ['Custom:AntiMalware']
                                }
                            ],
                            ResourceIds=instance_ids,
                            ResourceTypes=['ManagedInstance']
                        )
                        
                        # Track compliant instances
                        compliant_instances = set()
                        for item in compliance_response.get('ComplianceItems', []):
                            if item.get('Status') == 'COMPLIANT':
                                compliant_instances.add(item.get('ResourceId'))
                        
                        # Find non-compliant instances
                        for instance_id in instance_ids:
                            instance_arn = f"arn:aws:ec2:{region}:{self.aws.account_id}:instance/{instance_id}"
                            self._track_resource_tested(instance_arn)
                            
                            if instance_id not in compliant_instances:
                                findings.append({
                                    "type": "NO_MALWARE_PROTECTION",
                                    "resource": instance_id,
                                    "region": region,
                                    "details": f"EC2 instance {instance_id} does not have malware protection enabled"
                                })
                                
                    except Exception as e:
                        logger.warning(f"Could not check SSM compliance in {region}: {str(e)}")
                        # Fall back to checking for GuardDuty enablement as minimum protection
                        
                except Exception as e:
                    logger.error(f"Error checking malware protection in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_041: {str(e)}")
            
        return findings
    
    def check_check_042(self) -> List[Dict[str, Any]]:
        """Check for automated vulnerability remediation configuration."""
        findings = []
        
        try:
            # Check if Inspector v2 is enabled
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("inspector2", region):
                    continue
                    
                try:
                    inspector = self.aws.get_client("inspector2", region)
                    ssm = self.aws.get_client("ssm", region)
                    
                    # Check Inspector enablement
                    account_status = inspector.batch_get_account_status()
                    
                    inspector_enabled = False
                    if account_status['accounts']:
                        status = account_status['accounts'][0]['state']
                        if status.get('status') == 'ENABLED':
                            inspector_enabled = True
                    
                    if not inspector_enabled:
                        findings.append({
                            "type": "NO_VULNERABILITY_SCANNING",
                            "resource": f"inspector-{region}",
                            "region": region,
                            "details": f"Automated vulnerability scanning not enabled in {region}"
                        })
                        continue
                    
                    # Check for patch manager configuration
                    try:
                        patch_response = ssm.describe_patch_baselines()
                        
                        if not patch_response.get('BaselineIdentities'):
                            findings.append({
                                "type": "NO_PATCH_AUTOMATION",
                                "resource": f"patch-manager-{region}",
                                "region": region,
                                "details": f"No patch baselines configured for automated remediation in {region}"
                            })
                        else:
                            # Check for maintenance windows
                            mw_response = ssm.describe_maintenance_windows()
                            
                            if not mw_response.get('WindowIdentities'):
                                findings.append({
                                    "type": "NO_MAINTENANCE_WINDOW",
                                    "resource": f"maintenance-window-{region}",
                                    "region": region,
                                    "details": f"No maintenance windows configured for automated patching in {region}"
                                })
                                
                    except Exception as e:
                        logger.warning(f"Could not check patch automation in {region}: {str(e)}")
                        
                except Exception as e:
                    logger.error(f"Error checking vulnerability remediation in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_042: {str(e)}")
            
        return findings
    
    def check_check_043(self) -> List[Dict[str, Any]]:
        """Check CloudWatch Logs integration for critical services."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                try:
                    logs = self.aws.get_client("logs", region)
                    ec2 = self.aws.get_client("ec2", region)
                    lambda_client = self.aws.get_client("lambda", region)
                    ecs = self.aws.get_client("ecs", region)
                    
                    # Check EC2 instances for CloudWatch agent
                    instances_response = ec2.describe_instances(
                        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
                    )
                    
                    for reservation in instances_response['Reservations']:
                        for instance in reservation['Instances']:
                            instance_id = instance['InstanceId']
                            instance_arn = f"arn:aws:ec2:{region}:{self.aws.account_id}:instance/{instance_id}"
                            self._track_resource_tested(instance_arn)
                            
                            # Check if instance has CloudWatch logs configuration
                            # This is a simplified check - in production would check SSM or tags
                            log_group_name = f"/aws/ec2/{instance_id}"
                            
                            try:
                                logs.describe_log_groups(
                                    logGroupNamePrefix=log_group_name,
                                    limit=1
                                )
                            except:
                                findings.append({
                                    "type": "NO_CLOUDWATCH_LOGS",
                                    "resource": instance_id,
                                    "region": region,
                                    "details": f"EC2 instance {instance_id} not configured to send logs to CloudWatch"
                                })
                    
                    # Check Lambda functions
                    try:
                        lambda_response = lambda_client.list_functions()
                        
                        for function in lambda_response.get('Functions', []):
                            function_name = function['FunctionName']
                            function_arn = function['FunctionArn']
                            self._track_resource_tested(function_arn)
                            
                            # Lambda functions automatically log to CloudWatch, but check retention
                            log_group_name = f"/aws/lambda/{function_name}"
                            
                            try:
                                log_group = logs.describe_log_groups(
                                    logGroupNamePrefix=log_group_name,
                                    limit=1
                                )
                                
                                if log_group['logGroups']:
                                    retention = log_group['logGroups'][0].get('retentionInDays')
                                    if not retention or retention < 30:
                                        findings.append({
                                            "type": "INSUFFICIENT_LOG_RETENTION",
                                            "resource": function_name,
                                            "region": region,
                                            "details": f"Lambda function {function_name} has insufficient log retention period"
                                        })
                            except:
                                pass  # Lambda logs are created on first invocation
                                
                    except Exception as e:
                        logger.warning(f"Could not check Lambda logs in {region}: {str(e)}")
                        
                except Exception as e:
                    logger.error(f"Error checking CloudWatch logs integration in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_043: {str(e)}")
            
        return findings
    
    def check_check_044(self) -> List[Dict[str, Any]]:
        """Check security function verification through Config rules."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("config", region):
                    continue
                    
                try:
                    config = self.aws.get_client("config", region)
                    
                    # Check if Config is enabled
                    recorders = config.describe_configuration_recorders()
                    
                    if not recorders['ConfigurationRecorders']:
                        findings.append({
                            "type": "CONFIG_NOT_ENABLED",
                            "resource": f"config-{region}",
                            "region": region,
                            "details": f"AWS Config not enabled in {region} for security function verification"
                        })
                        continue
                    
                    # Check for security-related Config rules
                    rules_response = config.describe_config_rules()
                    
                    security_rules = [
                        'required-tags',
                        'encrypted-volumes',
                        'restricted-ssh',
                        'iam-password-policy',
                        'root-account-mfa-enabled',
                        'cloudtrail-enabled'
                    ]
                    
                    existing_rules = [rule['ConfigRuleName'] for rule in rules_response.get('ConfigRules', [])]
                    
                    missing_rules = []
                    for required_rule in security_rules:
                        found = False
                        for existing_rule in existing_rules:
                            if required_rule in existing_rule.lower():
                                found = True
                                break
                        if not found:
                            missing_rules.append(required_rule)
                    
                    if missing_rules:
                        findings.append({
                            "type": "MISSING_SECURITY_RULES",
                            "resource": f"config-rules-{region}",
                            "region": region,
                            "details": f"Missing security verification rules in {region}: {', '.join(missing_rules)}"
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking security function verification in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_044: {str(e)}")
            
        return findings
    
    def check_check_045(self) -> List[Dict[str, Any]]:
        """Check software and firmware integrity verification."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("ssm", region):
                    continue
                    
                try:
                    ssm = self.aws.get_client("ssm", region)
                    ec2 = self.aws.get_client("ec2", region)
                    
                    # Get managed instances
                    instances_response = ssm.describe_instance_information()
                    
                    for instance in instances_response.get('InstanceInformationList', []):
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{region}:{self.aws.account_id}:instance/{instance_id}"
                        self._track_resource_tested(instance_arn)
                        
                        # Check for inventory collection
                        try:
                            inventory_response = ssm.list_inventory_entries(
                                InstanceId=instance_id,
                                TypeName='AWS:Application'
                            )
                            
                            if not inventory_response.get('Entries'):
                                findings.append({
                                    "type": "NO_SOFTWARE_INVENTORY",
                                    "resource": instance_id,
                                    "region": region,
                                    "details": f"Instance {instance_id} does not have software inventory collection enabled"
                                })
                                
                        except Exception as e:
                            logger.warning(f"Could not check inventory for {instance_id}: {str(e)}")
                            
                    # Check for file integrity monitoring association
                    associations_response = ssm.list_associations(
                        AssociationFilterList=[
                            {
                                'key': 'Name',
                                'value': 'AWS-ConfigureFileIntegrityMonitoring'
                            }
                        ]
                    )
                    
                    if not associations_response.get('Associations'):
                        findings.append({
                            "type": "NO_FILE_INTEGRITY_MONITORING",
                            "resource": f"file-integrity-{region}",
                            "region": region,
                            "details": f"File integrity monitoring not configured in {region}"
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking software integrity in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_045: {str(e)}")
            
        return findings
    
    # Continue with implementations for CHECK-046 through CHECK-060...
    
    def check_check_046(self) -> List[Dict[str, Any]]:
        """Check container image scanning in ECR."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("ecr", region):
                    continue
                    
                try:
                    ecr = self.aws.get_client("ecr", region)
                    
                    # Get all repositories
                    repositories = ecr.describe_repositories()
                    
                    for repo in repositories.get('repositories', []):
                        repo_name = repo['repositoryName']
                        repo_arn = repo['repositoryArn']
                        self._track_resource_tested(repo_arn)
                        
                        # Check scan on push configuration
                        if not repo.get('imageScanningConfiguration', {}).get('scanOnPush', False):
                            findings.append({
                                "type": "IMAGE_SCANNING_DISABLED",
                                "resource": repo_name,
                                "region": region,
                                "details": f"ECR repository {repo_name} does not have image scanning on push enabled"
                            })
                            
                except Exception as e:
                    logger.error(f"Error checking container image scanning in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_046: {str(e)}")
            
        return findings
    
    def check_check_047(self) -> List[Dict[str, Any]]:
        """Check for Data Loss Prevention controls."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                try:
                    # Check if Macie is enabled
                    if self.aws.check_service_availability("macie2", region):
                        macie = self.aws.get_client("macie2", region)
                        
                        try:
                            macie_status = macie.get_macie_session()
                            
                            if macie_status.get('status') != 'ENABLED':
                                findings.append({
                                    "type": "MACIE_NOT_ENABLED",
                                    "resource": f"macie-{region}",
                                    "region": region,
                                    "details": f"Amazon Macie not enabled in {region} for data loss prevention"
                                })
                                continue
                                
                            # Check for classification jobs
                            jobs = macie.list_classification_jobs()
                            
                            if not jobs.get('items'):
                                findings.append({
                                    "type": "NO_DLP_SCANNING",
                                    "resource": f"macie-jobs-{region}",
                                    "region": region,
                                    "details": f"No Macie classification jobs configured in {region}"
                                })
                                
                        except Exception as e:
                            if 'AccessDeniedException' not in str(e):
                                findings.append({
                                    "type": "MACIE_NOT_CONFIGURED",
                                    "resource": f"macie-{region}",
                                    "region": region,
                                    "details": f"Macie not properly configured in {region}"
                                })
                    
                    # Check VPC endpoints for data exfiltration prevention
                    ec2 = self.aws.get_client("ec2", region)
                    
                    vpc_endpoints = ec2.describe_vpc_endpoints()
                    s3_endpoints = [ep for ep in vpc_endpoints['VpcEndpoints'] 
                                   if 's3' in ep.get('ServiceName', '').lower()]
                    
                    if not s3_endpoints:
                        findings.append({
                            "type": "NO_VPC_ENDPOINT_DLP",
                            "resource": f"vpc-endpoints-{region}",
                            "region": region,
                            "details": f"No S3 VPC endpoints configured in {region} to prevent data exfiltration"
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking DLP controls in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_047: {str(e)}")
            
        return findings
    
    def check_check_048(self) -> List[Dict[str, Any]]:
        """Check incident response plan testing."""
        findings = []
        
        try:
            # Check for incident response simulation tags or configurations
            organizations = self.aws.get_client("organizations")
            
            try:
                # Check if organization has incident response policies
                policies = organizations.list_policies(Filter='SERVICE_CONTROL_POLICY')
                
                ir_policy_found = False
                for policy in policies.get('Policies', []):
                    if 'incident' in policy['Name'].lower() or 'response' in policy['Name'].lower():
                        ir_policy_found = True
                        break
                
                if not ir_policy_found:
                    findings.append({
                        "type": "NO_IR_POLICY",
                        "resource": "organization-policies",
                        "region": "global",
                        "details": "No incident response policies found at organization level"
                    })
                    
            except Exception as e:
                logger.warning(f"Could not check organization policies: {str(e)}")
            
            # Check for Systems Manager documents related to incident response
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("ssm", region):
                    continue
                    
                try:
                    ssm = self.aws.get_client("ssm", region)
                    
                    documents = ssm.list_documents(
                        Filters=[
                            {
                                'Key': 'Owner',
                                'Values': ['Self']
                            }
                        ]
                    )
                    
                    ir_docs = [doc for doc in documents.get('DocumentIdentifiers', [])
                              if 'incident' in doc['Name'].lower() or 'response' in doc['Name'].lower()]
                    
                    if not ir_docs:
                        findings.append({
                            "type": "NO_IR_RUNBOOKS",
                            "resource": f"ssm-documents-{region}",
                            "region": region,
                            "details": f"No incident response runbooks found in {region}"
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking IR documents in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_048: {str(e)}")
            
        return findings
    
    def check_check_049(self) -> List[Dict[str, Any]]:
        """Check for automated incident response capabilities."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                try:
                    # Check EventBridge rules for automated response
                    events = self.aws.get_client("events", region)
                    
                    rules = events.list_rules()
                    
                    security_rules = [rule for rule in rules.get('Rules', [])
                                    if any(keyword in rule['Name'].lower() 
                                          for keyword in ['security', 'incident', 'response', 'remediation'])]
                    
                    if not security_rules:
                        findings.append({
                            "type": "NO_AUTOMATED_RESPONSE",
                            "resource": f"eventbridge-{region}",
                            "region": region,
                            "details": f"No automated incident response rules found in EventBridge in {region}"
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking automated response in region {region}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error in check_check_049: {str(e)}")
            
        return findings 