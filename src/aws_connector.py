#!/usr/bin/env python3
"""AWS Connector for security compliance checks."""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


class AWSConnector:
    """Handles AWS authentication and service connections."""

    def __init__(self, session_token: Optional[str] = None,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 region: str = 'us-east-1'):
        """Initialize AWS connector with credentials."""
        self.region = region
        self.session = self._create_session(session_token, access_key, secret_key)
        self.account_id = self._get_account_id()

    def _create_session(self, session_token: Optional[str],
                       access_key: Optional[str],
                       secret_key: Optional[str]) -> boto3.Session:
        """Create boto3 session with provided credentials."""
        if session_token and access_key and secret_key:
            return boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=self.region
            )
        else:
            # Use default credentials chain
            return boto3.Session(region_name=self.region)

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            sts = self.session.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Failed to get account ID: {str(e)}")
            return "unknown"

    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """Get boto3 client for specified service."""
        return self.session.client(service_name, region_name=region or self.region)

    def get_all_regions(self) -> List[str]:
        """Get all available AWS regions."""
        ec2 = self.get_client('ec2')
        regions = []
        try:
            response = ec2.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            logger.error(f"Failed to get regions: {str(e)}")
            regions = [self.region]  # Fallback to current region
        return regions

    def check_service_availability(self, service: str, region: str) -> bool:
        """Check if a service is available in a specific region."""
        try:
            self.session.client(service, region_name=region)
            return True
        except Exception:
            return False


class SecurityCheck:
    """Base class for security checks."""

    def __init__(self, aws_connector: AWSConnector):
        self.aws = aws_connector
        self.results = []

    def run_check(self, check_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific security check."""
        result = {
            'check_id': check_config['id'],
            'check_name': check_config['name'],
            'timestamp': datetime.utcnow().isoformat(),
            'account_id': self.aws.account_id,
            'region': self.aws.region,
            'status': 'PASS',
            'findings': [],
            'affected_resources': [],
            'framework': check_config['framework'],
            'severity': check_config['severity'],
            'nist_mappings': check_config['nist_mappings']
        }

        try:
            # Dynamically call the check function
            check_function = getattr(self, check_config['check_function'])
            findings = check_function()

            if findings:
                result['status'] = 'FAIL'
                result['findings'] = findings
                result['affected_resources'] = [f['resource'] for f in findings if 'resource' in f]

        except Exception as e:
            logger.error(f"Error running check {check_config['id']}: {str(e)}")
            result['status'] = 'ERROR'
            result['findings'] = [{'error': str(e)}]

        return result

    def check_root_account_usage(self) -> List[Dict[str, Any]]:
        """Check if root account has been used recently."""
        findings = []
        try:
            iam = self.aws.get_client('iam')
            response = iam.get_account_summary()

            # Check for root access key
            if response['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
                findings.append({
                    'type': 'ROOT_ACCESS_KEY_EXISTS',
                    'resource': 'root-account',
                    'details': 'Root account has active access keys'
                })

            # Check root account last used
            credential_report = iam.generate_credential_report()
            import time
            time.sleep(2)  # Wait for report generation

            report = iam.get_credential_report()
            import csv
            import io

            csv_content = report['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_content))

            for row in reader:
                if row['user'] == '<root_account>':
                    if row.get('password_last_used', 'N/A') != 'N/A':
                        last_used = datetime.strptime(row['password_last_used'], '%Y-%m-%dT%H:%M:%S+00:00')
                        if (datetime.utcnow() - last_used).days < 30:
                            findings.append({
                                'type': 'ROOT_RECENTLY_USED',
                                'resource': 'root-account',
                                'details': f'Root account used within last 30 days: {last_used}'
                            })

        except Exception as e:
            logger.error(f"Error checking root account usage: {str(e)}")

        return findings

    def check_root_mfa(self) -> List[Dict[str, Any]]:
        """Check if MFA is enabled on root account."""
        findings = []
        try:
            iam = self.aws.get_client('iam')
            response = iam.get_account_summary()

            if response['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                findings.append({
                    'type': 'ROOT_MFA_DISABLED',
                    'resource': 'root-account',
                    'details': 'MFA is not enabled for root account'
                })

        except Exception as e:
            logger.error(f"Error checking root MFA: {str(e)}")

        return findings

    def check_cloudtrail_enabled(self) -> List[Dict[str, Any]]:
        """Check if CloudTrail is enabled in all regions."""
        findings = []
        try:
            cloudtrail = self.aws.get_client('cloudtrail')
            response = cloudtrail.describe_trails()

            if not response['trailList']:
                findings.append({
                    'type': 'NO_CLOUDTRAIL',
                    'resource': 'cloudtrail',
                    'details': 'No CloudTrail trails configured'
                })
            else:
                # Check for multi-region trail
                multi_region_trail = False
                for trail in response['trailList']:
                    if trail.get('IsMultiRegionTrail', False):
                        multi_region_trail = True
                        # Check if trail is logging
                        status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                        if not status.get('IsLogging', False):
                            findings.append({
                                'type': 'TRAIL_NOT_LOGGING',
                                'resource': trail['TrailARN'],
                                'details': f"Trail {trail['Name']} is not logging"
                            })

                if not multi_region_trail:
                    findings.append({
                        'type': 'NO_MULTI_REGION_TRAIL',
                        'resource': 'cloudtrail',
                        'details': 'No multi-region CloudTrail trail configured'
                    })

        except Exception as e:
            logger.error(f"Error checking CloudTrail: {str(e)}")

        return findings

    def check_cloudtrail_validation(self) -> List[Dict[str, Any]]:
        """Check if CloudTrail log file validation is enabled."""
        findings = []
        try:
            cloudtrail = self.aws.get_client('cloudtrail')
            response = cloudtrail.describe_trails()

            for trail in response['trailList']:
                if not trail.get('LogFileValidationEnabled', False):
                    findings.append({
                        'type': 'LOG_VALIDATION_DISABLED',
                        'resource': trail['TrailARN'],
                        'details': f"Trail {trail['Name']} does not have log file validation enabled"
                    })

        except Exception as e:
            logger.error(f"Error checking CloudTrail validation: {str(e)}")

        return findings

    def check_s3_public_access(self) -> List[Dict[str, Any]]:
        """Check for publicly accessible S3 buckets."""
        findings = []
        try:
            s3 = self.aws.get_client('s3')
            response = s3.list_buckets()

            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    # Check bucket ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and \
                           grantee.get('URI', '').endswith('AllUsers'):
                            findings.append({
                                'type': 'PUBLIC_BUCKET_ACL',
                                'resource': f"arn:aws:s3:::{bucket_name}",
                                'details': f"Bucket {bucket_name} has public ACL permissions"
                            })

                    # Check bucket policy
                    try:
                        policy = s3.get_bucket_policy(Bucket=bucket_name)
                        policy_doc = json.loads(policy['Policy'])
                        for statement in policy_doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow' and \
                               statement.get('Principal') in ['*', {'AWS': '*'}]:
                                findings.append({
                                    'type': 'PUBLIC_BUCKET_POLICY',
                                    'resource': f"arn:aws:s3:::{bucket_name}",
                                    'details': f"Bucket {bucket_name} has public bucket policy"
                                })
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                            raise

                except Exception as e:
                    logger.error(f"Error checking bucket {bucket_name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking S3 public access: {str(e)}")

        return findings

    def check_s3_encryption(self) -> List[Dict[str, Any]]:
        """Check if S3 buckets have encryption enabled."""
        findings = []
        try:
            s3 = self.aws.get_client('s3')
            response = s3.list_buckets()

            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append({
                            'type': 'BUCKET_NOT_ENCRYPTED',
                            'resource': f"arn:aws:s3:::{bucket_name}",
                            'details': f"Bucket {bucket_name} does not have encryption enabled"
                        })
                    else:
                        logger.error(f"Error checking bucket {bucket_name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking S3 encryption: {str(e)}")

        return findings

    def check_ebs_encryption(self) -> List[Dict[str, Any]]:
        """Check if EBS volumes are encrypted."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client('ec2', region)
                    response = ec2.describe_volumes()

                    for volume in response['Volumes']:
                        if not volume.get('Encrypted', False):
                            findings.append({
                                'type': 'UNENCRYPTED_EBS_VOLUME',
                                'resource': volume['VolumeId'],
                                'region': region,
                                'details': f"EBS volume {volume['VolumeId']} in {region} is not encrypted"
                            })

                except Exception as e:
                    logger.error(f"Error checking EBS in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking EBS encryption: {str(e)}")

        return findings

    def check_sg_ssh_access(self) -> List[Dict[str, Any]]:
        """Check for security groups allowing unrestricted SSH access."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client('ec2', region)
                    response = ec2.describe_security_groups()

                    for sg in response['SecurityGroups']:
                        for rule in sg.get('IpPermissions', []):
                            if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                                for ip_range in rule.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        findings.append({
                                            'type': 'UNRESTRICTED_SSH',
                                            'resource': sg['GroupId'],
                                            'region': region,
                                            'details': f"Security group {sg['GroupName']} allows SSH from 0.0.0.0/0"
                                        })

                except Exception as e:
                    logger.error(f"Error checking security groups in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking security group SSH access: {str(e)}")

        return findings

    def check_password_policy(self) -> List[Dict[str, Any]]:
        """Check IAM password policy meets requirements."""
        findings = []
        try:
            iam = self.aws.get_client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']

            # Check minimum requirements
            requirements = {
                'MinimumPasswordLength': 14,
                'RequireUppercaseCharacters': True,
                'RequireLowercaseCharacters': True,
                'RequireNumbers': True,
                'RequireSymbols': True,
                'MaxPasswordAge': 90
            }

            for req, expected in requirements.items():
                if req in policy:
                    if req == 'MinimumPasswordLength' and policy[req] < expected:
                        findings.append({
                            'type': 'WEAK_PASSWORD_POLICY',
                            'resource': 'iam-password-policy',
                            'details': f"Password minimum length is {policy[req]}, should be at least {expected}"
                        })
                    elif req == 'MaxPasswordAge' and policy[req] > expected:
                        findings.append({
                            'type': 'WEAK_PASSWORD_POLICY',
                            'resource': 'iam-password-policy',
                            'details': f"Password max age is {policy[req]} days, should be at most {expected}"
                        })
                    elif isinstance(expected, bool) and not policy.get(req, False):
                        findings.append({
                            'type': 'WEAK_PASSWORD_POLICY',
                            'resource': 'iam-password-policy',
                            'details': f"Password policy missing requirement: {req}"
                        })

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                findings.append({
                    'type': 'NO_PASSWORD_POLICY',
                    'resource': 'iam-password-policy',
                    'details': 'No IAM password policy configured'
                })
            else:
                logger.error(f"Error checking password policy: {str(e)}")

        return findings

    def check_access_key_rotation(self) -> List[Dict[str, Any]]:
        """Check if access keys are rotated every 90 days."""
        findings = []
        try:
            iam = self.aws.get_client('iam')

            # Get all users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    # Get access keys for user
                    keys_response = iam.list_access_keys(UserName=user['UserName'])

                    for key_metadata in keys_response['AccessKeyMetadata']:
                        create_date = key_metadata['CreateDate']
                        age_days = (datetime.now(create_date.tzinfo) - create_date).days

                        if age_days > 90 and key_metadata['Status'] == 'Active':
                            findings.append({
                                'type': 'OLD_ACCESS_KEY',
                                'resource': f"arn:aws:iam::{self.aws.account_id}:user/{user['UserName']}",
                                'details': f"Access key {key_metadata['AccessKeyId']} for user {user['UserName']} is {age_days} days old"
                            })

        except Exception as e:
            logger.error(f"Error checking access key rotation: {str(e)}")

        return findings

    def check_unused_credentials(self) -> List[Dict[str, Any]]:
        """Check for credentials unused for 90 days."""
        findings = []
        try:
            iam = self.aws.get_client('iam')

            # Generate credential report
            iam.generate_credential_report()
            import time
            time.sleep(2)  # Wait for report generation

            report = iam.get_credential_report()
            import csv
            import io

            csv_content = report['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_content))

            for row in reader:
                user = row['user']
                if user == '<root_account>':
                    continue

                # Check password last used
                if row.get('password_enabled', 'false') == 'true':
                    last_used = row.get('password_last_used', 'N/A')
                    if last_used != 'N/A' and last_used != 'no_information':
                        last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                        if (datetime.utcnow() - last_used_date).days > 90:
                            findings.append({
                                'type': 'UNUSED_PASSWORD',
                                'resource': f"arn:aws:iam::{self.aws.account_id}:user/{user}",
                                'details': f"User {user} password not used in over 90 days"
                            })

                # Check access keys last used
                for i in ['1', '2']:
                    if row.get(f'access_key_{i}_active', 'false') == 'true':
                        last_used = row.get(f'access_key_{i}_last_used_date', 'N/A')
                        if last_used != 'N/A':
                            last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                            if (datetime.utcnow() - last_used_date).days > 90:
                                findings.append({
                                    'type': 'UNUSED_ACCESS_KEY',
                                    'resource': f"arn:aws:iam::{self.aws.account_id}:user/{user}",
                                    'details': f"User {user} access key {i} not used in over 90 days"
                                })

        except Exception as e:
            logger.error(f"Error checking unused credentials: {str(e)}")

        return findings

    def check_imdsv2(self) -> List[Dict[str, Any]]:
        """Check if IMDSv2 is enforced on EC2 instances."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client('ec2', region)
                    response = ec2.describe_instances()

                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            if instance['State']['Name'] != 'terminated':
                                metadata_options = instance.get('MetadataOptions', {})
                                if metadata_options.get('HttpTokens') != 'required':
                                    findings.append({
                                        'type': 'IMDSV1_ENABLED',
                                        'resource': instance['InstanceId'],
                                        'region': region,
                                        'details': f"Instance {instance['InstanceId']} does not enforce IMDSv2"
                                    })

                except Exception as e:
                    logger.error(f"Error checking instances in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking IMDSv2: {str(e)}")

        return findings

    def check_vpc_flow_logs(self) -> List[Dict[str, Any]]:
        """Check if VPC flow logs are enabled."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client('ec2', region)
                    vpcs = ec2.describe_vpcs()['Vpcs']

                    for vpc in vpcs:
                        vpc_id = vpc['VpcId']
                        flow_logs = ec2.describe_flow_logs(
                            Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                        )['FlowLogs']

                        if not flow_logs:
                            findings.append({
                                'type': 'NO_VPC_FLOW_LOGS',
                                'resource': vpc_id,
                                'region': region,
                                'details': f"VPC {vpc_id} in {region} does not have flow logs enabled"
                            })

                except Exception as e:
                    logger.error(f"Error checking VPCs in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking VPC flow logs: {str(e)}")

        return findings

    def check_rds_encryption(self) -> List[Dict[str, Any]]:
        """Check if RDS databases are encrypted."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability('rds', region):
                    continue

                try:
                    rds = self.aws.get_client('rds', region)
                    response = rds.describe_db_instances()

                    for db in response['DBInstances']:
                        if not db.get('StorageEncrypted', False):
                            findings.append({
                                'type': 'UNENCRYPTED_RDS',
                                'resource': db['DBInstanceArn'],
                                'region': region,
                                'details': f"RDS instance {db['DBInstanceIdentifier']} is not encrypted"
                            })

                except Exception as e:
                    logger.error(f"Error checking RDS in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking RDS encryption: {str(e)}")

        return findings

    def check_config_enabled(self) -> List[Dict[str, Any]]:
        """Check if AWS Config is enabled in all regions."""
        findings = []
        try:
            # Check all regions
            enabled_regions = []

            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability('config', region):
                    continue

                try:
                    config = self.aws.get_client('config', region)
                    recorders = config.describe_configuration_recorders()

                    if recorders['ConfigurationRecorders']:
                        # Check if recorder is actually running
                        for recorder in recorders['ConfigurationRecorders']:
                            status = config.describe_configuration_recorder_status(
                                ConfigurationRecorderNames=[recorder['name']]
                            )
                            if status['ConfigurationRecordersStatus'][0]['recording']:
                                enabled_regions.append(region)

                except Exception as e:
                    logger.error(f"Error checking Config in region {region}: {str(e)}")

            # Check if Config is enabled in all regions
            all_regions = self.aws.get_all_regions()
            if len(enabled_regions) < len(all_regions):
                missing_regions = set(all_regions) - set(enabled_regions)
                findings.append({
                    'type': 'CONFIG_NOT_ALL_REGIONS',
                    'resource': 'aws-config',
                    'details': f"AWS Config not enabled in regions: {', '.join(missing_regions)}"
                })

        except Exception as e:
            logger.error(f"Error checking AWS Config: {str(e)}")

        return findings
