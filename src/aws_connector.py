#!/usr/bin/env python3
"""AWS Connector for security compliance checks."""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class AWSConnector:
    """Handles AWS authentication and service connections."""

    def __init__(
        self,
        session_token: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: str = "us-east-1",
    ):
        """Initialize AWS connector with credentials."""
        self.region = region
        self.session = self._create_session(session_token, access_key, secret_key)
        self.account_id = self._get_account_id()

    def _create_session(
        self, session_token: Optional[str], access_key: Optional[str], secret_key: Optional[str]
    ) -> boto3.Session:
        """Create boto3 session with provided credentials."""
        if session_token and access_key and secret_key:
            return boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=self.region,
            )
        else:
            # Use default credentials chain
            return boto3.Session(region_name=self.region)

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            sts = self.session.client("sts")
            account_id: str = sts.get_caller_identity()["Account"]
            return account_id
        except Exception as e:
            logger.error(f"Failed to get account ID: {str(e)}")
            return "unknown"

    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """Get boto3 client for specified service."""
        return self.session.client(service_name, region_name=region or self.region)

    def get_all_regions(self) -> List[str]:
        """Get all available AWS regions."""
        ec2 = self.get_client("ec2")
        regions = []
        try:
            response = ec2.describe_regions()
            regions = [region["RegionName"] for region in response["Regions"]]
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
        """Initialize SecurityCheck with AWS connector."""
        self.aws = aws_connector
        self.results: List[Dict[str, Any]] = []

    def run_check(self, check_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific security check."""
        result = {
            "check_id": check_config["id"],
            "check_name": check_config["name"],
            "timestamp": datetime.utcnow().isoformat(),
            "account_id": self.aws.account_id,
            "region": self.aws.region,
            "status": "PASS",
            "findings": [],
            "affected_resources": [],
            "framework": check_config["framework"],
            "severity": check_config["severity"],
            "nist_mappings": check_config["nist_mappings"],
        }

        try:
            # Dynamically call the check function
            check_function = getattr(self, check_config["check_function"])
            findings = check_function()

            if findings:
                result["status"] = "FAIL"
                result["findings"] = findings
                result["affected_resources"] = [f["resource"] for f in findings if "resource" in f]

        except Exception as e:
            logger.error(f"Error running check {check_config['id']}: {str(e)}")
            result["status"] = "ERROR"
            result["findings"] = [{"error": str(e)}]

        return result

    def check_root_account_usage(self) -> List[Dict[str, Any]]:
        """Check if root account has been used recently."""
        findings = []
        try:
            iam = self.aws.get_client("iam")
            response = iam.get_account_summary()

            # Check for root access key
            if response["SummaryMap"].get("AccountAccessKeysPresent", 0) > 0:
                findings.append(
                    {
                        "type": "ROOT_ACCESS_KEY_EXISTS",
                        "resource": "root-account",
                        "details": "Root account has active access keys",
                    }
                )

            # Check root account last used
            iam.generate_credential_report()
            import time

            time.sleep(2)  # Wait for report generation

            report = iam.get_credential_report()
            import csv
            import io

            csv_content = report["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(csv_content))

            for row in reader:
                if row["user"] == "<root_account>":
                    if row.get("password_last_used", "N/A") != "N/A":
                        last_used = datetime.strptime(
                            row["password_last_used"], "%Y-%m-%dT%H:%M:%S+00:00"
                        )
                        if (datetime.utcnow() - last_used).days < 30:
                            findings.append(
                                {
                                    "type": "ROOT_RECENTLY_USED",
                                    "resource": "root-account",
                                    "details": f"Root account used within last 30 days: {last_used}",
                                }
                            )

        except Exception as e:
            logger.error(f"Error checking root account usage: {str(e)}")

        return findings

    def check_root_mfa(self) -> List[Dict[str, Any]]:
        """Check if MFA is enabled on root account."""
        findings = []
        try:
            iam = self.aws.get_client("iam")
            response = iam.get_account_summary()

            if response["SummaryMap"].get("AccountMFAEnabled", 0) == 0:
                findings.append(
                    {
                        "type": "ROOT_MFA_DISABLED",
                        "resource": "root-account",
                        "details": "MFA is not enabled for root account",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking root MFA: {str(e)}")

        return findings

    def check_cloudtrail_enabled(self) -> List[Dict[str, Any]]:
        """Check if CloudTrail is enabled in all regions."""
        findings = []
        try:
            cloudtrail = self.aws.get_client("cloudtrail")
            response = cloudtrail.describe_trails()

            if not response["trailList"]:
                findings.append(
                    {
                        "type": "NO_CLOUDTRAIL",
                        "resource": "cloudtrail",
                        "details": "No CloudTrail trails configured",
                    }
                )
            else:
                # Check for multi-region trail
                multi_region_trail = False
                for trail in response["trailList"]:
                    if trail.get("IsMultiRegionTrail", False):
                        multi_region_trail = True
                        # Check if trail is logging
                        status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
                        if not status.get("IsLogging", False):
                            findings.append(
                                {
                                    "type": "TRAIL_NOT_LOGGING",
                                    "resource": trail["TrailARN"],
                                    "details": f"Trail {trail['Name']} is not logging",
                                }
                            )

                if not multi_region_trail:
                    findings.append(
                        {
                            "type": "NO_MULTI_REGION_TRAIL",
                            "resource": "cloudtrail",
                            "details": "No multi-region CloudTrail trail configured",
                        }
                    )

        except Exception as e:
            logger.error(f"Error checking CloudTrail: {str(e)}")

        return findings

    def check_cloudtrail_validation(self) -> List[Dict[str, Any]]:
        """Check if CloudTrail log file validation is enabled."""
        findings = []
        try:
            cloudtrail = self.aws.get_client("cloudtrail")
            response = cloudtrail.describe_trails()

            for trail in response["trailList"]:
                if not trail.get("LogFileValidationEnabled", False):
                    findings.append(
                        {
                            "type": "LOG_VALIDATION_DISABLED",
                            "resource": trail["TrailARN"],
                            "details": f"Trail {trail['Name']} does not have log file validation enabled",
                        }
                    )

        except Exception as e:
            logger.error(f"Error checking CloudTrail validation: {str(e)}")

        return findings

    def check_s3_public_access(self) -> List[Dict[str, Any]]:
        """Check for publicly accessible S3 buckets."""
        findings = []
        try:
            s3 = self.aws.get_client("s3")
            response = s3.list_buckets()

            for bucket in response["Buckets"]:
                bucket_name = bucket["Name"]
                try:
                    # Check bucket ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl["Grants"]:
                        grantee = grant.get("Grantee", {})
                        if grantee.get("Type") == "Group" and grantee.get("URI", "").endswith(
                            "AllUsers"
                        ):
                            findings.append(
                                {
                                    "type": "PUBLIC_BUCKET_ACL",
                                    "resource": f"arn:aws:s3:::{bucket_name}",
                                    "details": f"Bucket {bucket_name} has public ACL permissions",
                                }
                            )

                    # Check bucket policy
                    try:
                        policy = s3.get_bucket_policy(Bucket=bucket_name)
                        policy_doc = json.loads(policy["Policy"])
                        for statement in policy_doc.get("Statement", []):
                            if statement.get("Effect") == "Allow" and statement.get(
                                "Principal"
                            ) in ["*", {"AWS": "*"}]:
                                findings.append(
                                    {
                                        "type": "PUBLIC_BUCKET_POLICY",
                                        "resource": f"arn:aws:s3:::{bucket_name}",
                                        "details": f"Bucket {bucket_name} has public bucket policy",
                                    }
                                )
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
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
            s3 = self.aws.get_client("s3")
            response = s3.list_buckets()

            for bucket in response["Buckets"]:
                bucket_name = bucket["Name"]
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if (
                        e.response["Error"]["Code"]
                        == "ServerSideEncryptionConfigurationNotFoundError"
                    ):
                        findings.append(
                            {
                                "type": "BUCKET_NOT_ENCRYPTED",
                                "resource": f"arn:aws:s3:::{bucket_name}",
                                "details": f"Bucket {bucket_name} does not have encryption enabled",
                            }
                        )
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
                    ec2 = self.aws.get_client("ec2", region)
                    response = ec2.describe_volumes()

                    for volume in response["Volumes"]:
                        if not volume.get("Encrypted", False):
                            findings.append(
                                {
                                    "type": "UNENCRYPTED_EBS_VOLUME",
                                    "resource": volume["VolumeId"],
                                    "region": region,
                                    "details": f"EBS volume {volume['VolumeId']} in {region} is not encrypted",
                                }
                            )

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
                    ec2 = self.aws.get_client("ec2", region)
                    response = ec2.describe_security_groups()

                    for sg in response["SecurityGroups"]:
                        for rule in sg.get("IpPermissions", []):
                            if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:
                                for ip_range in rule.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        findings.append(
                                            {
                                                "type": "UNRESTRICTED_SSH",
                                                "resource": sg["GroupId"],
                                                "region": region,
                                                "details": f"Security group {sg['GroupName']} allows SSH from 0.0.0.0/0",
                                            }
                                        )

                except Exception as e:
                    logger.error(f"Error checking security groups in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking security group SSH access: {str(e)}")

        return findings

    def check_password_policy(self) -> List[Dict[str, Any]]:
        """Check IAM password policy meets requirements."""
        findings = []
        try:
            iam = self.aws.get_client("iam")
            policy = iam.get_account_password_policy()["PasswordPolicy"]

            # Check minimum requirements
            requirements = {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "MaxPasswordAge": 90,
            }

            for req, expected in requirements.items():
                if req in policy:
                    if req == "MinimumPasswordLength" and policy[req] < expected:
                        findings.append(
                            {
                                "type": "WEAK_PASSWORD_POLICY",
                                "resource": "iam-password-policy",
                                "details": f"Password minimum length is {policy[req]}, should be at least {expected}",
                            }
                        )
                    elif req == "MaxPasswordAge" and policy[req] > expected:
                        findings.append(
                            {
                                "type": "WEAK_PASSWORD_POLICY",
                                "resource": "iam-password-policy",
                                "details": f"Password max age is {policy[req]} days, should be at most {expected}",
                            }
                        )
                    elif isinstance(expected, bool) and not policy.get(req, False):
                        findings.append(
                            {
                                "type": "WEAK_PASSWORD_POLICY",
                                "resource": "iam-password-policy",
                                "details": f"Password policy missing requirement: {req}",
                            }
                        )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                findings.append(
                    {
                        "type": "NO_PASSWORD_POLICY",
                        "resource": "iam-password-policy",
                        "details": "No IAM password policy configured",
                    }
                )
            else:
                logger.error(f"Error checking password policy: {str(e)}")

        return findings

    def check_access_key_rotation(self) -> List[Dict[str, Any]]:
        """Check if access keys are rotated every 90 days."""
        findings = []
        try:
            iam = self.aws.get_client("iam")

            # Get all users
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    # Get access keys for user
                    keys_response = iam.list_access_keys(UserName=user["UserName"])

                    for key_metadata in keys_response["AccessKeyMetadata"]:
                        create_date = key_metadata["CreateDate"]
                        age_days = (datetime.now(create_date.tzinfo) - create_date).days

                        if age_days > 90 and key_metadata["Status"] == "Active":
                            findings.append(
                                {
                                    "type": "OLD_ACCESS_KEY",
                                    "resource": f"arn:aws:iam::{self.aws.account_id}:user/{user['UserName']}",
                                    "details": f"Access key {key_metadata['AccessKeyId']} for user {user['UserName']} is {age_days} days old",
                                }
                            )

        except Exception as e:
            logger.error(f"Error checking access key rotation: {str(e)}")

        return findings

    def check_unused_credentials(self) -> List[Dict[str, Any]]:
        """Check for credentials unused for 90 days."""
        findings = []
        try:
            iam = self.aws.get_client("iam")

            # Generate credential report
            iam.generate_credential_report()
            import time

            time.sleep(2)  # Wait for report generation

            report = iam.get_credential_report()
            import csv
            import io

            csv_content = report["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(csv_content))

            for row in reader:
                user = row["user"]
                if user == "<root_account>":
                    continue

                # Check password last used
                if row.get("password_enabled", "false") == "true":
                    last_used = row.get("password_last_used", "N/A")
                    if last_used != "N/A" and last_used != "no_information":
                        last_used_date = datetime.strptime(last_used, "%Y-%m-%dT%H:%M:%S+00:00")
                        if (datetime.utcnow() - last_used_date).days > 90:
                            findings.append(
                                {
                                    "type": "UNUSED_PASSWORD",
                                    "resource": f"arn:aws:iam::{self.aws.account_id}:user/{user}",
                                    "details": f"User {user} password not used in over 90 days",
                                }
                            )

                # Check access keys last used
                for i in ["1", "2"]:
                    if row.get(f"access_key_{i}_active", "false") == "true":
                        last_used = row.get(f"access_key_{i}_last_used_date", "N/A")
                        if last_used != "N/A":
                            last_used_date = datetime.strptime(last_used, "%Y-%m-%dT%H:%M:%S+00:00")
                            if (datetime.utcnow() - last_used_date).days > 90:
                                findings.append(
                                    {
                                        "type": "UNUSED_ACCESS_KEY",
                                        "resource": f"arn:aws:iam::{self.aws.account_id}:user/{user}",
                                        "details": f"User {user} access key {i} not used in over 90 days",
                                    }
                                )

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
                    ec2 = self.aws.get_client("ec2", region)
                    response = ec2.describe_instances()

                    for reservation in response["Reservations"]:
                        for instance in reservation["Instances"]:
                            if instance["State"]["Name"] != "terminated":
                                metadata_options = instance.get("MetadataOptions", {})
                                if metadata_options.get("HttpTokens") != "required":
                                    findings.append(
                                        {
                                            "type": "IMDSV1_ENABLED",
                                            "resource": instance["InstanceId"],
                                            "region": region,
                                            "details": f"Instance {instance['InstanceId']} does not enforce IMDSv2",
                                        }
                                    )

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
                    ec2 = self.aws.get_client("ec2", region)
                    vpcs = ec2.describe_vpcs()["Vpcs"]

                    for vpc in vpcs:
                        vpc_id = vpc["VpcId"]
                        flow_logs = ec2.describe_flow_logs(
                            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                        )["FlowLogs"]

                        if not flow_logs:
                            findings.append(
                                {
                                    "type": "NO_VPC_FLOW_LOGS",
                                    "resource": vpc_id,
                                    "region": region,
                                    "details": f"VPC {vpc_id} in {region} does not have flow logs enabled",
                                }
                            )

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
                if not self.aws.check_service_availability("rds", region):
                    continue

                try:
                    rds = self.aws.get_client("rds", region)
                    response = rds.describe_db_instances()

                    for db in response["DBInstances"]:
                        if not db.get("StorageEncrypted", False):
                            findings.append(
                                {
                                    "type": "UNENCRYPTED_RDS",
                                    "resource": db["DBInstanceArn"],
                                    "region": region,
                                    "details": f"RDS instance {db['DBInstanceIdentifier']} is not encrypted",
                                }
                            )

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
                if not self.aws.check_service_availability("config", region):
                    continue

                try:
                    config = self.aws.get_client("config", region)
                    recorders = config.describe_configuration_recorders()

                    if recorders["ConfigurationRecorders"]:
                        # Check if recorder is actually running
                        for recorder in recorders["ConfigurationRecorders"]:
                            status = config.describe_configuration_recorder_status(
                                ConfigurationRecorderNames=[recorder["name"]]
                            )
                            if status["ConfigurationRecordersStatus"][0]["recording"]:
                                enabled_regions.append(region)

                except Exception as e:
                    logger.error(f"Error checking Config in region {region}: {str(e)}")

            # Check if Config is enabled in all regions
            all_regions = self.aws.get_all_regions()
            if len(enabled_regions) < len(all_regions):
                missing_regions = set(all_regions) - set(enabled_regions)
                findings.append(
                    {
                        "type": "CONFIG_NOT_ALL_REGIONS",
                        "resource": "aws-config",
                        "details": f"AWS Config not enabled in regions: {', '.join(missing_regions)}",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking AWS Config: {str(e)}")

        return findings

    def check_cloudwatch_anomaly_detection(self) -> List[Dict[str, Any]]:
        """Check if CloudWatch Anomaly Detectors are configured."""
        findings = []
        try:
            cloudwatch = self.aws.get_client("cloudwatch")

            # Check for anomaly detectors
            paginator = cloudwatch.get_paginator("describe_anomaly_detectors")
            anomaly_detectors = []

            for page in paginator.paginate():
                anomaly_detectors.extend(page["AnomalyDetectors"])

            if not anomaly_detectors:
                findings.append(
                    {
                        "type": "NO_ANOMALY_DETECTORS",
                        "resource": "cloudwatch-anomaly-detection",
                        "details": "No CloudWatch Anomaly Detectors configured",
                    }
                )

            # Check for critical metrics without anomaly detection
            critical_metrics = ["CPUUtilization", "NetworkIn", "NetworkOut", "StatusCheckFailed"]

            detector_metrics = [d.get("MetricName", "") for d in anomaly_detectors]
            missing_metrics = [m for m in critical_metrics if m not in detector_metrics]

            if missing_metrics:
                findings.append(
                    {
                        "type": "MISSING_ANOMALY_DETECTION",
                        "resource": "cloudwatch-metrics",
                        "details": f'Critical metrics without anomaly detection: {", ".join(missing_metrics)}',
                    }
                )

        except Exception as e:
            logger.error(f"Error checking CloudWatch anomaly detection: {str(e)}")

        return findings

    def check_guardduty_enabled(self) -> List[Dict[str, Any]]:
        """Check if GuardDuty is enabled in all regions."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("guardduty", region):
                    continue

                try:
                    guardduty = self.aws.get_client("guardduty", region)

                    # List detectors
                    detectors = guardduty.list_detectors()["DetectorIds"]

                    if not detectors:
                        findings.append(
                            {
                                "type": "GUARDDUTY_NOT_ENABLED",
                                "resource": f"guardduty-{region}",
                                "region": region,
                                "details": f"GuardDuty not enabled in region {region}",
                            }
                        )
                    else:
                        # Check if detector is actually enabled
                        for detector_id in detectors:
                            detector = guardduty.get_detector(DetectorId=detector_id)
                            if detector["Status"] != "ENABLED":
                                findings.append(
                                    {
                                        "type": "GUARDDUTY_NOT_ACTIVE",
                                        "resource": detector_id,
                                        "region": region,
                                        "details": f"GuardDuty detector {detector_id} is not active in {region}",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking GuardDuty in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking GuardDuty: {str(e)}")

        return findings

    def check_inspector_assessments(self) -> List[Dict[str, Any]]:
        """Check if AWS Inspector is running assessments."""
        findings = []
        try:
            # Inspector v2 is the current version
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("inspector2", region):
                    continue

                try:
                    inspector = self.aws.get_client("inspector2", region)

                    # Check if Inspector is enabled
                    account_status = inspector.batch_get_account_status()

                    if account_status["accounts"]:
                        status = account_status["accounts"][0]["state"]
                        if status["status"] != "ENABLED":
                            findings.append(
                                {
                                    "type": "INSPECTOR_NOT_ENABLED",
                                    "resource": f"inspector-{region}",
                                    "region": region,
                                    "details": f"AWS Inspector not enabled in region {region}",
                                }
                            )
                    else:
                        findings.append(
                            {
                                "type": "INSPECTOR_NOT_CONFIGURED",
                                "resource": f"inspector-{region}",
                                "region": region,
                                "details": f"AWS Inspector not configured in region {region}",
                            }
                        )

                except Exception as e:
                    logger.error(f"Error checking Inspector in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking Inspector: {str(e)}")

        return findings

    def check_ssm_patch_compliance(self) -> List[Dict[str, Any]]:
        """Check EC2 instances patch compliance status."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                try:
                    ssm = self.aws.get_client("ssm", region)
                    ec2 = self.aws.get_client("ec2", region)

                    # Get all EC2 instances
                    instances = ec2.describe_instances()
                    instance_ids = []

                    for reservation in instances["Reservations"]:
                        for instance in reservation["Instances"]:
                            if instance["State"]["Name"] == "running":
                                instance_ids.append(instance["InstanceId"])

                    if instance_ids:
                        # Check patch compliance
                        compliance = ssm.list_compliance_items(
                            Filters=[{"Key": "ComplianceType", "Values": ["Patch"]}]
                        )

                        # Get non-compliant instances
                        for item in compliance.get("ComplianceItems", []):
                            if item["Status"] != "COMPLIANT":
                                findings.append(
                                    {
                                        "type": "PATCH_NON_COMPLIANCE",
                                        "resource": item["ResourceId"],
                                        "region": region,
                                        "details": f"Instance {item['ResourceId']} is non-compliant with patch baseline",
                                    }
                                )

                        # Check for instances without SSM agent
                        managed_instances = ssm.describe_instance_information()
                        managed_ids = [
                            i["InstanceId"]
                            for i in managed_instances.get("InstanceInformationList", [])
                        ]

                        unmanaged = set(instance_ids) - set(managed_ids)
                        for instance_id in unmanaged:
                            findings.append(
                                {
                                    "type": "NO_SSM_AGENT",
                                    "resource": instance_id,
                                    "region": region,
                                    "details": f"Instance {instance_id} does not have SSM agent installed/running",
                                }
                            )

                except Exception as e:
                    logger.error(
                        f"Error checking SSM patch compliance in region {region}: {str(e)}"
                    )

        except Exception as e:
            logger.error(f"Error checking SSM patch compliance: {str(e)}")

        return findings

    def check_security_hub_enabled(self) -> List[Dict[str, Any]]:
        """Check if Security Hub is enabled and configured."""
        findings = []
        try:
            # Check all regions
            enabled_regions = []

            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("securityhub", region):
                    continue

                try:
                    securityhub = self.aws.get_client("securityhub", region)

                    # Check if Security Hub is enabled
                    hub = securityhub.describe_hub()

                    if hub.get("HubArn"):
                        enabled_regions.append(region)

                        # Check if standards are enabled
                        standards = securityhub.get_enabled_standards()
                        if not standards["StandardsSubscriptions"]:
                            findings.append(
                                {
                                    "type": "NO_SECURITY_STANDARDS",
                                    "resource": f"securityhub-{region}",
                                    "region": region,
                                    "details": f"Security Hub enabled but no standards activated in {region}",
                                }
                            )

                except ClientError as e:
                    if e.response["Error"]["Code"] != "InvalidAccessException":
                        logger.error(f"Error checking Security Hub in region {region}: {str(e)}")

            # Check if Security Hub is enabled in all regions
            all_regions = self.aws.get_all_regions()
            if len(enabled_regions) < len(all_regions):
                missing_regions = set(all_regions) - set(enabled_regions)
                findings.append(
                    {
                        "type": "SECURITY_HUB_NOT_ALL_REGIONS",
                        "resource": "securityhub",
                        "details": f'Security Hub not enabled in regions: {", ".join(missing_regions)}',
                    }
                )

        except Exception as e:
            logger.error(f"Error checking Security Hub: {str(e)}")

        return findings

    def check_security_alarms(self) -> List[Dict[str, Any]]:
        """Check if CloudWatch alarms exist for security events."""
        findings = []
        try:
            cloudwatch = self.aws.get_client("cloudwatch")

            # Define required security alarms
            required_alarms = [
                "root-account-usage",
                "unauthorized-api-calls",
                "console-signin-failures",
                "iam-policy-changes",
                "cloudtrail-config-changes",
                "security-group-changes",
                "network-acl-changes",
                "vpc-gateway-changes",
            ]

            # Get all alarms
            paginator = cloudwatch.get_paginator("describe_alarms")
            existing_alarms = []

            for page in paginator.paginate():
                for alarm in page["MetricAlarms"]:
                    existing_alarms.append(alarm["AlarmName"].lower())

            # Check for missing security alarms
            missing_alarms = []
            for required in required_alarms:
                found = False
                for existing in existing_alarms:
                    if required in existing:
                        found = True
                        break
                if not found:
                    missing_alarms.append(required)

            if missing_alarms:
                findings.append(
                    {
                        "type": "MISSING_SECURITY_ALARMS",
                        "resource": "cloudwatch-alarms",
                        "details": f'Missing security alarms: {", ".join(missing_alarms)}',
                    }
                )

        except Exception as e:
            logger.error(f"Error checking security alarms: {str(e)}")

        return findings

    def check_security_sns_topics(self) -> List[Dict[str, Any]]:
        """Check if SNS topics exist for security notifications."""
        findings = []
        try:
            sns = self.aws.get_client("sns")

            # Get all SNS topics
            paginator = sns.get_paginator("list_topics")
            security_topics = []

            for page in paginator.paginate():
                for topic in page["Topics"]:
                    topic_arn = topic["TopicArn"]
                    # Check if topic name suggests security purpose
                    if any(
                        keyword in topic_arn.lower()
                        for keyword in ["security", "alert", "alarm", "incident", "notification"]
                    ):
                        security_topics.append(topic_arn)

                        # Check if topic has subscriptions
                        subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
                        if not subs["Subscriptions"]:
                            findings.append(
                                {
                                    "type": "SNS_TOPIC_NO_SUBSCRIBERS",
                                    "resource": topic_arn,
                                    "details": f"Security topic {topic_arn} has no subscribers",
                                }
                            )

            if not security_topics:
                findings.append(
                    {
                        "type": "NO_SECURITY_SNS_TOPICS",
                        "resource": "sns-topics",
                        "details": "No SNS topics found for security notifications",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking SNS security topics: {str(e)}")

        return findings

    def check_kms_key_rotation(self) -> List[Dict[str, Any]]:
        """Check if KMS key rotation is enabled."""
        findings = []
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                try:
                    kms = self.aws.get_client("kms", region)

                    # List all customer managed keys
                    paginator = kms.get_paginator("list_keys")

                    for page in paginator.paginate():
                        for key in page["Keys"]:
                            key_id = key["KeyId"]

                            try:
                                # Get key metadata
                                key_info = kms.describe_key(KeyId=key_id)
                                key_metadata = key_info["KeyMetadata"]

                                # Skip AWS managed keys
                                if key_metadata["KeyManager"] != "CUSTOMER":
                                    continue

                                # Skip keys that don't support rotation
                                if key_metadata["KeySpec"] != "SYMMETRIC_DEFAULT":
                                    continue

                                # Check rotation status
                                rotation_status = kms.get_key_rotation_status(KeyId=key_id)
                                if not rotation_status["KeyRotationEnabled"]:
                                    findings.append(
                                        {
                                            "type": "KMS_ROTATION_DISABLED",
                                            "resource": key_metadata["Arn"],
                                            "region": region,
                                            "details": f"Key rotation disabled for CMK {key_id}",
                                        }
                                    )

                            except ClientError as e:
                                if e.response["Error"]["Code"] not in [
                                    "AccessDeniedException",
                                    "InvalidKeyId.NotFound",
                                ]:
                                    logger.error(f"Error checking key {key_id}: {str(e)}")

                except Exception as e:
                    logger.error(f"Error checking KMS in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking KMS key rotation: {str(e)}")

        return findings

    def check_secrets_manager_usage(self) -> List[Dict[str, Any]]:
        """Check for hardcoded credentials that should be in Secrets Manager."""
        findings = []
        try:
            # Check for common indicators of hardcoded secrets
            # This is a simplified check - in practice would need more sophisticated detection

            # Check Lambda environment variables
            for region in self.aws.get_all_regions():
                try:
                    lambda_client = self.aws.get_client("lambda", region)

                    paginator = lambda_client.get_paginator("list_functions")
                    for page in paginator.paginate():
                        for function in page["Functions"]:
                            env_vars = function.get("Environment", {}).get("Variables", {})

                            # Check for potential secrets in environment variables
                            suspicious_keys = [
                                "password",
                                "secret",
                                "key",
                                "token",
                                "credential",
                                "api_key",
                            ]
                            for key, value in env_vars.items():
                                if any(suspicious in key.lower() for suspicious in suspicious_keys):
                                    # Check if it's a reference to Secrets Manager
                                    if not value.startswith("arn:aws:secretsmanager:"):
                                        findings.append(
                                            {
                                                "type": "HARDCODED_SECRET_SUSPECTED",
                                                "resource": function["FunctionArn"],
                                                "region": region,
                                                "details": f"Lambda function may have hardcoded secret in environment variable: {key}",
                                            }
                                        )

                except Exception as e:
                    logger.error(f"Error checking Lambda functions in region {region}: {str(e)}")

            # Check if Secrets Manager is being used at all
            secretsmanager = self.aws.get_client("secretsmanager")
            try:
                secrets = secretsmanager.list_secrets()
                if not secrets["SecretList"]:
                    findings.append(
                        {
                            "type": "NO_SECRETS_MANAGER_USAGE",
                            "resource": "secretsmanager",
                            "details": "No secrets found in AWS Secrets Manager",
                        }
                    )
            except Exception as e:
                logger.error(f"Error checking Secrets Manager: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking for hardcoded secrets: {str(e)}")

        return findings

    def check_vpc_endpoints(self) -> List[Dict[str, Any]]:
        """Check if VPC endpoints are used for AWS services."""
        findings = []
        try:
            # Services that should have VPC endpoints in production
            recommended_endpoints = ["s3", "dynamodb", "ec2", "kms", "secretsmanager", "ssm"]

            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client("ec2", region)

                    # Get all VPCs
                    vpcs = ec2.describe_vpcs()["Vpcs"]

                    for vpc in vpcs:
                        vpc_id = vpc["VpcId"]

                        # Get VPC endpoints for this VPC
                        endpoints = ec2.describe_vpc_endpoints(
                            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                        )["VpcEndpoints"]

                        # Extract service names from endpoints
                        existing_services = []
                        for endpoint in endpoints:
                            service_name = endpoint["ServiceName"].split(".")[-1]
                            existing_services.append(service_name)

                        # Check for missing recommended endpoints
                        missing_endpoints = [
                            svc for svc in recommended_endpoints if svc not in existing_services
                        ]

                        if missing_endpoints:
                            findings.append(
                                {
                                    "type": "MISSING_VPC_ENDPOINTS",
                                    "resource": vpc_id,
                                    "region": region,
                                    "details": f'VPC {vpc_id} missing endpoints for: {", ".join(missing_endpoints)}',
                                }
                            )

                except Exception as e:
                    logger.error(f"Error checking VPC endpoints in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking VPC endpoints: {str(e)}")

        return findings

    def check_efs_encryption(self) -> List[Dict[str, Any]]:
        """Check if EFS file systems are encrypted."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("efs", region):
                    continue

                try:
                    efs = self.aws.get_client("efs", region)

                    # List all EFS file systems
                    paginator = efs.get_paginator("describe_file_systems")

                    for page in paginator.paginate():
                        for fs in page["FileSystems"]:
                            if not fs.get("Encrypted", False):
                                findings.append(
                                    {
                                        "type": "EFS_NOT_ENCRYPTED",
                                        "resource": fs["FileSystemArn"],
                                        "region": region,
                                        "details": f"EFS file system {fs['FileSystemId']} is not encrypted",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking EFS in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking EFS encryption: {str(e)}")

        return findings

    def check_dynamodb_encryption(self) -> List[Dict[str, Any]]:
        """Check if DynamoDB tables are encrypted."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                try:
                    dynamodb = self.aws.get_client("dynamodb", region)

                    # List all tables
                    paginator = dynamodb.get_paginator("list_tables")

                    for page in paginator.paginate():
                        for table_name in page["TableNames"]:
                            # Describe table to check encryption
                            table = dynamodb.describe_table(TableName=table_name)
                            table_desc = table["Table"]

                            # Check if SSE is enabled
                            if (
                                "SSEDescription" not in table_desc
                                or table_desc["SSEDescription"]["Status"] != "ENABLED"
                            ):
                                findings.append(
                                    {
                                        "type": "DYNAMODB_NOT_ENCRYPTED",
                                        "resource": table_desc["TableArn"],
                                        "region": region,
                                        "details": f"DynamoDB table {table_name} does not have encryption enabled",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking DynamoDB in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking DynamoDB encryption: {str(e)}")

        return findings

    def check_elasticache_encryption(self) -> List[Dict[str, Any]]:
        """Check if ElastiCache clusters have encryption enabled."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("elasticache", region):
                    continue

                try:
                    elasticache = self.aws.get_client("elasticache", region)

                    # Check Redis replication groups
                    paginator = elasticache.get_paginator("describe_replication_groups")

                    for page in paginator.paginate():
                        for rg in page["ReplicationGroups"]:
                            # Check encryption at rest
                            if not rg.get("AtRestEncryptionEnabled", False):
                                findings.append(
                                    {
                                        "type": "ELASTICACHE_NOT_ENCRYPTED_AT_REST",
                                        "resource": rg["ARN"],
                                        "region": region,
                                        "details": f"ElastiCache replication group {rg['ReplicationGroupId']} does not have at-rest encryption",
                                    }
                                )

                            # Check encryption in transit
                            if not rg.get("TransitEncryptionEnabled", False):
                                findings.append(
                                    {
                                        "type": "ELASTICACHE_NOT_ENCRYPTED_IN_TRANSIT",
                                        "resource": rg["ARN"],
                                        "region": region,
                                        "details": f"ElastiCache replication group {rg['ReplicationGroupId']} does not have in-transit encryption",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking ElastiCache in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking ElastiCache encryption: {str(e)}")

        return findings

    def check_network_acl_rules(self) -> List[Dict[str, Any]]:
        """Check for overly permissive Network ACL rules."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client("ec2", region)

                    # Get all Network ACLs
                    nacls = ec2.describe_network_acls()

                    for nacl in nacls["NetworkAcls"]:
                        # Check for overly permissive rules
                        for entry in nacl["Entries"]:
                            # Check for allow all traffic rules
                            if (
                                entry["RuleAction"] == "allow"
                                and entry.get("CidrBlock") == "0.0.0.0/0"
                                and entry["Protocol"] == "-1"
                            ):  # -1 means all protocols

                                findings.append(
                                    {
                                        "type": "NACL_ALLOWS_ALL_TRAFFIC",
                                        "resource": nacl["NetworkAclId"],
                                        "region": region,
                                        "details": f"Network ACL {nacl['NetworkAclId']} has rule allowing all traffic from 0.0.0.0/0",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking Network ACLs in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking Network ACL rules: {str(e)}")

        return findings

    def check_waf_enabled(self) -> List[Dict[str, Any]]:
        """Check if WAF is enabled for web applications."""
        findings = []
        try:
            # Check WAFv2 (current version)
            self.aws.get_client("wafv2")

            # Check for CloudFront distributions without WAF
            cloudfront = self.aws.get_client("cloudfront")

            try:
                # Get all CloudFront distributions
                paginator = cloudfront.get_paginator("list_distributions")
                cf_distributions = []

                for page in paginator.paginate():
                    if "Items" in page["DistributionList"]:
                        cf_distributions.extend(page["DistributionList"]["Items"])

                # Check each distribution for WAF association
                for dist in cf_distributions:
                    if not dist.get("WebACLId"):
                        findings.append(
                            {
                                "type": "CLOUDFRONT_NO_WAF",
                                "resource": dist["ARN"],
                                "details": f"CloudFront distribution {dist['Id']} does not have WAF enabled",
                            }
                        )

            except Exception as e:
                logger.error(f"Error checking CloudFront WAF: {str(e)}")

            # Check for ALBs without WAF in each region
            for region in self.aws.get_all_regions():
                try:
                    elbv2 = self.aws.get_client("elbv2", region)
                    wafv2_regional = self.aws.get_client("wafv2", region)

                    # Get all ALBs
                    paginator = elbv2.get_paginator("describe_load_balancers")

                    for page in paginator.paginate():
                        for lb in page["LoadBalancers"]:
                            if lb["Type"] == "application":
                                # Check if ALB has WAF association
                                try:
                                    waf_response = wafv2_regional.get_web_acl_for_resource(
                                        ResourceArn=lb["LoadBalancerArn"]
                                    )
                                    if not waf_response.get("WebACL"):
                                        findings.append(
                                            {
                                                "type": "ALB_NO_WAF",
                                                "resource": lb["LoadBalancerArn"],
                                                "region": region,
                                                "details": f"ALB {lb['LoadBalancerName']} does not have WAF enabled",
                                            }
                                        )
                                except ClientError as e:
                                    if e.response["Error"]["Code"] != "WAFNonexistentItemException":
                                        logger.error(f"Error checking WAF for ALB: {str(e)}")

                except Exception as e:
                    logger.error(f"Error checking ALBs in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking WAF: {str(e)}")

        return findings

    def check_cloudfront_security_headers(self) -> List[Dict[str, Any]]:
        """Check if CloudFront distributions use security headers."""
        findings = []
        try:
            cloudfront = self.aws.get_client("cloudfront")

            # Security headers to check for

            # Get all distributions
            paginator = cloudfront.get_paginator("list_distributions")

            for page in paginator.paginate():
                if "Items" in page["DistributionList"]:
                    for dist in page["DistributionList"]["Items"]:
                        # Get distribution config
                        dist_config = cloudfront.get_distribution_config(Id=dist["Id"])

                        # Simple check - in reality would need to check response headers policy
                        # This is a simplified version
                        if not dist_config["DistributionConfig"].get("ResponseHeadersPolicyId"):
                            findings.append(
                                {
                                    "type": "CLOUDFRONT_NO_SECURITY_HEADERS",
                                    "resource": dist["ARN"],
                                    "details": f"CloudFront distribution {dist['Id']} does not have a response headers policy",
                                }
                            )

        except Exception as e:
            logger.error(f"Error checking CloudFront security headers: {str(e)}")

        return findings

    def check_iam_roles_for_services(self) -> List[Dict[str, Any]]:
        """Check if EC2 instances use IAM roles instead of hardcoded credentials."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                try:
                    ec2 = self.aws.get_client("ec2", region)

                    # Get all instances
                    paginator = ec2.get_paginator("describe_instances")

                    for page in paginator.paginate():
                        for reservation in page["Reservations"]:
                            for instance in reservation["Instances"]:
                                if instance["State"]["Name"] == "running":
                                    # Check if instance has IAM role
                                    if "IamInstanceProfile" not in instance:
                                        findings.append(
                                            {
                                                "type": "EC2_NO_IAM_ROLE",
                                                "resource": instance["InstanceId"],
                                                "region": region,
                                                "details": f"EC2 instance {instance['InstanceId']} does not have an IAM role attached",
                                            }
                                        )

                except Exception as e:
                    logger.error(f"Error checking EC2 IAM roles in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking IAM roles for services: {str(e)}")

        return findings

    def check_cross_account_access(self) -> List[Dict[str, Any]]:
        """Check and validate cross-account access roles."""
        findings = []
        try:
            iam = self.aws.get_client("iam")

            # Get all roles
            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page["Roles"]:
                    # Check assume role policy for cross-account access
                    assume_policy = role["AssumeRolePolicyDocument"]

                    for statement in assume_policy.get("Statement", []):
                        if statement.get("Effect") == "Allow":
                            principal = statement.get("Principal", {})

                            # Check for external AWS accounts
                            if isinstance(principal, dict) and "AWS" in principal:
                                aws_principals = (
                                    principal["AWS"]
                                    if isinstance(principal["AWS"], list)
                                    else [principal["AWS"]]
                                )

                                for arn in aws_principals:
                                    if isinstance(arn, str) and ":root" in arn:
                                        # Extract account ID
                                        account_id = arn.split(":")[4]
                                        if account_id != self.aws.account_id:
                                            findings.append(
                                                {
                                                    "type": "CROSS_ACCOUNT_ROLE",
                                                    "resource": role["Arn"],
                                                    "details": f"Role {role['RoleName']} allows cross-account access from account {account_id}",
                                                }
                                            )

        except Exception as e:
            logger.error(f"Error checking cross-account access: {str(e)}")

        return findings

    def check_backup_plans(self) -> List[Dict[str, Any]]:
        """Check if AWS Backup plans exist for critical resources."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("backup", region):
                    continue

                try:
                    backup = self.aws.get_client("backup", region)

                    # Get backup plans
                    plans = backup.list_backup_plans()

                    if not plans["BackupPlansList"]:
                        findings.append(
                            {
                                "type": "NO_BACKUP_PLANS",
                                "resource": f"backup-{region}",
                                "region": region,
                                "details": f"No AWS Backup plans configured in region {region}",
                            }
                        )
                    else:
                        # Check if plans have selections
                        for plan in plans["BackupPlansList"]:
                            selections = backup.list_backup_selections(
                                BackupPlanId=plan["BackupPlanId"]
                            )

                            if not selections["BackupSelectionsList"]:
                                findings.append(
                                    {
                                        "type": "BACKUP_PLAN_NO_RESOURCES",
                                        "resource": plan["BackupPlanArn"],
                                        "region": region,
                                        "details": f"Backup plan {plan['BackupPlanName']} has no resources selected",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking backup plans in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking AWS Backup plans: {str(e)}")

        return findings

    def check_rds_backups(self) -> List[Dict[str, Any]]:
        """Check if RDS instances have automated backups enabled."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("rds", region):
                    continue

                try:
                    rds = self.aws.get_client("rds", region)

                    # Get all DB instances
                    paginator = rds.get_paginator("describe_db_instances")

                    for page in paginator.paginate():
                        for db in page["DBInstances"]:
                            # Check backup retention period
                            if db["BackupRetentionPeriod"] == 0:
                                findings.append(
                                    {
                                        "type": "RDS_NO_BACKUPS",
                                        "resource": db["DBInstanceArn"],
                                        "region": region,
                                        "details": f"RDS instance {db['DBInstanceIdentifier']} has automated backups disabled",
                                    }
                                )
                            elif db["BackupRetentionPeriod"] < 7:
                                findings.append(
                                    {
                                        "type": "RDS_SHORT_BACKUP_RETENTION",
                                        "resource": db["DBInstanceArn"],
                                        "region": region,
                                        "details": f"RDS instance {db['DBInstanceIdentifier']} has backup retention less than 7 days",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking RDS backups in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking RDS backups: {str(e)}")

        return findings

    def check_cloudwatch_logs_retention(self) -> List[Dict[str, Any]]:
        """Check CloudWatch Logs retention periods."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                try:
                    logs = self.aws.get_client("logs", region)

                    # Get all log groups
                    paginator = logs.get_paginator("describe_log_groups")

                    for page in paginator.paginate():
                        for log_group in page["logGroups"]:
                            # Check if retention is set
                            if "retentionInDays" not in log_group:
                                findings.append(
                                    {
                                        "type": "CLOUDWATCH_LOGS_NO_RETENTION",
                                        "resource": log_group["arn"],
                                        "region": region,
                                        "details": f"Log group {log_group['logGroupName']} has no retention policy set",
                                    }
                                )
                            elif log_group["retentionInDays"] < 90:
                                findings.append(
                                    {
                                        "type": "CLOUDWATCH_LOGS_SHORT_RETENTION",
                                        "resource": log_group["arn"],
                                        "region": region,
                                        "details": f"Log group {log_group['logGroupName']} has retention less than 90 days",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking CloudWatch Logs in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking CloudWatch Logs retention: {str(e)}")

        return findings

    def check_api_gateway_logging(self) -> List[Dict[str, Any]]:
        """Check if API Gateway has logging enabled."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                try:
                    apigateway = self.aws.get_client("apigateway", region)

                    # Get all REST APIs
                    paginator = apigateway.get_paginator("get_rest_apis")

                    for page in paginator.paginate():
                        for api in page["items"]:
                            # Get stages for each API
                            stages = apigateway.get_stages(restApiId=api["id"])

                            for stage in stages["item"]:
                                # Check if logging is enabled
                                if not stage.get("accessLogSettings"):
                                    findings.append(
                                        {
                                            "type": "API_GATEWAY_NO_LOGGING",
                                            "resource": f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage['stageName']}",
                                            "region": region,
                                            "details": f"API Gateway {api['name']} stage {stage['stageName']} has no access logging",
                                        }
                                    )

                except Exception as e:
                    logger.error(f"Error checking API Gateway in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking API Gateway logging: {str(e)}")

        return findings

    def check_lambda_logging(self) -> List[Dict[str, Any]]:
        """Check if Lambda functions have proper logging configuration."""
        findings = []
        try:
            for region in self.aws.get_all_regions():
                try:
                    lambda_client = self.aws.get_client("lambda", region)
                    logs = self.aws.get_client("logs", region)

                    # Get all Lambda functions
                    paginator = lambda_client.get_paginator("list_functions")

                    for page in paginator.paginate():
                        for function in page["Functions"]:
                            # Check if CloudWatch Logs log group exists
                            log_group_name = f"/aws/lambda/{function['FunctionName']}"

                            try:
                                logs.describe_log_groups(logGroupNamePrefix=log_group_name)
                            except ClientError:
                                findings.append(
                                    {
                                        "type": "LAMBDA_NO_LOG_GROUP",
                                        "resource": function["FunctionArn"],
                                        "region": region,
                                        "details": f"Lambda function {function['FunctionName']} has no CloudWatch Logs group",
                                    }
                                )

                except Exception as e:
                    logger.error(f"Error checking Lambda functions in region {region}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking Lambda logging: {str(e)}")

        return findings

    def check_cloudtrail_kms_encryption(self) -> List[Dict[str, Any]]:
        """Check if CloudTrail logs are encrypted with KMS."""
        findings = []
        try:
            cloudtrail = self.aws.get_client("cloudtrail")

            # Get all trails
            trails = cloudtrail.describe_trails()

            for trail in trails["trailList"]:
                # Check if KMS encryption is enabled
                if not trail.get("KmsKeyId"):
                    findings.append(
                        {
                            "type": "CLOUDTRAIL_NO_KMS_ENCRYPTION",
                            "resource": trail["TrailARN"],
                            "details": f"CloudTrail {trail['Name']} is not encrypted with KMS",
                        }
                    )

        except Exception as e:
            logger.error(f"Error checking CloudTrail KMS encryption: {str(e)}")

        return findings

    def check_s3_bucket_logging(self) -> List[Dict[str, Any]]:
        """Check if S3 buckets have access logging enabled."""
        findings = []
        try:
            s3 = self.aws.get_client("s3")

            # Get all buckets
            buckets = s3.list_buckets()

            for bucket in buckets["Buckets"]:
                bucket_name = bucket["Name"]

                try:
                    # Check if bucket has logging enabled
                    logging_config = s3.get_bucket_logging(Bucket=bucket_name)

                    if "LoggingEnabled" not in logging_config:
                        # Check if this is a sensitive bucket (contains certain keywords)
                        sensitive_keywords = ["logs", "backup", "data", "config", "audit"]
                        if any(keyword in bucket_name.lower() for keyword in sensitive_keywords):
                            findings.append(
                                {
                                    "type": "S3_BUCKET_NO_LOGGING",
                                    "resource": f"arn:aws:s3:::{bucket_name}",
                                    "details": f"S3 bucket {bucket_name} appears sensitive but has no access logging",
                                }
                            )

                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchBucket":
                        logger.error(f"Error checking bucket {bucket_name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking S3 bucket logging: {str(e)}")

        return findings
