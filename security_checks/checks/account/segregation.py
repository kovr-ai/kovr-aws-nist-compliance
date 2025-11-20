#!/usr/bin/env python3
"""Ensure production accounts are separated"""

import os
import contextlib
import configparser
import logging
from typing import Any, Dict, List, Iterator, Tuple, Optional

import boto3
from botocore.client import BaseClient

from security_checks.base import BaseSecurityCheck

logger = logging.getLogger(__name__)


# ------------------------------
# Helpers for config & sessions
# ------------------------------

def _active_profile_name() -> str:
    return (
        os.getenv("AWS_PROFILE")
        or os.getenv("AWS_DEFAULT_PROFILE")
        or "default"
    )


def _load_mgmt_role_cfg() -> Dict[str, Any]:
    """
    Load custom keys from ~/.aws/config for the active profile.
    Keys:
      - mgmt_role_arn                (required)
      - mgmt_role_region             (default: us-east-1)
      - mgmt_role_duration           (default: 900)
      - mgmt_role_session_name       (default: segregation-check)
    """
    profile = _active_profile_name()
    section = "default" if profile == "default" else f"profile {profile}"

    cfg_path = os.path.expanduser("~/.aws/config")
    parser = configparser.RawConfigParser()
    parser.read(cfg_path)

    get = lambda key, default=None: parser.get(section, key, fallback=default)

    mgmt_role_arn = get("mgmt_role_arn", None)
    mgmt_role_region = get("mgmt_role_region", "us-east-1")
    mgmt_role_duration = int(get("mgmt_role_duration", "900"))
    mgmt_role_session_name = get("mgmt_role_session_name", "segregation-check")

    # If ARN is GovCloud but region is left at the public default, nudge to GovCloud.
    if (
        mgmt_role_arn
        and "arn:aws-us-gov:" in mgmt_role_arn
        and mgmt_role_region == "us-east-1"
    ):
        mgmt_role_region = "us-gov-west-1"

    return {
        "arn": mgmt_role_arn,
        "region": mgmt_role_region,
        "duration": mgmt_role_duration,
        "session_name": mgmt_role_session_name,
    }


@contextlib.contextmanager
def assumed_role_session(
    role_arn: str,
    role_session_name: str,
    duration_seconds: int,
    region_name: str,
) -> Iterator[boto3.Session]:
    """
    Yield a boto3.Session using STS:AssumeRole with the provided parameters.
    Does NOT mutate the caller's default environment/session.
    """
    sts: BaseClient = boto3.client("sts", region_name=region_name)
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=role_session_name,
        DurationSeconds=duration_seconds,
    )
    creds = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region_name,
    )
    try:
        yield session
    finally:
        # Nothing to clean up; creds expire automatically.
        pass


# ------------------------------
# The check
# ------------------------------

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
            'aws_well_architected': ['SEC-1'],
            'nist_800_53': ['SC-32'],
            'nist_800_171': ['3.13.2'],
            'zero_trust': ['ZT-4.4']
        }

    def _mgmt_role_params(self) -> Optional[Tuple[str, str, int, str]]:
        """
        Pull AssumeRole parameters from ~/.aws/config (active profile).
        Returns (role_arn, region, duration_seconds, session_name) or None if not configured.
        """
        cfg = _load_mgmt_role_cfg()
        if not cfg.get("arn"):
            return None
        return cfg["arn"], cfg["region"], cfg["duration"], cfg["session_name"]
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the segregation_of_production check."""
        try:
            mgmt_params = self._mgmt_role_params()
            if not mgmt_params:
                # Skip this check if mgmt_role_arn is not configured
                logger.warning(
                    f"Skipping {self.check_id} ({self.description}): "
                    f"mgmt_role_arn not configured in ~/.aws/config for profile '{_active_profile_name()}'. "
                    f"Add 'mgmt_role_arn' to your AWS config to enable this check."
                )
                return self.findings
            
            role_arn, role_region, role_duration, role_session_name = mgmt_params

            # Assume into the management account and call Organizations there
            with assumed_role_session(
                role_arn=role_arn,
                role_session_name=role_session_name,
                duration_seconds=role_duration,
                region_name=role_region,
            ) as mgmt_sess:
                org_client = mgmt_sess.client("organizations", region_name=role_region)

                try:
                    org_info = org_client.describe_organization()
                    _ = org_info['Organization']  # verifies org is enabled

                    # Roots
                    roots = org_client.list_roots()
                    root_id = roots['Roots'][0]['Id']

                    # OUs (paginate)
                    ous: List[Dict[str, Any]] = []
                    paginator = org_client.get_paginator("list_organizational_units_for_parent")
                    for page in paginator.paginate(ParentId=root_id):
                        ous.extend(page.get("OrganizationalUnits", []))

                    ou_names = [ou['Name'].lower() for ou in ous]
                    has_prod_ou = any('prod' in name for name in ou_names)
                    has_dev_ou = any(name in ['dev', 'development', 'test', 'staging'] for name in ou_names)

                    if not (has_prod_ou and has_dev_ou):
                        # Accounts (paginate)
                        prod_accounts = 0
                        non_prod_accounts = 0
                        acct_paginator = org_client.get_paginator("list_accounts")
                        for page in acct_paginator.paginate():
                            for account in page.get('Accounts', []):
                                try:
                                    tags_resp = org_client.list_tags_for_resource(ResourceId=account['Id'])
                                    for tag in tags_resp.get('Tags', []):
                                        if tag['Key'].lower() in ['environment', 'env']:
                                            if 'prod' in tag['Value'].lower():
                                                prod_accounts += 1
                                            else:
                                                non_prod_accounts += 1
                                            break
                                except Exception:
                                    # Non-fatal: continue scanning
                                    pass

                        if prod_accounts == 0 or non_prod_accounts == 0:
                            self.add_finding(
                                resource_type="AWS::Organizations::Account",
                                resource_id=self.aws.account_id,  # current member account id
                                region="global",
                                severity="HIGH",
                                details="No clear separation between production and non-production accounts detected",
                                recommendation=(
                                    "Implement account separation strategy using Organizations OUs "
                                    "or consistent tagging to isolate production workloads."
                                ),
                                evidence={
                                    "organization_enabled": True,
                                    "ou_count": len(ous),
                                    "has_production_ou": has_prod_ou,
                                    "has_development_ou": has_dev_ou,
                                    "tagged_prod_accounts": prod_accounts,
                                    "tagged_nonprod_accounts": non_prod_accounts
                                }
                            )

                except Exception as e:
                    # If Organizations isn't enabled, fall back to a member-account heuristic
                    if 'AWSOrganizationsNotInUseException' in str(e):
                        ec2_client = self.aws.get_client('ec2', self.regions[0])
                        instances = ec2_client.describe_instances()
                        has_production_resources = False

                        for reservation in instances.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                for tag in instance.get('Tags', []) or []:
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
                                recommendation=(
                                    "Enable AWS Organizations and implement a multi-account strategy "
                                    "to separate production from non-production workloads."
                                ),
                                evidence={
                                    "organization_enabled": False,
                                    "has_production_resources": True
                                }
                            )
                    else:
                        raise  # bubble up to outer handler

            # Leaving the context → we're back on original member-account creds.

        except Exception as e:
            self.handle_error(e, "checking account segregation")

        return self.findings
