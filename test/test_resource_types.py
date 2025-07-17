#!/usr/bin/env python3
"""
Test script to verify resource type detection logic.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Load .env if present
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

sys.path.append(os.path.join(os.path.dirname(__file__), "../src"))

from report_generator import ReportGenerator


def test_resource_type_detection():
    """Test the resource type detection logic."""

    # Create a dummy ReportGenerator instance
    dummy_results = []
    dummy_nist_mappings = {}
    report_gen = ReportGenerator(dummy_results, dummy_nist_mappings)

    # Test cases from the actual CSV data
    test_cases = [
        # EBS Volumes
        ("vol-09c206a1c09b33af3", "EBS Volume"),
        ("vol-0631e4815530ca36f", "EBS Volume"),
        ("vol-0a8a5fee964beea8b", "EBS Volume"),
        # Security Groups
        ("sg-094a6eb65248287d3", "Security Group"),
        ("sg-0dbe5e23262e65265", "Security Group"),
        ("sg-0ea03cc551152bed0", "Security Group"),
        # VPCs
        ("vpc-09323d4bf8f466750", "VPC"),
        ("vpc-0b765906e45af5081", "VPC"),
        ("vpc-073aa773c7aebb2a8", "VPC"),
        # EC2 Instances
        ("i-0122a9ca02ffb28c3", "EC2 Instance"),
        ("i-0f4c080c61bf18afa", "EC2 Instance"),
        # Network ACLs
        ("acl-0a2c7c085118c3fe0", "Network ACL"),
        ("acl-097197bf3f683eb6d", "Network ACL"),
        # ARN formats
        ("arn:aws:s3:::aws-cloudtrail-logs-314146328961-77256df2", "S3 Bucket"),
        ("arn:aws:ec2:us-west-2:314146328961:volume/vol-0631e4815530ca36f", "EBS Volume"),
        (
            "arn:aws:dynamodb:us-east-1:314146328961:table/terraform-locks-314146328961",
            "DynamoDB Table",
        ),
        (
            "arn:aws:elasticache:us-west-2:314146328961:replicationgroup:prod-kovr-prod-app-redis",
            "ElastiCache Cluster",
        ),
        (
            "arn:aws:elasticloadbalancing:us-west-2:314146328961:loadbalancer/app/InfraP-ChatS-juQ3Vpp91iIT/49ddca235e5e1fe9",
            "ELASTICLOADBALANCING Resource",
        ),
        ("arn:aws:cloudfront::314146328961:distribution/E2LWOCA351O6SU", "CloudFront Distribution"),
        (
            "arn:aws:logs:us-west-2:314146328961:log-group:/aws/pipes/artifacts-listner-queue:*",
            "CloudWatch Log Group",
        ),
        ("arn:aws:iam::314146328961:role/OrganizationAccountAccessRole", "IAM Role"),
        # Special cases
        ("aws-config", "aws-config"),
        ("cloudwatch-metrics", "CloudWatch Metrics"),
        ("cloudwatch-anomaly-detection", "CloudWatch Anomaly Detection"),
        ("guardduty-us-east-1", "GuardDuty Detector"),
        ("inspector-us-east-1", "Inspector Assessment"),
        ("securityhub", "Security Hub"),
        ("secretsmanager", "Secrets Manager"),
        ("backup-us-east-1", "Backup Plan"),
        ("cloudwatch-alarms", "CloudWatch Alarm"),
        ("sns-topics", "SNS Topic"),
    ]

    print("Testing resource type detection:")
    print("=" * 60)

    passed = 0
    failed = 0

    for resource_id, expected_type in test_cases:
        detected_type = report_gen._get_resource_type_from_arn(resource_id)
        if detected_type == expected_type:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        print(
            f"{status} | {resource_id:<50} | Expected: {expected_type:<25} | Got: {detected_type}"
        )

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All resource type detection tests passed!")
    else:
        print("❌ Some resource type detection tests failed.")

    return failed == 0


if __name__ == "__main__":
    success = test_resource_type_detection()
    sys.exit(0 if success else 1)
