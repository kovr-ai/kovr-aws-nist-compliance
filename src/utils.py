#!/usr/bin/env python3
"""Utility functions for AWS NIST compliance checker."""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def validate_aws_credentials(access_key: str, secret_key: str) -> bool:
    """Validate AWS credential format."""
    # AWS Access Key ID format: 20 uppercase alphanumeric characters
    access_key_pattern = re.compile(r"^[A-Z0-9]{20}$")

    # AWS Secret Access Key format: 40 base64 characters
    secret_key_pattern = re.compile(r"^[A-Za-z0-9/+=]{40}$")

    return bool(access_key_pattern.match(access_key) and secret_key_pattern.match(secret_key))


def parse_severity_level(severity: str) -> int:
    """Convert severity string to numeric level."""
    severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return severity_map.get(severity.upper(), 0)


def format_resource_arn(
    resource_type: str, resource_id: str, account_id: str, region: str = None
) -> str:
    """Format a resource identifier as an ARN."""
    if resource_id.startswith("arn:"):
        return resource_id

    # Build ARN based on resource type
    arn_patterns = {
        "s3": f"arn:aws:s3:::{resource_id}",
        "iam": f"arn:aws:iam::{account_id}:{resource_type}/{resource_id}",
        "ec2": f"arn:aws:ec2:{region}:{account_id}:{resource_type}/{resource_id}",
        "rds": f"arn:aws:rds:{region}:{account_id}:{resource_type}:{resource_id}",
        "lambda": f"arn:aws:lambda:{region}:{account_id}:function:{resource_id}",
    }

    service = resource_type.split("-")[0] if "-" in resource_type else resource_type
    pattern = arn_patterns.get(service)

    if pattern:
        return pattern
    else:
        # Generic ARN format
        return f'arn:aws:{service}:{region or "*"}:{account_id}:{resource_type}/{resource_id}'


def calculate_compliance_score(results: List[Dict[str, Any]]) -> Dict[str, float]:
    """Calculate overall compliance score and breakdown by severity."""
    if not results:
        return {"overall": 0.0, "by_severity": {}}

    # Overall score
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    overall_score = (passed / total) * 100

    # Score by severity
    severity_scores = {}
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_results = [r for r in results if r["severity"] == severity]
        if severity_results:
            severity_passed = sum(1 for r in severity_results if r["status"] == "PASS")
            severity_scores[severity] = (severity_passed / len(severity_results)) * 100
        else:
            severity_scores[severity] = 100.0  # No checks means compliant

    return {
        "overall": overall_score,
        "by_severity": severity_scores,
        "total_checks": total,
        "passed_checks": passed,
        "failed_checks": total - passed,
    }


def group_findings_by_service(results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group failed findings by AWS service."""
    service_findings = {}

    for result in results:
        if result["status"] == "FAIL" and result["findings"]:
            # Extract service from check config or resource ARN
            service = "unknown"

            # Try to get service from first affected resource
            if result["affected_resources"]:
                first_resource = result["affected_resources"][0]
                if first_resource.startswith("arn:aws:"):
                    parts = first_resource.split(":")
                    if len(parts) > 2:
                        service = parts[2]

            if service not in service_findings:
                service_findings[service] = []

            service_findings[service].extend(result["findings"])

    return service_findings


def estimate_remediation_effort(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Estimate remediation effort based on findings."""
    effort_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    total_effort = 0
    remediation_items = []

    for result in results:
        if result["status"] == "FAIL":
            severity = result["severity"]
            effort = effort_weights.get(severity, 1)
            finding_count = len(result["findings"])

            total_effort += effort * finding_count

            remediation_items.append(
                {
                    "check_id": result["check_id"],
                    "check_name": result["check_name"],
                    "severity": severity,
                    "effort_score": effort * finding_count,
                    "finding_count": finding_count,
                }
            )

    # Sort by effort score
    remediation_items.sort(key=lambda x: x["effort_score"], reverse=True)

    return {
        "total_effort_score": total_effort,
        "estimated_hours": total_effort * 2,  # Rough estimate: 2 hours per effort point
        "priority_items": remediation_items[:10],  # Top 10 items
        "total_items": len(remediation_items),
    }


def validate_check_config(check: Dict[str, Any]) -> List[str]:
    """Validate a security check configuration."""
    errors = []
    required_fields = [
        "id",
        "name",
        "category",
        "framework",
        "severity",
        "nist_mappings",
        "service",
        "check_function",
    ]

    for field in required_fields:
        if field not in check:
            errors.append(f"Missing required field: {field}")

    # Validate severity
    if "severity" in check and check["severity"] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        errors.append(f"Invalid severity: {check['severity']}")

    # Validate NIST mappings
    if "nist_mappings" in check:
        if not isinstance(check["nist_mappings"], list):
            errors.append("nist_mappings must be a list")
        elif not check["nist_mappings"]:
            errors.append("nist_mappings cannot be empty")

    return errors


def merge_check_results(
    results1: List[Dict[str, Any]], results2: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Merge results from multiple compliance runs."""
    # Create a map of existing results by check_id
    results_map = {r["check_id"]: r for r in results1}

    # Merge or add results from second set
    for result in results2:
        check_id = result["check_id"]
        if check_id in results_map:
            # Update with latest result
            existing = results_map[check_id]
            # Keep the worst status (FAIL > ERROR > PASS)
            if result["status"] == "FAIL" or existing["status"] == "PASS":
                results_map[check_id] = result
            elif result["status"] == "ERROR" and existing["status"] != "FAIL":
                results_map[check_id] = result
        else:
            results_map[check_id] = result

    return list(results_map.values())


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage."""
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    return sanitized


def parse_resource_tags(tags: List[Dict[str, str]]) -> Dict[str, str]:
    """Parse AWS resource tags into a dictionary."""
    tag_dict = {}
    for tag in tags:
        if "Key" in tag and "Value" in tag:
            tag_dict[tag["Key"]] = tag["Value"]
    return tag_dict


def filter_resources_by_tags(
    resources: List[Dict[str, Any]], required_tags: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Filter AWS resources by required tags."""
    filtered = []

    for resource in resources:
        resource_tags = parse_resource_tags(resource.get("Tags", []))

        # Check if all required tags match
        match = True
        for key, value in required_tags.items():
            if key not in resource_tags or resource_tags[key] != value:
                match = False
                break

        if match:
            filtered.append(resource)

    return filtered
