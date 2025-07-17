#!/usr/bin/env python3
"""
Example script showing how to use the AWS NIST compliance checker programmatically.
This can be used for integration into larger systems or CI/CD pipelines.
"""

import json
import os

# Add the src directory to Python path
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Load AWS credentials from .env if present
from dotenv import load_dotenv

from aws_connector import AWSConnector, SecurityCheck
from report_generator import ReportGenerator

load_dotenv()


def run_compliance_check_example():
    """Example of running compliance checks programmatically."""

    # Load configurations
    with open("security_checks/checks_config.json", "r") as f:
        security_checks = json.load(f)

    with open("mappings/nist_800_53_mappings.json", "r") as f:
        nist_mappings = json.load(f)

    # Initialize AWS connector
    # You can pass credentials directly or use environment variables
    aws_connector = AWSConnector(
        access_key=os.getenv("AWS_ACCESS_KEY_ID"),
        secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        session_token=os.getenv("AWS_SESSION_TOKEN"),
        region="us-east-1",
    )

    print(f"Connected to AWS Account: {aws_connector.account_id}")

    # Initialize security checker
    security_checker = SecurityCheck(aws_connector)

    # Run specific checks (or all checks)
    results = []
    checks_to_run = security_checks["security_checks"][:5]  # Run first 5 checks as example

    for check_config in checks_to_run:
        print(f"Running check: {check_config['name']}...")
        result = security_checker.run_check(check_config)
        results.append(result)

        # Print immediate feedback
        if result["status"] == "FAIL":
            print(f"  ❌ FAILED - {len(result['findings'])} issues found")
        elif result["status"] == "PASS":
            print(f"  ✅ PASSED")
        else:
            print(f"  ⚠️  ERROR")

    # Generate reports
    report_generator = ReportGenerator(results, nist_mappings)

    # Generate all report types
    csv_path = report_generator.generate_csv_report()
    md_path = report_generator.generate_markdown_report()
    json_path = report_generator.generate_summary_json()
    # Generate the new resource-level report
    resources_path = report_generator.generate_resources_report()

    print(f"\nReports generated:")
    print(f"  - CSV: {csv_path}")
    print(f"  - Markdown: {md_path}")
    print(f"  - JSON: {json_path}")
    print(f"  - Resources CSV: {resources_path}")

    # Example: Process results programmatically
    failed_checks = [r for r in results if r["status"] == "FAIL"]
    if failed_checks:
        print(f"\n⚠️  {len(failed_checks)} checks failed:")
        for check in failed_checks:
            print(f"  - {check['check_name']}: {len(check['findings'])} findings")

    return results


def analyze_by_nist_control(results):
    """Example of analyzing results by NIST control."""
    control_summary = {}

    for result in results:
        for control in result["nist_mappings"]:
            if control not in control_summary:
                control_summary[control] = {"total": 0, "passed": 0, "failed": 0, "checks": []}

            control_summary[control]["total"] += 1
            control_summary[control]["checks"].append(result["check_id"])

            if result["status"] == "PASS":
                control_summary[control]["passed"] += 1
            elif result["status"] == "FAIL":
                control_summary[control]["failed"] += 1

    print("\nNIST Control Coverage Summary:")
    for control, stats in sorted(control_summary.items()):
        coverage = (stats["passed"] / stats["total"]) * 100
        print(
            f"  {control}: {coverage:.1f}% compliant ({stats['passed']}/{stats['total']} checks passed)"
        )


def check_critical_controls(results):
    """Example of checking specific critical controls."""
    critical_controls = ["AC-2", "AU-2", "SC-28", "IA-2"]

    print("\nCritical Control Status:")
    for control in critical_controls:
        control_results = [r for r in results if control in r["nist_mappings"]]

        if control_results:
            failed = sum(1 for r in control_results if r["status"] == "FAIL")
            total = len(control_results)
            status = (
                "✅ COMPLIANT"
                if failed == 0
                else f"❌ NON-COMPLIANT ({failed}/{total} checks failed)"
            )
            print(f"  {control}: {status}")
        else:
            print(f"  {control}: ⚠️  No checks mapped")


if __name__ == "__main__":
    # Run the compliance check
    results = run_compliance_check_example()

    # Analyze results by NIST control
    analyze_by_nist_control(results)

    # Check critical controls
    check_critical_controls(results)
