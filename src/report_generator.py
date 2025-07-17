#!/usr/bin/env python3
"""Report generator for compliance check results."""

import csv
import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd
from tabulate import tabulate


class ReportGenerator:
    """Generates CSV and Markdown reports from compliance check results."""

    def __init__(self, results: List[Dict[str, Any]], nist_mappings: Dict[str, Any], nist_171_mappings: Dict[str, Any] = None):
        self.results = results
        self.nist_mappings = nist_mappings
        self.nist_171_mappings = nist_171_mappings
        self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    def generate_csv_report(self, output_dir: str = "./reports") -> str:
        """Generate CSV report with check results and NIST mappings."""
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, f"compliance_results_{self.timestamp}.csv")

        with open(csv_path, "w", newline="") as csvfile:
            fieldnames = [
                "check_id",
                "check_name",
                "status",
                "severity",
                "framework",
                "nist_controls",
                "findings_count",
                "affected_resources",
                "resources_checked",
                "resource_ids_tested",
                "account_id",
                "timestamp",
                "check_description",
                "verification_details",
                "details",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in self.results:
                findings_details = []
                if result["findings"]:
                    for finding in result["findings"]:
                        findings_details.append(
                            f"{finding.get('type', 'Unknown')}: {finding.get('details', '')}"
                        )

                # Get verification details for passed checks
                verification_details = ""
                if result["status"] == "PASS" and "check_details" in result:
                    verification_details = result["check_details"].get("verification_details", "")

                row = {
                    "check_id": result["check_id"],
                    "check_name": result["check_name"],
                    "status": result["status"],
                    "severity": result["severity"],
                    "framework": result["framework"],
                    "nist_controls": ", ".join(result["nist_mappings"]),
                    "findings_count": len(result["findings"]),
                    "affected_resources": ", ".join(result["affected_resources"]),
                    "resources_checked": ", ".join(result.get("resources_checked", [])),
                    "resource_ids_tested": ", ".join(result.get("resource_ids_tested", [])),
                    "account_id": result["account_id"],
                    "timestamp": result["timestamp"],
                    "check_description": result.get(
                        "detailed_description", result.get("description", "")
                    ),
                    "verification_details": verification_details,
                    "details": (
                        " | ".join(findings_details) if findings_details else "No issues found"
                    ),
                }
                writer.writerow(row)

        print(f"CSV report generated: {csv_path}")
        return csv_path

    def generate_markdown_report(self, output_dir: str = "./reports", framework: str = "800-53") -> str:
        """Generate detailed Markdown report organized by NIST control families."""
        os.makedirs(output_dir, exist_ok=True)
        if framework == "800-53":
            md_path = os.path.join(output_dir, f"nist_800-53_compliance_report_{self.timestamp}.md")
        else:
            md_path = os.path.join(output_dir, f"nist_800-171_compliance_report_{self.timestamp}.md")

        try:
            with open(md_path, "w", encoding="utf-8") as f:
                # Write header
                if framework == "800-53":
                    f.write("# NIST 800-53 Compliance Report\n\n")
                else:
                    f.write("# NIST 800-171 Compliance Report\n\n")
                f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(
                    f"**Account ID:** {self.results[0]['account_id'] if self.results else 'Unknown'}\n\n"
                )

                # Write executive summary
                self._write_executive_summary(f, framework)

                # Write detailed findings by control family
                if framework == "800-53":
                    self._write_control_family_details(f)
                else:
                    self._write_nist_171_control_family_details(f)

                # Write detailed passed checks section
                self._write_passed_checks_details(f, framework)

                # Write appendix with all check details
                self._write_appendix(f, framework)

            print(f"Markdown report generated: {md_path}")
            return md_path
        except Exception as e:
            print(f"Error generating Markdown report: {str(e)}")
            raise

    def _write_executive_summary(self, f, framework="800-53"):
        """Write executive summary section."""
        f.write("## Executive Summary\n\n")

        # Calculate statistics
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r["status"] == "PASS")
        failed_checks = sum(1 for r in self.results if r["status"] == "FAIL")
        error_checks = sum(1 for r in self.results if r["status"] == "ERROR")

        # Summary table
        summary_data = [
            ["Total Security Checks", total_checks],
            ["Passed", passed_checks],
            ["Failed", failed_checks],
            ["Errors", error_checks],
            ["Pass Rate", f"{(passed_checks/total_checks)*100:.1f}%" if total_checks > 0 else "0%"],
        ]

        f.write(tabulate(summary_data, headers=["Metric", "Value"], tablefmt="pipe"))
        f.write("\n\n")

        # Security posture summary
        if passed_checks > 0:
            f.write("### Security Posture Summary\n\n")
            f.write(
                f"✅ **{passed_checks} security controls are properly configured** and actively protecting your AWS environment.\n\n"
            )

            # Show top categories of passed checks
            categories = {}
            for result in self.results:
                if result["status"] == "PASS":
                    category = result.get("category", "Other")
                    categories[category] = categories.get(category, 0) + 1

            if categories:
                f.write("**Security Controls by Category:**\n\n")
                category_data = [
                    [cat, count]
                    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)
                ]
                f.write(
                    tabulate(category_data, headers=["Category", "Passed Checks"], tablefmt="pipe")
                )
                f.write("\n\n")

        # Severity breakdown
        f.write("### Findings by Severity\n\n")
        severity_counts = defaultdict(int)
        for result in self.results:
            if result["status"] == "FAIL":
                severity_counts[result["severity"]] += 1

        severity_data = [[sev, count] for sev, count in severity_counts.items()]
        if severity_data:
            f.write(tabulate(severity_data, headers=["Severity", "Count"], tablefmt="pipe"))
        else:
            f.write("No failed checks found.\n")
        f.write("\n\n")

        # Framework coverage
        f.write("### Security Framework Coverage\n\n")
        framework_counts = defaultdict(int)
        for result in self.results:
            framework_counts[result["framework"]] += 1

        framework_data = [[fw, count] for fw, count in framework_counts.items()]
        f.write(tabulate(framework_data, headers=["Framework", "Checks"], tablefmt="pipe"))
        f.write("\n\n")

    def _write_control_family_details(self, f):
        """Write detailed findings organized by NIST control families."""
        f.write("## NIST Control Family Analysis\n\n")

        # Group results by NIST control
        control_results = defaultdict(list)
        for result in self.results:
            for control in result["nist_mappings"]:
                control_results[control].append(result)

        # Process each control family
        for family_id, family_info in self.nist_mappings["control_families"].items():
            f.write(f"### {family_id} - {family_info['name']}\n\n")

            # Process each control in the family
            family_has_results = False
            for control_id, control_info in family_info["controls"].items():
                if control_id in control_results:
                    family_has_results = True
                    f.write(f"#### {control_id}: {control_info['title']}\n\n")

                    # Get all checks for this control
                    checks = control_results[control_id]
                    passed = sum(1 for c in checks if c["status"] == "PASS")
                    failed = sum(1 for c in checks if c["status"] == "FAIL")

                    f.write(
                        f"**Coverage:** {len(checks)} checks ({passed} passed, {failed} failed)\n\n"
                    )

                    # Requirements coverage
                    if "requirements" in control_info:
                        f.write("**Requirements:**\n")
                        for req in control_info["requirements"]:
                            f.write(f"- {req}\n")
                        f.write("\n")

                    # Failed checks details
                    failed_checks = [c for c in checks if c["status"] == "FAIL"]
                    if failed_checks:
                        f.write("**Failed Checks:**\n\n")
                        for check in failed_checks:
                            f.write(f"- **{check['check_name']}** ({check['check_id']})\n")
                            f.write(f"  - Framework: {check['framework']}\n")
                            f.write(f"  - Severity: {check['severity']}\n")
                            if check["findings"]:
                                f.write(f"  - Findings:\n")
                                for finding in check["findings"]:
                                    f.write(
                                        f"    - {finding.get('type', 'Unknown')}: {finding.get('details', '')}\n"
                                    )
                            f.write("\n")

                    # Passed checks details
                    passed_checks = [c for c in checks if c["status"] == "PASS"]
                    if passed_checks:
                        f.write("**Passed Checks:**\n\n")
                        for check in passed_checks:
                            f.write(f"- **{check['check_name']}** ({check['check_id']})\n")
                            f.write(f"  - Framework: {check['framework']}\n")
                            f.write(f"  - Severity: {check['severity']}\n")
                            if "check_details" in check and check["check_details"].get(
                                "verification_details"
                            ):
                                f.write(
                                    f"  - Verification: {check['check_details']['verification_details']}\n"
                                )
                            if check.get("resources_checked"):
                                f.write(
                                    f"  - Resources Tested: {', '.join(check['resources_checked'])}\n"
                                )
                            if check.get("resource_ids_tested"):
                                f.write(
                                    f"  - Resource IDs Tested: {', '.join(check['resource_ids_tested'])}\n"
                                )
                            f.write("\n")

            if not family_has_results:
                f.write("*No security checks mapped to this control family.*\n\n")
    
    def _write_nist_171_control_family_details(self, f):
        """Write detailed findings organized by NIST 800-171 control families."""
        f.write("## NIST 800-171 Control Family Analysis\n\n")
        
        if not self.nist_171_mappings:
            f.write("*NIST 800-171 mappings not available.*\n\n")
            return
        
        # Group results by NIST 800-171 control
        control_results = defaultdict(list)
        for result in self.results:
            check_id = result["check_id"]
            if check_id in self.nist_171_mappings["check_mappings"]:
                for control in self.nist_171_mappings["check_mappings"][check_id]:
                    control_results[control].append(result)
        
        # Process each control family
        for family_id, family_info in sorted(self.nist_171_mappings["control_families"].items()):
            f.write(f"### {family_id} - {family_info['name']}\n\n")
            f.write(f"{family_info['description']}\n\n")
            
            # Find all controls in this family
            family_has_results = False
            for control_id, checks in sorted(control_results.items()):
                if control_id.startswith(family_id + "."):
                    family_has_results = True
                    f.write(f"#### Control {control_id}\n\n")
                    
                    # Get all checks for this control
                    passed = sum(1 for c in checks if c["status"] == "PASS")
                    failed = sum(1 for c in checks if c["status"] == "FAIL")
                    
                    f.write(f"**Coverage:** {len(checks)} checks ({passed} passed, {failed} failed)\n\n")
                    
                    # Failed checks details
                    failed_checks = [c for c in checks if c["status"] == "FAIL"]
                    if failed_checks:
                        f.write("**Failed Checks:**\n\n")
                        for check in failed_checks:
                            f.write(f"- **{check['check_name']}** ({check['check_id']})\n")
                            f.write(f"  - Framework: {check['framework']}\n")
                            f.write(f"  - Severity: {check['severity']}\n")
                            if check["findings"]:
                                f.write(f"  - Findings:\n")
                                for finding in check["findings"]:
                                    f.write(f"    - {finding.get('type', 'Unknown')}: {finding.get('details', '')}\n")
                            f.write("\n")
                    
                    # Passed checks details
                    passed_checks = [c for c in checks if c["status"] == "PASS"]
                    if passed_checks:
                        f.write("**Passed Checks:**\n\n")
                        for check in passed_checks:
                            f.write(f"- **{check['check_name']}** ({check['check_id']})\n")
                            f.write(f"  - Framework: {check['framework']}\n")
                            f.write(f"  - Severity: {check['severity']}\n")
                            if "check_details" in check and check["check_details"].get("verification_details"):
                                f.write(f"  - Verification: {check['check_details']['verification_details']}\n")
                            if check.get("resources_checked"):
                                f.write(f"  - Resources Tested: {', '.join(check['resources_checked'])}\n")
                            f.write("\n")
            
            if not family_has_results:
                f.write("*No security checks mapped to this control family.*\n\n")

    def _write_appendix(self, f, framework="800-53"):
        """Write appendix with all check details."""
        f.write("## Appendix: All Security Checks\n\n")

        # Create detailed table of all checks
        check_data = []
        for result in self.results:
            check_data.append(
                [
                    result["check_id"],
                    result["check_name"],
                    result["status"],
                    result["severity"],
                    result["framework"],
                    ", ".join(result["nist_mappings"]) if framework == "800-53" else ", ".join(self.nist_171_mappings["check_mappings"].get(result["check_id"], [])),
                    len(result["findings"]),
                    (
                        result.get("detailed_description", result.get("description", ""))[:100]
                        + "..."
                        if len(result.get("detailed_description", result.get("description", "")))
                        > 100
                        else result.get("detailed_description", result.get("description", ""))
                    ),
                    (
                        ", ".join(result.get("resources_checked", []))[:50] + "..."
                        if len(", ".join(result.get("resources_checked", []))) > 50
                        else ", ".join(result.get("resources_checked", []))
                    ),
                ]
            )

        headers = [
            "Check ID",
            "Name",
            "Status",
            "Severity",
            "Framework",
            "NIST 800-53 Controls" if framework == "800-53" else "NIST 800-171 Controls",
            "Findings",
            "Description",
            "Resources Tested",
        ]
        f.write(tabulate(check_data, headers=headers, tablefmt="pipe"))
        f.write("\n\n")

        # Detailed findings
        f.write("### Detailed Findings\n\n")
        for result in self.results:
            if result["findings"]:
                f.write(f"#### {result['check_name']} ({result['check_id']})\n\n")
                for finding in result["findings"]:
                    f.write(f"- **Type:** {finding.get('type', 'Unknown')}\n")
                    if "resource" in finding:
                        f.write(f"- **Resource:** {finding['resource']}\n")
                    if "region" in finding:
                        f.write(f"- **Region:** {finding['region']}\n")
                    f.write(f"- **Details:** {finding.get('details', 'No details available')}\n")
                    f.write("\n")

    def _write_passed_checks_details(self, f, framework="800-53"):
        """Write detailed information about all passed checks."""
        f.write("## Passed Security Checks - Detailed Analysis\n\n")
        f.write(
            "This section provides detailed information about security checks that passed, showing how your environment is properly configured to meet security requirements.\n\n"
        )

        passed_checks = [r for r in self.results if r["status"] == "PASS"]

        if not passed_checks:
            f.write("*No security checks passed in this assessment.*\n\n")
            return

        # Group by category
        categories = {}
        for check in passed_checks:
            category = check.get("category", "Other")
            if category not in categories:
                categories[category] = []
            categories[category].append(check)

        for category, checks in categories.items():
            f.write(f"### {category}\n\n")

            for check in checks:
                f.write(f"#### {check['check_name']} ({check['check_id']})\n\n")
                f.write(f"**Framework:** {check['framework']}  \n")
                f.write(f"**Severity:** {check['severity']}  \n")
                if framework == "800-53":
                    f.write(f"**NIST 800-53 Controls:** {', '.join(check['nist_mappings'])}  \n\n")
                else:
                    f.write(f"**NIST 800-171 Controls:** {', '.join(self.nist_171_mappings['check_mappings'].get(check['check_id'], []))}  \n\n")

                # Detailed description
                if "detailed_description" in check:
                    f.write(f"**What This Check Verifies:**\n{check['detailed_description']}\n\n")

                # Verification details
                if "check_details" in check and check["check_details"].get("verification_details"):
                    f.write(
                        f"**Verification Results:**\n{check['check_details']['verification_details']}\n\n"
                    )

                # Resources checked
                if check.get("resources_checked"):
                    f.write(f"**Resources Tested:**\n{', '.join(check['resources_checked'])}\n\n")

                # Resource IDs tested
                if check.get("resource_ids_tested"):
                    f.write(
                        f"**Resource IDs Tested:**\n{', '.join(check['resource_ids_tested'])}\n\n"
                    )

                f.write("---\n\n")

    def generate_summary_json(self, output_dir: str = "./reports") -> str:
        """Generate JSON summary for programmatic processing."""
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, f"compliance_summary_{self.timestamp}.json")

        summary = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "account_id": self.results[0]["account_id"] if self.results else "Unknown",
                "total_checks": len(self.results),
            },
            "statistics": {
                "passed": sum(1 for r in self.results if r["status"] == "PASS"),
                "failed": sum(1 for r in self.results if r["status"] == "FAIL"),
                "error": sum(1 for r in self.results if r["status"] == "ERROR"),
            },
            "control_coverage": {},
            "results": self.results,
        }

        # Calculate control coverage
        control_stats = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})
        for result in self.results:
            for control in result["nist_mappings"]:
                control_stats[control]["total"] += 1
                if result["status"] == "PASS":
                    control_stats[control]["passed"] += 1
                elif result["status"] == "FAIL":
                    control_stats[control]["failed"] += 1

        summary["control_coverage"] = dict(control_stats)

        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        print(f"JSON summary generated: {json_path}")
        return json_path

    def generate_resources_report(self) -> str:
        """Generate a detailed resources report showing all AWS resources tested."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        resources_path = f"./reports/resources_{timestamp}.csv"

        # Collect all resources and their associated checks
        resource_data = {}

        for result in self.results:
            check_id = result["check_id"]
            check_name = result["check_name"]
            status = result["status"]
            timestamp = result["timestamp"]

            # Get resource IDs that were tested
            resource_ids = result.get("resource_ids_tested", [])

            # For failed checks, also include affected resources
            if result["status"] == "FAIL":
                affected_resources = result.get("affected_resources", [])
                resource_ids.extend(affected_resources)

            # Process each resource
            for resource_id in resource_ids:
                if resource_id not in resource_data:
                    resource_data[resource_id] = {
                        "resource_type": self._get_resource_type_from_arn(resource_id),
                        "arn": resource_id,
                        "status": "UNKNOWN",
                        "checks": [],
                        "findings": [],
                        "date_checked": timestamp,
                        "account_id": result["account_id"],
                        "region": result.get("region", "unknown"),
                        "compliance_score": 0,
                        "total_checks": 0,
                        "passed_checks": 0,
                        "failed_checks": 0,
                        "error_checks": 0,
                    }

                # Add check information
                resource_data[resource_id]["checks"].append(f"{check_id}: {check_name}")
                resource_data[resource_id]["total_checks"] += 1

                # Update status and findings
                if status == "PASS":
                    resource_data[resource_id]["passed_checks"] += 1
                    resource_data[resource_id]["findings"].append(
                        f"PASS: {check_name} - {result.get('check_details', {}).get('verification_details', 'Compliant')}"
                    )
                elif status == "FAIL":
                    resource_data[resource_id]["failed_checks"] += 1
                    resource_data[resource_id]["status"] = "NON_COMPLIANT"
                    for finding in result.get("findings", []):
                        if finding.get("resource") == resource_id:
                            resource_data[resource_id]["findings"].append(
                                f"FAIL: {check_name} - {finding.get('details', 'Non-compliant')}"
                            )
                elif status == "ERROR":
                    resource_data[resource_id]["error_checks"] += 1
                    resource_data[resource_id]["findings"].append(
                        f"ERROR: {check_name} - {result.get('findings', [{}])[0].get('error', 'Check failed')}"
                    )

        # Calculate compliance scores and determine overall status
        for resource_id, data in resource_data.items():
            if data["total_checks"] > 0:
                data["compliance_score"] = (data["passed_checks"] / data["total_checks"]) * 100

                # Determine overall status
                if data["failed_checks"] > 0:
                    data["status"] = "NON_COMPLIANT"
                elif data["error_checks"] > 0 and data["passed_checks"] == 0:
                    data["status"] = "ERROR"
                elif data["passed_checks"] > 0:
                    data["status"] = "COMPLIANT"
                else:
                    data["status"] = "UNKNOWN"

        # Write CSV report
        with open(resources_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "resource_type",
                "arn",
                "status",
                "compliance_score",
                "total_checks",
                "passed_checks",
                "failed_checks",
                "error_checks",
                "checks",
                "findings",
                "date_checked",
                "account_id",
                "region",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for resource_id, data in resource_data.items():
                row = {
                    "resource_type": data["resource_type"],
                    "arn": data["arn"],
                    "status": data["status"],
                    "compliance_score": f"{data['compliance_score']:.1f}%",
                    "total_checks": data["total_checks"],
                    "passed_checks": data["passed_checks"],
                    "failed_checks": data["failed_checks"],
                    "error_checks": data["error_checks"],
                    "checks": "; ".join(data["checks"]),
                    "findings": "; ".join(data["findings"]) if data["findings"] else "No findings",
                    "date_checked": data["date_checked"],
                    "account_id": data["account_id"],
                    "region": data["region"],
                }
                writer.writerow(row)

        return resources_path

    def _get_resource_type_from_arn(self, arn: str) -> str:
        """Extract resource type from ARN or resource ID."""
        if not arn or arn == "aws-config":
            return "aws-config"

        # Handle AWS resource IDs (non-ARN format)
        if arn.startswith("vol-"):
            return "EBS Volume"
        elif arn.startswith("sg-"):
            return "Security Group"
        elif arn.startswith("vpc-"):
            return "VPC"
        elif arn.startswith("i-"):
            return "EC2 Instance"
        elif arn.startswith("acl-"):
            return "Network ACL"
        elif arn.startswith("subnet-"):
            return "Subnet"
        elif arn.startswith("igw-"):
            return "Internet Gateway"
        elif arn.startswith("rtb-"):
            return "Route Table"
        elif arn.startswith("eni-"):
            return "Network Interface"
        elif arn.startswith("eipalloc-"):
            return "Elastic IP"
        elif arn.startswith("ami-"):
            return "AMI"
        elif arn.startswith("snap-"):
            return "EBS Snapshot"
        elif arn.startswith("db-"):
            return "RDS Instance"
        elif arn.startswith("subgrp-"):
            return "RDS Subnet Group"
        elif arn.startswith("secgrp-"):
            return "RDS Security Group"
        elif arn.startswith("user-"):
            return "IAM User"
        elif arn.startswith("role-"):
            return "IAM Role"
        elif arn.startswith("policy-"):
            return "IAM Policy"
        elif arn.startswith("group-"):
            return "IAM Group"
        elif arn.startswith("key-"):
            return "KMS Key"
        elif arn.startswith("alias/"):
            return "KMS Alias"
        elif arn.startswith("secret-"):
            return "Secrets Manager Secret"
        elif arn.startswith("table/"):
            return "DynamoDB Table"
        elif arn.startswith("replicationgroup/"):
            return "ElastiCache Cluster"
        elif arn.startswith("loadbalancer/"):
            return "Load Balancer"
        elif arn.startswith("targetgroup/"):
            return "Target Group"
        elif arn.startswith("distribution/"):
            return "CloudFront Distribution"
        elif arn.startswith("function:"):
            return "Lambda Function"
        elif arn.startswith("log-group:"):
            return "CloudWatch Log Group"
        elif arn.startswith("alarm:"):
            return "CloudWatch Alarm"
        elif arn.startswith("topic/"):
            return "SNS Topic"
        elif arn.startswith("queue/"):
            return "SQS Queue"
        elif arn.startswith("stream/"):
            return "Kinesis Stream"
        elif arn.startswith("cluster/"):
            return "ECS Cluster"
        elif arn.startswith("service/"):
            return "ECS Service"
        elif arn.startswith("task-definition/"):
            return "ECS Task Definition"
        elif arn.startswith("repository/"):
            return "ECR Repository"
        elif arn.startswith("workspace/"):
            return "Workspaces Workspace"
        elif arn.startswith("directory/"):
            return "Directory Service"
        elif arn.startswith("certificate/"):
            return "ACM Certificate"
        elif arn.startswith("hostedzone/"):
            return "Route53 Hosted Zone"
        elif arn.startswith("recordset/"):
            return "Route53 Record"
        elif arn.startswith("bucket/"):
            return "S3 Bucket"
        elif arn.startswith("object/"):
            return "S3 Object"
        elif arn.startswith("trail/"):
            return "CloudTrail Trail"
        elif arn.startswith("detector/"):
            return "GuardDuty Detector"
        elif arn.startswith("assessment/"):
            return "Inspector Assessment"
        elif arn.startswith("web-acl/"):
            return "WAF Web ACL"
        elif arn.startswith("rule-group/"):
            return "WAF Rule Group"
        elif arn.startswith("ip-set/"):
            return "WAF IP Set"
        elif arn.startswith("regex-pattern-set/"):
            return "WAF Regex Pattern Set"
        elif arn.startswith("backup-vault/"):
            return "Backup Vault"
        elif arn.startswith("backup-plan/"):
            return "Backup Plan"
        elif arn.startswith("file-system/"):
            return "EFS File System"
        elif arn.startswith("mount-target/"):
            return "EFS Mount Target"
        elif arn.startswith("vpc-endpoint/"):
            return "VPC Endpoint"
        elif arn.startswith("transit-gateway/"):
            return "Transit Gateway"
        elif arn.startswith("vpn-connection/"):
            return "VPN Connection"
        elif arn.startswith("customer-gateway/"):
            return "Customer Gateway"
        elif arn.startswith("vpn-gateway/"):
            return "VPN Gateway"
        elif arn.startswith("nat-gateway/"):
            return "NAT Gateway"
        elif arn.startswith("vpc-peering-connection/"):
            return "VPC Peering Connection"
        elif arn.startswith("network-acl/"):
            return "Network ACL"
        elif arn.startswith("route-table/"):
            return "Route Table"
        elif arn.startswith("subnet/"):
            return "Subnet"
        elif arn.startswith("internet-gateway/"):
            return "Internet Gateway"
        elif arn.startswith("elastic-ip/"):
            return "Elastic IP"
        elif arn.startswith("network-interface/"):
            return "Network Interface"
        elif arn.startswith("instance/"):
            return "EC2 Instance"
        elif arn.startswith("volume/"):
            return "EBS Volume"
        elif arn.startswith("snapshot/"):
            return "EBS Snapshot"
        elif arn.startswith("image/"):
            return "AMI"
        elif arn.startswith("security-group/"):
            return "Security Group"
        elif arn.startswith("vpc/"):
            return "VPC"
        elif arn.startswith("db-instance/"):
            return "RDS Instance"
        elif arn.startswith("db-snapshot/"):
            return "RDS Snapshot"
        elif arn.startswith("db-subnet-group/"):
            return "RDS Subnet Group"
        elif arn.startswith("db-security-group/"):
            return "RDS Security Group"
        elif arn.startswith("user/"):
            return "IAM User"
        elif arn.startswith("role/"):
            return "IAM Role"
        elif arn.startswith("policy/"):
            return "IAM Policy"
        elif arn.startswith("group/"):
            return "IAM Group"
        elif arn.startswith("key/"):
            return "KMS Key"
        elif arn.startswith("secret/"):
            return "Secrets Manager Secret"
        elif arn.startswith("table/"):
            return "DynamoDB Table"
        elif arn.startswith("replicationgroup/"):
            return "ElastiCache Cluster"
        elif arn.startswith("loadbalancer/"):
            return "Load Balancer"
        elif arn.startswith("targetgroup/"):
            return "Target Group"
        elif arn.startswith("distribution/"):
            return "CloudFront Distribution"
        elif arn.startswith("function/"):
            return "Lambda Function"
        elif arn.startswith("log-group/"):
            return "CloudWatch Log Group"
        elif arn.startswith("alarm/"):
            return "CloudWatch Alarm"
        elif arn.startswith("topic/"):
            return "SNS Topic"
        elif arn.startswith("queue/"):
            return "SQS Queue"
        elif arn.startswith("stream/"):
            return "Kinesis Stream"
        elif arn.startswith("cluster/"):
            return "ECS Cluster"
        elif arn.startswith("service/"):
            return "ECS Service"
        elif arn.startswith("task-definition/"):
            return "ECS Task Definition"
        elif arn.startswith("repository/"):
            return "ECR Repository"
        elif arn.startswith("workspace/"):
            return "Workspaces Workspace"
        elif arn.startswith("directory/"):
            return "Directory Service"
        elif arn.startswith("certificate/"):
            return "ACM Certificate"
        elif arn.startswith("hostedzone/"):
            return "Route53 Hosted Zone"
        elif arn.startswith("recordset/"):
            return "Route53 Record"
        elif arn.startswith("bucket/"):
            return "S3 Bucket"
        elif arn.startswith("object/"):
            return "S3 Object"
        elif arn.startswith("trail/"):
            return "CloudTrail Trail"
        elif arn.startswith("detector/"):
            return "GuardDuty Detector"
        elif arn.startswith("assessment/"):
            return "Inspector Assessment"
        elif arn.startswith("web-acl/"):
            return "WAF Web ACL"
        elif arn.startswith("rule-group/"):
            return "WAF Rule Group"
        elif arn.startswith("ip-set/"):
            return "WAF IP Set"
        elif arn.startswith("regex-pattern-set/"):
            return "WAF Regex Pattern Set"
        elif arn.startswith("backup-vault/"):
            return "Backup Vault"
        elif arn.startswith("backup-plan/"):
            return "Backup Plan"
        elif arn.startswith("file-system/"):
            return "EFS File System"
        elif arn.startswith("mount-target/"):
            return "EFS Mount Target"
        elif arn.startswith("vpc-endpoint/"):
            return "VPC Endpoint"
        elif arn.startswith("transit-gateway/"):
            return "Transit Gateway"
        elif arn.startswith("vpn-connection/"):
            return "VPN Connection"
        elif arn.startswith("customer-gateway/"):
            return "Customer Gateway"
        elif arn.startswith("vpn-gateway/"):
            return "VPN Gateway"
        elif arn.startswith("nat-gateway/"):
            return "NAT Gateway"
        elif arn.startswith("vpc-peering-connection/"):
            return "VPC Peering Connection"

        # Handle different ARN formats
        if arn.startswith("arn:aws:"):
            parts = arn.split(":")
            if len(parts) >= 6:
                service = parts[2]
                resource_part = parts[5]

                # Map service to resource type
                service_mapping = {
                    "s3": "S3 Bucket",
                    "ec2": "EC2 Resource",
                    "iam": "IAM Resource",
                    "rds": "RDS Instance",
                    "cloudtrail": "CloudTrail Trail",
                    "guardduty": "GuardDuty Detector",
                    "inspector2": "Inspector Account",
                    "securityhub": "Security Hub",
                    "kms": "KMS Key",
                    "secretsmanager": "Secrets Manager Secret",
                    "efs": "EFS File System",
                    "dynamodb": "DynamoDB Table",
                    "elasticache": "ElastiCache Cluster",
                    "logs": "CloudWatch Log Group",
                    "lambda": "Lambda Function",
                    "api-gateway": "API Gateway",
                    "backup": "Backup Plan",
                    "cloudfront": "CloudFront Distribution",
                    "waf": "WAF Web ACL",
                    "sns": "SNS Topic",
                    "elasticloadbalancing": "ELASTICLOADBALANCING Resource",
                }

                # Extract specific resource type from resource part
                if service == "ec2":
                    if resource_part.startswith("volume/"):
                        return "EBS Volume"
                    elif resource_part.startswith("instance/"):
                        return "EC2 Instance"
                    elif resource_part.startswith("security-group/"):
                        return "Security Group"
                    elif resource_part.startswith("vpc/"):
                        return "VPC"
                    elif resource_part.startswith("vpc-endpoint/"):
                        return "VPC Endpoint"
                    elif resource_part.startswith("network-acl/"):
                        return "Network ACL"
                    else:
                        return "EC2 Resource"
                elif service == "iam":
                    if resource_part.startswith("user/"):
                        return "IAM User"
                    elif resource_part.startswith("role/"):
                        return "IAM Role"
                    elif resource_part.startswith("policy/"):
                        return "IAM Policy"
                    else:
                        return "IAM Resource"
                elif service == "rds":
                    if "/db:" in resource_part:
                        return "RDS Instance"
                    else:
                        return "RDS Resource"
                else:
                    return service_mapping.get(service, f"{service.upper()} Resource")

        # Handle non-ARN resources
        if arn == "root-account":
            return "Root Account"
        elif arn == "iam-password-policy":
            return "IAM Password Policy"
        elif arn == "cloudtrail":
            return "CloudTrail"
        elif arn == "security-hub":
            return "Security Hub"
        elif arn == "cloudwatch-anomaly-detectors":
            return "CloudWatch Anomaly Detector"
        elif arn == "sns-topics":
            return "SNS Topic"
        elif arn == "secrets-manager-secrets":
            return "Secrets Manager Secret"
        elif arn == "backup-plans":
            return "Backup Plan"
        elif arn == "cloudwatch-log-groups":
            return "CloudWatch Log Group"
        elif arn == "api-gateway-rest-apis":
            return "API Gateway"
        elif arn == "lambda-functions":
            return "Lambda Function"
        elif arn == "cloudtrail-trails":
            return "CloudTrail Trail"
        elif arn == "s3-buckets":
            return "S3 Bucket"
        elif arn == "ebs-volumes":
            return "EBS Volume"
        elif arn == "security-groups":
            return "Security Group"
        elif arn == "rds-instances":
            return "RDS Instance"
        elif arn == "guardduty-detectors":
            return "GuardDuty Detector"
        elif arn == "inspector-account-status":
            return "Inspector Account"
        elif arn == "cloudwatch-alarms":
            return "CloudWatch Alarm"
        elif arn == "kms-keys":
            return "KMS Key"
        elif arn == "vpc-endpoints":
            return "VPC Endpoint"
        elif arn == "efs-file-systems":
            return "EFS File System"
        elif arn == "dynamodb-tables":
            return "DynamoDB Table"
        elif arn == "elasticache-clusters":
            return "ElastiCache Cluster"
        elif arn == "network-acls":
            return "Network ACL"
        elif arn == "waf-web-acls":
            return "WAF Web ACL"
        elif arn == "cloudfront-distributions":
            return "CloudFront Distribution"
        elif arn == "iam-roles":
            return "IAM Role"
        elif arn == "automated-backups":
            return "RDS Automated Backup"
        elif arn == "retention-policies":
            return "CloudWatch Log Retention"
        elif arn == "access-logs":
            return "Access Logs"
        elif arn == "cloudwatch-logs":
            return "CloudWatch Logs"
        elif arn == "kms-encryption":
            return "KMS Encryption"
        elif arn == "access-logging":
            return "S3 Access Logging"
        elif arn == "cloudwatch-metrics":
            return "CloudWatch Metrics"
        elif arn == "cloudwatch-anomaly-detection":
            return "CloudWatch Anomaly Detection"
        elif arn.startswith("guardduty-"):
            return "GuardDuty Detector"
        elif arn.startswith("inspector-"):
            return "Inspector Assessment"
        elif arn == "securityhub":
            return "Security Hub"
        elif arn == "secretsmanager":
            return "Secrets Manager"
        elif arn.startswith("backup-"):
            return "Backup Plan"
        elif arn == "cloudwatch-alarms":
            return "CloudWatch Alarm"
        elif arn == "sns-topics":
            return "SNS Topic"
        else:
            return "Unknown Resource"

    def generate_reports(self, formats: List[str], frameworks: List[str] = ["800-53"]) -> List[str]:
        """Generate compliance reports in the specified formats."""
        generated_reports = []

        if "csv" in formats or "all" in formats:
            csv_path = self.generate_csv_report()
            generated_reports.append(csv_path)

        if "markdown" in formats or "all" in formats:
            for framework in frameworks:
                if framework == "800-53":
                    markdown_path = self.generate_markdown_report(framework="800-53")
                    generated_reports.append(markdown_path)
                elif framework == "800-171" and self.nist_171_mappings:
                    markdown_path = self.generate_markdown_report(framework="800-171")
                    generated_reports.append(markdown_path)

        if "json" in formats or "all" in formats:
            json_path = self.generate_summary_json()
            generated_reports.append(json_path)

        if "resources" in formats or "all" in formats:
            resources_path = self.generate_resources_report()
            generated_reports.append(resources_path)

        return generated_reports
