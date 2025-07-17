#!/usr/bin/env python3
"""Multi-framework report generator for compliance results."""

import csv
import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import pandas as pd
from tabulate import tabulate

from enhanced_report_generator import EnhancedReportGenerator


class MultiFrameworkReporter:
    """Generates reports supporting multiple compliance frameworks."""
    
    def __init__(
        self,
        results: List[Dict[str, Any]],
        framework_mappings: Dict[str, Any],
        nist_800_53_mappings: Dict[str, Any],
        nist_800_171_mappings: Dict[str, Any]
    ):
        """Initialize multi-framework reporter.
        
        Args:
            results: Check execution results
            framework_mappings: Multi-framework mapping data
            nist_800_53_mappings: NIST 800-53 control definitions
            nist_800_171_mappings: NIST 800-171 control definitions
        """
        self.results = results
        self.framework_mappings = framework_mappings
        self.nist_800_53_mappings = nist_800_53_mappings
        self.nist_800_171_mappings = nist_800_171_mappings
        self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Initialize enhanced report generator for detailed reports
        self.enhanced_reporter = EnhancedReportGenerator(
            results=results,
            framework_mappings=framework_mappings,
            nist_800_53_mappings=nist_800_53_mappings,
            nist_800_171_mappings=nist_800_171_mappings
        )
        
    def generate_all_reports(self, output_dir: str = "./reports") -> Dict[str, str]:
        """Generate all report types.
        
        Args:
            output_dir: Output directory for reports
            
        Returns:
            Dictionary of report types to file paths
        """
        os.makedirs(output_dir, exist_ok=True)
        
        report_paths = {}
        
        # Generate detailed framework-specific reports using enhanced reporter
        report_paths["nist_800_53_detailed"] = self.enhanced_reporter.generate_detailed_nist_800_53_report(output_dir)
        report_paths["nist_800_171_detailed"] = self.enhanced_reporter.generate_detailed_nist_800_171_report(output_dir)
        
        # Also generate the original reports for backwards compatibility
        report_paths["nist_800_53"] = self.generate_nist_800_53_report(output_dir)
        report_paths["nist_800_171"] = self.generate_nist_800_171_report(output_dir)
        
        # Generate cross-framework matrix
        report_paths["cross_framework"] = self.generate_cross_framework_matrix(output_dir)
        
        # Generate enhanced CSV with all frameworks
        report_paths["enhanced_csv"] = self.generate_enhanced_csv_report(output_dir)
        
        # Generate evidence packages
        report_paths["evidence_summary"] = self.generate_evidence_summary(output_dir)
        
        # Generate resource-level report
        report_paths["resources"] = self.generate_resources_report(output_dir)
        
        return report_paths
    
    def generate_nist_800_53_report(self, output_dir: str) -> str:
        """Generate NIST 800-53 specific report."""
        file_path = os.path.join(output_dir, f"nist_800_53_report_{self.timestamp}.md")
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# NIST 800-53 Compliance Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Framework Version:** Rev 5\n\n")
            
            # Group results by NIST 800-53 controls
            control_results = self._group_by_framework_controls("nist_800_53")
            
            # Generate executive summary
            f.write("## Executive Summary\n\n")
            summary = self._generate_framework_summary(control_results, "nist_800_53")
            f.write(summary)
            
            # Generate detailed findings by control family
            f.write("\n## Detailed Findings by Control Family\n\n")
            
            for family_id, family_data in self.nist_800_53_mappings.get("control_families", {}).items():
                f.write(f"### {family_id} - {family_data['name']}\n\n")
                
                # Check each control in the family
                for control_id, control_data in family_data.get("controls", {}).items():
                    if control_id in control_results:
                        f.write(f"#### {control_id}: {control_data['title']}\n\n")
                        
                        # List all checks that map to this control
                        for check_result in control_results[control_id]:
                            status_emoji = "✅" if check_result["status"] == "PASS" else "❌"
                            f.write(f"- {status_emoji} **{check_result['check_name']}** ({check_result['check_id']})\n")
                            
                            if check_result["status"] == "FAIL":
                                f.write(f"  - Severity: {check_result.get('severity', 'Unknown')}\n")
                                f.write(f"  - Findings: {len(check_result.get('findings', []))}\n")
                                f.write(f"  - Affected Resources: {', '.join(check_result.get('affected_resources', []))}\n")
                        
                        f.write("\n")
        
        print(f"NIST 800-53 report generated: {file_path}")
        return file_path
    
    def generate_nist_800_171_report(self, output_dir: str) -> str:
        """Generate NIST 800-171 specific report."""
        file_path = os.path.join(output_dir, f"nist_800_171_report_{self.timestamp}.md")
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# NIST 800-171 Compliance Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Framework Version:** Rev 2\n")
            f.write("**Purpose:** Protecting Controlled Unclassified Information (CUI)\n\n")
            
            # Group results by NIST 800-171 controls
            control_results = self._group_by_framework_controls("nist_800_171")
            
            # Generate executive summary
            f.write("## Executive Summary\n\n")
            summary = self._generate_framework_summary(control_results, "nist_800_171")
            f.write(summary)
            
            # Generate detailed findings by control family
            f.write("\n## Detailed Findings by Control Family\n\n")
            
            for family_id, family_data in self.nist_800_171_mappings.get("control_families", {}).items():
                f.write(f"### {family_id} - {family_data['name']}\n\n")
                
                # Check each control in the family
                for control_id, control_data in family_data.get("controls", {}).items():
                    if control_id in control_results:
                        f.write(f"#### {control_id}: {control_data['title']}\n")
                        f.write(f"*{control_data['description']}*\n\n")
                        
                        # List all checks that map to this control
                        for check_result in control_results[control_id]:
                            status_emoji = "✅" if check_result["status"] == "PASS" else "❌"
                            f.write(f"- {status_emoji} **{check_result['check_name']}** ({check_result['check_id']})\n")
                            
                            if check_result["status"] == "PASS":
                                f.write(f"  - Evidence: Check passed, control requirement satisfied\n")
                            else:
                                f.write(f"  - Severity: {check_result.get('severity', 'Unknown')}\n")
                                f.write(f"  - Findings: {len(check_result.get('findings', []))}\n")
                        
                        f.write("\n")
        
        print(f"NIST 800-171 report generated: {file_path}")
        return file_path
    
    def generate_cross_framework_matrix(self, output_dir: str) -> str:
        """Generate cross-framework compliance matrix."""
        file_path = os.path.join(output_dir, f"cross_framework_matrix_{self.timestamp}.csv")
        
        # Get all available frameworks
        frameworks = list(self.framework_mappings["frameworks"].keys())
        
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            # Define fields
            fieldnames = ["check_id", "check_name", "status", "severity"] + frameworks
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Process each result
            for result in self.results:
                check_id = result["check_id"]
                
                # Get mappings for this check
                check_mappings = self.framework_mappings["check_mappings"].get(
                    check_id, {}
                ).get("frameworks", {})
                
                row = {
                    "check_id": check_id,
                    "check_name": result["check_name"],
                    "status": result["status"],
                    "severity": result.get("severity", "Unknown")
                }
                
                # Add framework mappings
                for framework in frameworks:
                    controls = check_mappings.get(framework, [])
                    row[framework] = ", ".join(controls) if controls else "N/A"
                
                writer.writerow(row)
        
        print(f"Cross-framework matrix generated: {file_path}")
        return file_path
    
    def generate_enhanced_csv_report(self, output_dir: str) -> str:
        """Generate enhanced CSV with multi-framework support."""
        file_path = os.path.join(output_dir, f"compliance_results_enhanced_{self.timestamp}.csv")
        
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "check_id",
                "check_name",
                "status",
                "severity",
                "framework_source",
                "nist_800_53_controls",
                "nist_800_171_controls",
                "cis_aws_controls",
                "mitre_attack_techniques",
                "findings_count",
                "affected_resources",
                "account_id",
                "regions_checked",
                "timestamp",
                "remediation_effort",
                "business_impact"
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                check_id = result["check_id"]
                check_mappings = self.framework_mappings["check_mappings"].get(
                    check_id, {}
                ).get("frameworks", {})
                
                # Estimate remediation effort based on severity
                effort_map = {
                    "CRITICAL": "High",
                    "HIGH": "Medium-High",
                    "MEDIUM": "Medium",
                    "LOW": "Low"
                }
                
                row = {
                    "check_id": check_id,
                    "check_name": result["check_name"],
                    "status": result["status"],
                    "severity": result.get("severity", "Unknown"),
                    "framework_source": result.get("framework", "Multiple"),
                    "nist_800_53_controls": ", ".join(check_mappings.get("nist_800_53", [])),
                    "nist_800_171_controls": ", ".join(check_mappings.get("nist_800_171", [])),
                    "cis_aws_controls": ", ".join(check_mappings.get("cis_aws", [])),
                    "mitre_attack_techniques": ", ".join(check_mappings.get("mitre_attack", [])),
                    "findings_count": len(result.get("findings", [])),
                    "affected_resources": ", ".join(result.get("affected_resources", [])),
                    "account_id": result.get("account_id", "Unknown"),
                    "regions_checked": ", ".join(result.get("regions_checked", [result.get("region", "Unknown")])),
                    "timestamp": result.get("timestamp", ""),
                    "remediation_effort": effort_map.get(result.get("severity", ""), "Unknown"),
                    "business_impact": self._assess_business_impact(result)
                }
                
                writer.writerow(row)
        
        print(f"Enhanced CSV report generated: {file_path}")
        return file_path
    
    def generate_evidence_summary(self, output_dir: str) -> str:
        """Generate evidence summary for audit purposes."""
        file_path = os.path.join(output_dir, f"evidence_summary_{self.timestamp}.json")
        
        evidence = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_checks": len(self.results),
                "frameworks_covered": list(self.framework_mappings["frameworks"].keys())
            },
            "compliance_summary": {},
            "evidence_packages": {}
        }
        
        # Generate compliance summary for each framework
        for framework_id in self.framework_mappings["frameworks"]:
            control_results = self._group_by_framework_controls(framework_id)
            
            total_controls = len(control_results)
            passed_controls = sum(
                1 for controls in control_results.values()
                if all(r["status"] == "PASS" for r in controls)
            )
            
            evidence["compliance_summary"][framework_id] = {
                "controls_tested": total_controls,
                "controls_passed": passed_controls,
                "compliance_percentage": (passed_controls / total_controls * 100) if total_controls > 0 else 0
            }
        
        # Generate evidence packages for critical controls
        critical_controls = ["AC-2", "IA-2", "SC-28", "AU-2"]  # Example critical controls
        
        for control_id in critical_controls:
            evidence["evidence_packages"][control_id] = self._generate_evidence_package(
                control_id, "nist_800_53"
            )
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        
        print(f"Evidence summary generated: {file_path}")
        return file_path
    
    def _group_by_framework_controls(self, framework_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """Group results by framework controls."""
        control_results = defaultdict(list)
        
        for result in self.results:
            check_id = result["check_id"]
            check_mappings = self.framework_mappings["check_mappings"].get(
                check_id, {}
            ).get("frameworks", {})
            
            controls = check_mappings.get(framework_id, [])
            for control in controls:
                control_results[control].append(result)
        
        return dict(control_results)
    
    def _generate_framework_summary(
        self,
        control_results: Dict[str, List[Dict[str, Any]]],
        framework_id: str
    ) -> str:
        """Generate summary statistics for a framework."""
        total_controls = len(control_results)
        passed_controls = 0
        failed_controls = 0
        total_findings = 0
        
        for control_id, results in control_results.items():
            # Control passes if all related checks pass
            if all(r["status"] == "PASS" for r in results):
                passed_controls += 1
            else:
                failed_controls += 1
                total_findings += sum(len(r.get("findings", [])) for r in results)
        
        compliance_percentage = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        summary = f"""
- **Total Controls Evaluated:** {total_controls}
- **Controls Passed:** {passed_controls}
- **Controls Failed:** {failed_controls}
- **Overall Compliance:** {compliance_percentage:.1f}%
- **Total Findings:** {total_findings}
"""
        
        return summary
    
    def _assess_business_impact(self, result: Dict[str, Any]) -> str:
        """Assess business impact of a finding."""
        severity = result.get("severity", "Unknown")
        check_id = result["check_id"]
        
        # High impact checks
        high_impact_checks = ["CHECK-001", "CHECK-002", "CHECK-005", "CHECK-006"]
        
        if check_id in high_impact_checks and result["status"] == "FAIL":
            return "High"
        elif severity == "CRITICAL":
            return "High"
        elif severity == "HIGH":
            return "Medium-High"
        elif severity == "MEDIUM":
            return "Medium"
        else:
            return "Low"
    
    def _generate_evidence_package(self, control_id: str, framework_id: str) -> Dict[str, Any]:
        """Generate evidence package for a specific control."""
        package = {
            "control_id": control_id,
            "framework": framework_id,
            "checks_performed": [],
            "overall_status": "PASS",
            "evidence_items": []
        }
        
        # Find all checks related to this control
        for result in self.results:
            check_id = result["check_id"]
            check_mappings = self.framework_mappings["check_mappings"].get(
                check_id, {}
            ).get("frameworks", {})
            
            if control_id in check_mappings.get(framework_id, []):
                package["checks_performed"].append({
                    "check_id": check_id,
                    "check_name": result["check_name"],
                    "status": result["status"],
                    "timestamp": result.get("timestamp", "")
                })
                
                if result["status"] == "FAIL":
                    package["overall_status"] = "FAIL"
                
                # Add evidence items
                package["evidence_items"].append({
                    "type": "automated_check",
                    "source": check_id,
                    "result": result["status"],
                    "details": f"{len(result.get('findings', []))} findings" if result["status"] == "FAIL" else "No issues found"
                })
        
        return package
    
    def generate_resources_report(self, output_dir: str) -> str:
        """Generate a detailed resources report showing all AWS resources tested."""
        file_path = os.path.join(output_dir, f"resources_{self.timestamp}.csv")
        
        # Collect all resources and their associated checks
        resource_data = {}
        
        for result in self.results:
            check_id = result["check_id"]
            check_name = result["check_name"]
            status = result["status"]
            timestamp = result.get("timestamp", self.timestamp)
            account_id = result.get("account_id", "Unknown")
            
            # Get all resources from findings
            resources_to_process = []
            
            # Add resources from findings
            for finding in result.get("findings", []):
                resource_id = finding.get("resource_id") or finding.get("resource") or finding.get("id")
                if resource_id:
                    resources_to_process.append({
                        "id": resource_id,
                        "type": finding.get("resource_type") or finding.get("type", "Unknown"),
                        "region": finding.get("region", "Unknown"),
                        "details": finding.get("details", "")
                    })
            
            # Also add affected_resources if no findings
            if not resources_to_process and result.get("affected_resources"):
                for resource in result["affected_resources"]:
                    resources_to_process.append({
                        "id": resource,
                        "type": self._get_resource_type_from_id(resource),
                        "region": result.get("region", "Unknown"),
                        "details": ""
                    })
            
            # Process each resource
            for resource_info in resources_to_process:
                resource_id = resource_info["id"]
                
                if resource_id not in resource_data:
                    resource_data[resource_id] = {
                        "resource_type": resource_info["type"],
                        "resource_id": resource_id,
                        "region": resource_info["region"],
                        "account_id": account_id,
                        "status": "UNKNOWN",
                        "checks_performed": [],
                        "findings": [],
                        "compliance_score": 0.0,
                        "total_checks": 0,
                        "passed_checks": 0,
                        "failed_checks": 0,
                        "error_checks": 0,
                        "frameworks_covered": set(),
                        "last_checked": timestamp
                    }
                
                # Update resource data
                resource_data[resource_id]["checks_performed"].append(f"{check_id}: {check_name}")
                resource_data[resource_id]["total_checks"] += 1
                
                # Add frameworks
                check_mappings = self.framework_mappings["check_mappings"].get(check_id, {}).get("frameworks", {})
                for framework in check_mappings:
                    resource_data[resource_id]["frameworks_covered"].add(framework)
                
                # Update status counts
                if status == "PASS":
                    resource_data[resource_id]["passed_checks"] += 1
                    if resource_info["details"]:
                        resource_data[resource_id]["findings"].append(f"PASS: {check_name} - {resource_info['details']}")
                elif status == "FAIL":
                    resource_data[resource_id]["failed_checks"] += 1
                    resource_data[resource_id]["findings"].append(f"FAIL: {check_name} - {resource_info['details']}")
                elif status == "ERROR":
                    resource_data[resource_id]["error_checks"] += 1
                    resource_data[resource_id]["findings"].append(f"ERROR: {check_name} - Check failed")
        
        # Calculate compliance scores and determine status
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
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "resource_type",
                "resource_id",
                "region",
                "account_id",
                "status",
                "compliance_score",
                "total_checks",
                "passed_checks",
                "failed_checks",
                "error_checks",
                "frameworks_covered",
                "checks_performed",
                "findings",
                "last_checked"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for resource_id, data in sorted(resource_data.items()):
                row = {
                    "resource_type": data["resource_type"],
                    "resource_id": data["resource_id"],
                    "region": data["region"],
                    "account_id": data["account_id"],
                    "status": data["status"],
                    "compliance_score": f"{data['compliance_score']:.1f}%",
                    "total_checks": data["total_checks"],
                    "passed_checks": data["passed_checks"],
                    "failed_checks": data["failed_checks"],
                    "error_checks": data["error_checks"],
                    "frameworks_covered": ", ".join(sorted(data["frameworks_covered"])),
                    "checks_performed": "; ".join(data["checks_performed"]),
                    "findings": "; ".join(data["findings"]) if data["findings"] else "No specific findings",
                    "last_checked": data["last_checked"]
                }
                writer.writerow(row)
        
        print(f"Resources report generated: {file_path}")
        return file_path
    
    def _get_resource_type_from_id(self, resource_id: str) -> str:
        """Extract resource type from resource ID or ARN."""
        if not resource_id:
            return "Unknown"
        
        # Handle ARNs
        if resource_id.startswith("arn:aws:"):
            parts = resource_id.split(":")
            if len(parts) >= 6:
                service = parts[2]
                resource_part = parts[5]
                
                # Map service to resource type
                service_map = {
                    "s3": "S3 Bucket",
                    "ec2": "EC2 Resource",
                    "iam": "IAM Resource",
                    "rds": "RDS Instance",
                    "cloudtrail": "CloudTrail Trail",
                    "kms": "KMS Key",
                    "lambda": "Lambda Function",
                    "logs": "CloudWatch Logs",
                    "dynamodb": "DynamoDB Table",
                    "ecs": "ECS Resource",
                    "eks": "EKS Resource",
                    "elasticache": "ElastiCache Resource",
                    "sns": "SNS Topic",
                    "sqs": "SQS Queue"
                }
                
                # Get specific type from resource part
                if "/" in resource_part:
                    resource_type = resource_part.split("/")[0]
                    if resource_type == "volume":
                        return "EBS Volume"
                    elif resource_type == "instance":
                        return "EC2 Instance"
                    elif resource_type == "security-group":
                        return "Security Group"
                    elif resource_type == "user":
                        return "IAM User"
                    elif resource_type == "role":
                        return "IAM Role"
                    elif resource_type == "function":
                        return "Lambda Function"
                    elif resource_type == "table":
                        return "DynamoDB Table"
                
                return service_map.get(service, f"{service.upper()} Resource")
        
        # Handle resource IDs
        if resource_id.startswith("i-"):
            return "EC2 Instance"
        elif resource_id.startswith("vol-"):
            return "EBS Volume"
        elif resource_id.startswith("sg-"):
            return "Security Group"
        elif resource_id.startswith("vpc-"):
            return "VPC"
        elif resource_id.startswith("subnet-"):
            return "Subnet"
        elif resource_id.startswith("igw-"):
            return "Internet Gateway"
        elif resource_id.startswith("rtb-"):
            return "Route Table"
        elif resource_id.startswith("acl-"):
            return "Network ACL"
        elif resource_id.startswith("eni-"):
            return "Network Interface"
        elif resource_id.startswith("db-"):
            return "RDS Instance"
        elif resource_id == "root-account":
            return "Root Account"
        elif resource_id == "iam-password-policy":
            return "IAM Password Policy"
        elif "/" in resource_id:
            # Handle paths like buckets/my-bucket
            parts = resource_id.split("/")
            if parts[0] == "buckets":
                return "S3 Bucket"
            elif parts[0] == "trails":
                return "CloudTrail Trail"
        
        # Region names (from CloudTrail check)
        if resource_id.startswith("us-") or resource_id.startswith("eu-") or resource_id.startswith("ap-"):
            return "AWS Region"
        
        return "AWS Resource"