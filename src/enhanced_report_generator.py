#!/usr/bin/env python3
"""Enhanced report generator with detailed findings."""

import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List


class EnhancedReportGenerator:
    """Generates detailed compliance reports."""
    
    def __init__(
        self,
        results: List[Dict[str, Any]],
        framework_mappings: Dict[str, Any],
        nist_800_53_mappings: Dict[str, Any],
        nist_800_171_mappings: Dict[str, Any]
    ):
        """Initialize enhanced report generator."""
        self.results = results
        self.framework_mappings = framework_mappings
        self.nist_800_53_mappings = nist_800_53_mappings
        self.nist_800_171_mappings = nist_800_171_mappings
        self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
    def generate_detailed_nist_800_53_report(self, output_dir: str) -> str:
        """Generate detailed NIST 800-53 report."""
        file_path = os.path.join(output_dir, f"nist_800_53_detailed_report_{self.timestamp}.md")
        
        with open(file_path, "w", encoding="utf-8") as f:
            # Header
            f.write("# NIST 800-53 Rev 5 Detailed Compliance Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Account ID:** {self.results[0].get('account_id', 'Unknown') if self.results else 'Unknown'}\n")
            f.write(f"**Total Checks Executed:** {len(self.results)}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            self._write_executive_summary(f, "nist_800_53")
            
            # Summary by Severity
            f.write("\n## Findings by Severity\n\n")
            self._write_severity_summary(f)
            
            # Detailed Findings by Control Family
            f.write("\n## Detailed Findings by Control Family\n\n")
            self._write_detailed_findings_by_family(f, "nist_800_53")
            
            # Failed Checks Detail
            f.write("\n## Failed Checks - Detailed Analysis\n\n")
            self._write_failed_checks_detail(f)
            
            # Remediation Recommendations
            f.write("\n## Remediation Recommendations\n\n")
            self._write_remediation_recommendations(f)
            
            # Appendix: All Checks
            f.write("\n## Appendix: All Security Checks\n\n")
            self._write_all_checks_summary(f, "nist_800_53")
            
        print(f"Enhanced NIST 800-53 report generated: {file_path}")
        return file_path
    
    def generate_detailed_nist_800_171_report(self, output_dir: str) -> str:
        """Generate detailed NIST 800-171 report."""
        file_path = os.path.join(output_dir, f"nist_800_171_detailed_report_{self.timestamp}.md")
        
        with open(file_path, "w", encoding="utf-8") as f:
            # Header
            f.write("# NIST 800-171 Rev 2 Detailed Compliance Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Purpose:** Assessment of Controlled Unclassified Information (CUI) Protection\n")
            f.write(f"**Account ID:** {self.results[0].get('account_id', 'Unknown') if self.results else 'Unknown'}\n")
            f.write(f"**Total Checks Executed:** {len(self.results)}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            self._write_executive_summary(f, "nist_800_171")
            
            # CUI Protection Assessment
            f.write("\n## CUI Protection Assessment\n\n")
            self._write_cui_assessment(f)
            
            # Detailed Findings by Requirement Family
            f.write("\n## Detailed Findings by Requirement Family\n\n")
            self._write_detailed_findings_by_family(f, "nist_800_171")
            
            # Gap Analysis
            f.write("\n## Gap Analysis\n\n")
            self._write_gap_analysis(f, "nist_800_171")
            
            # Implementation Priorities
            f.write("\n## Implementation Priorities\n\n")
            self._write_implementation_priorities(f)
            
            # Detailed Evidence
            f.write("\n## Detailed Evidence by Requirement\n\n")
            self._write_detailed_evidence(f, "nist_800_171")
            
        print(f"Enhanced NIST 800-171 report generated: {file_path}")
        return file_path
    
    def _write_executive_summary(self, f, framework: str):
        """Write executive summary section."""
        # Group results by control
        control_results = self._group_by_framework_controls(framework)
        
        total_controls = len(control_results)
        passed_controls = sum(1 for controls in control_results.values() 
                            if all(r["status"] == "PASS" for r in controls))
        failed_controls = total_controls - passed_controls
        
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r["status"] == "PASS")
        failed_checks = sum(1 for r in self.results if r["status"] == "FAIL")
        error_checks = sum(1 for r in self.results if r["status"] == "ERROR")
        
        total_findings = sum(len(r.get("findings", [])) for r in self.results)
        critical_findings = sum(len(r.get("findings", [])) for r in self.results 
                              if r.get("severity") == "CRITICAL")
        high_findings = sum(len(r.get("findings", [])) for r in self.results 
                          if r.get("severity") == "HIGH")
        
        f.write(f"### Compliance Overview\n\n")
        f.write(f"- **Framework Compliance:** {(passed_controls/total_controls*100) if total_controls > 0 else 0:.1f}%\n")
        f.write(f"- **Controls Evaluated:** {total_controls}\n")
        f.write(f"- **Controls Passed:** {passed_controls}\n")
        f.write(f"- **Controls Failed:** {failed_controls}\n\n")
        
        f.write(f"### Check Execution Summary\n\n")
        f.write(f"- **Total Checks:** {total_checks}\n")
        if total_checks > 0:
            f.write(f"- **Passed:** {passed_checks} ({passed_checks/total_checks*100:.1f}%)\n")
            f.write(f"- **Failed:** {failed_checks} ({failed_checks/total_checks*100:.1f}%)\n")
            f.write(f"- **Errors:** {error_checks} ({error_checks/total_checks*100:.1f}%)\n\n")
        else:
            f.write(f"- **Passed:** {passed_checks} (0.0%)\n")
            f.write(f"- **Failed:** {failed_checks} (0.0%)\n")
            f.write(f"- **Errors:** {error_checks} (0.0%)\n\n")
        
        f.write(f"### Finding Summary\n\n")
        f.write(f"- **Total Findings:** {total_findings}\n")
        f.write(f"- **Critical:** {critical_findings}\n")
        f.write(f"- **High:** {high_findings}\n")
        f.write(f"- **Medium:** {sum(len(r.get('findings', [])) for r in self.results if r.get('severity') == 'MEDIUM')}\n")
        f.write(f"- **Low:** {sum(len(r.get('findings', [])) for r in self.results if r.get('severity') == 'LOW')}\n")
    
    def _write_severity_summary(self, f):
        """Write findings grouped by severity."""
        severity_groups = defaultdict(list)
        
        for result in self.results:
            if result["status"] == "FAIL":
                severity = result.get("severity", "Unknown")
                severity_groups[severity].append(result)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in severity_groups:
                f.write(f"### {severity} Severity Findings\n\n")
                
                for result in severity_groups[severity]:
                    f.write(f"**{result['check_name']}** ({result['check_id']})\n")
                    f.write(f"- Findings: {len(result.get('findings', []))}\n")
                    f.write(f"- Affected Resources: {len(result.get('affected_resources', []))}\n")
                    
                    # Show first few findings
                    for finding in result.get('findings', [])[:3]:
                        f.write(f"  - {finding.get('details', 'No details')}\n")
                    
                    if len(result.get('findings', [])) > 3:
                        f.write(f"  - ... and {len(result.get('findings', [])) - 3} more\n")
                    
                    f.write("\n")
    
    def _write_detailed_findings_by_family(self, f, framework: str):
        """Write detailed findings organized by control family."""
        control_results = self._group_by_framework_controls(framework)
        
        # Organize by family
        family_results = defaultdict(lambda: defaultdict(list))
        
        for control_id, results in control_results.items():
            # Extract family from control ID (e.g., AC-2 -> AC)
            family = control_id.split('-')[0] if '-' in control_id else control_id.split('.')[0]
            family_results[family][control_id] = results
        
        # Define family names
        family_names = {
            'AC': 'Access Control',
            'AU': 'Audit and Accountability',
            'CM': 'Configuration Management',
            'CP': 'Contingency Planning',
            'IA': 'Identification and Authentication',
            'SC': 'System and Communications Protection',
            'SI': 'System and Information Integrity',
            '3.1': 'Access Control',
            '3.3': 'Audit and Accountability',
            '3.4': 'Configuration Management',
            '3.5': 'Identification and Authentication',
            '3.13': 'System and Communications Protection',
            '3.14': 'System and Information Integrity'
        }
        
        for family in sorted(family_results.keys()):
            f.write(f"### {family} - {family_names.get(family, 'Other')}\n\n")
            
            family_controls = family_results[family]
            total_controls = len(family_controls)
            passed_controls = sum(1 for controls in family_controls.values() 
                                if all(r["status"] == "PASS" for r in controls))
            
            f.write(f"**Family Compliance:** {(passed_controls/total_controls*100) if total_controls > 0 else 0:.1f}% ")
            f.write(f"({passed_controls}/{total_controls} controls)\n\n")
            
            for control_id in sorted(family_controls.keys()):
                results = family_controls[control_id]
                control_status = "PASS" if all(r["status"] == "PASS" for r in results) else "FAIL"
                status_emoji = "✅" if control_status == "PASS" else "❌"
                
                f.write(f"#### {status_emoji} {control_id}\n\n")
                
                # Group checks by status
                passed_checks = [r for r in results if r["status"] == "PASS"]
                failed_checks = [r for r in results if r["status"] == "FAIL"]
                
                if passed_checks:
                    f.write("**Passed Checks:**\n")
                    for check in passed_checks:
                        f.write(f"- ✅ {check['check_name']} ({check['check_id']})\n")
                    f.write("\n")
                
                if failed_checks:
                    f.write("**Failed Checks:**\n")
                    for check in failed_checks:
                        f.write(f"- ❌ {check['check_name']} ({check['check_id']})\n")
                        f.write(f"  - Severity: {check.get('severity', 'Unknown')}\n")
                        f.write(f"  - Findings: {len(check.get('findings', []))}\n")
                        
                        # Show specific findings
                        for finding in check.get('findings', [])[:2]:
                            f.write(f"    - {finding.get('resource_type', 'Resource')}: {finding.get('resource_id', 'Unknown')}\n")
                            f.write(f"      - {finding.get('details', 'No details')}\n")
                        
                        if len(check.get('findings', [])) > 2:
                            f.write(f"    - ... and {len(check.get('findings', [])) - 2} more findings\n")
                    f.write("\n")
    
    def _write_failed_checks_detail(self, f):
        """Write detailed information about failed checks."""
        failed_checks = [r for r in self.results if r["status"] == "FAIL"]
        
        if not failed_checks:
            f.write("No failed checks - excellent compliance posture!\n")
            return
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        failed_checks.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
        
        for check in failed_checks:
            f.write(f"### {check['check_name']} ({check['check_id']})\n\n")
            f.write(f"**Severity:** {check.get('severity', 'Unknown')}\n")
            f.write(f"**Service:** {check.get('service', 'Unknown')}\n")
            f.write(f"**Category:** {check.get('category', 'Unknown')}\n\n")
            
            # Framework mappings
            mappings = self.framework_mappings["check_mappings"].get(
                check['check_id'], {}
            ).get("frameworks", {})
            
            f.write("**Compliance Mappings:**\n")
            for fw, controls in mappings.items():
                if controls:
                    f.write(f"- {fw.upper()}: {', '.join(controls)}\n")
            f.write("\n")
            
            # Findings
            f.write(f"**Findings ({len(check.get('findings', []))}):**\n\n")
            
            for i, finding in enumerate(check.get('findings', []), 1):
                f.write(f"{i}. **{finding.get('resource_type', 'Resource')}:** `{finding.get('resource_id', 'Unknown')}`\n")
                f.write(f"   - Region: {finding.get('region', 'Unknown')}\n")
                f.write(f"   - Details: {finding.get('details', 'No details')}\n")
                if finding.get('recommendation'):
                    f.write(f"   - Recommendation: {finding.get('recommendation')}\n")
                if finding.get('evidence'):
                    f.write(f"   - Evidence: `{json.dumps(finding.get('evidence'), indent=2)}`\n")
                f.write("\n")
    
    def _write_remediation_recommendations(self, f):
        """Write prioritized remediation recommendations."""
        # Group failed checks by severity and service
        remediation_groups = defaultdict(lambda: defaultdict(list))
        
        for result in self.results:
            if result["status"] == "FAIL":
                severity = result.get("severity", "Unknown")
                service = result.get("service", "Unknown")
                remediation_groups[severity][service].append(result)
        
        f.write("### Prioritized Remediation Plan\n\n")
        
        priority = 1
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in remediation_groups:
                f.write(f"#### Priority {priority}: {severity} Severity Issues\n\n")
                
                for service, checks in remediation_groups[severity].items():
                    f.write(f"**{service.upper()} Service:**\n")
                    
                    for check in checks:
                        f.write(f"- {check['check_name']} ({check['check_id']})\n")
                        
                        # Get first finding for recommendation
                        if check.get('findings'):
                            recommendation = check['findings'][0].get('recommendation', 'Review and remediate')
                            f.write(f"  - Action: {recommendation}\n")
                        
                        f.write(f"  - Resources Affected: {len(check.get('affected_resources', []))}\n")
                    
                    f.write("\n")
                
                priority += 1
    
    def _write_cui_assessment(self, f):
        """Write CUI-specific assessment for NIST 800-171."""
        cui_controls = {
            '3.1': 'Access Control - Limit access to authorized users',
            '3.3': 'Audit and Accountability - Create and retain audit records',
            '3.4': 'Configuration Management - Establish secure configurations',
            '3.5': 'Identification and Authentication - Identify users and devices',
            '3.8': 'Media Protection - Protect CUI on media',
            '3.11': 'Risk Assessment - Assess risk to CUI',
            '3.13': 'System and Communications Protection - Protect communications',
            '3.14': 'System and Information Integrity - Identify and manage flaws'
        }
        
        control_results = self._group_by_framework_controls("nist_800_171")
        
        for family_id, description in cui_controls.items():
            family_controls = {k: v for k, v in control_results.items() if k.startswith(family_id)}
            
            if family_controls:
                total = len(family_controls)
                passed = sum(1 for controls in family_controls.values() 
                           if all(r["status"] == "PASS" for r in controls))
                
                status = "✅ Compliant" if passed == total else f"⚠️  Partial ({passed}/{total})"
                f.write(f"- **{description}**: {status}\n")
    
    def _write_gap_analysis(self, f, framework: str):
        """Write gap analysis section."""
        control_results = self._group_by_framework_controls(framework)
        
        # Find controls with no checks
        if framework == "nist_800_171":
            all_controls = set()
            # Common NIST 800-171 controls
            for i in range(1, 23):
                all_controls.add(f"3.1.{i}")
            for i in range(1, 10):
                all_controls.add(f"3.3.{i}")
            # Add other families...
        else:
            all_controls = set()  # Would need complete control list
        
        covered_controls = set(control_results.keys())
        missing_controls = all_controls - covered_controls
        
        f.write(f"- **Controls with Coverage:** {len(covered_controls)}\n")
        f.write(f"- **Controls without Coverage:** {len(missing_controls)}\n")
        f.write(f"- **Coverage Percentage:** {(len(covered_controls)/len(all_controls)*100) if all_controls else 0:.1f}%\n\n")
        
        if missing_controls:
            f.write("**Controls Requiring Additional Checks:**\n")
            for control in sorted(missing_controls)[:10]:
                f.write(f"- {control}\n")
            if len(missing_controls) > 10:
                f.write(f"- ... and {len(missing_controls) - 10} more\n")
    
    def _write_implementation_priorities(self, f):
        """Write implementation priorities."""
        failed_checks = [r for r in self.results if r["status"] == "FAIL"]
        
        # Calculate impact scores
        impact_scores = []
        for check in failed_checks:
            severity_score = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                check.get("severity", "LOW"), 1
            )
            finding_count = len(check.get("findings", []))
            impact_score = severity_score * finding_count
            
            impact_scores.append({
                "check": check,
                "score": impact_score,
                "effort": self._estimate_effort(check)
            })
        
        # Sort by score
        impact_scores.sort(key=lambda x: x["score"], reverse=True)
        
        f.write("### Quick Wins (Low Effort, High Impact)\n\n")
        quick_wins = [x for x in impact_scores if x["effort"] == "Low" and x["score"] >= 3]
        for item in quick_wins[:5]:
            check = item["check"]
            f.write(f"- {check['check_name']} ({check['check_id']})\n")
            f.write(f"  - Impact Score: {item['score']}\n")
            f.write(f"  - Findings: {len(check.get('findings', []))}\n\n")
        
        f.write("### High Priority (High Impact)\n\n")
        high_priority = [x for x in impact_scores if x["score"] >= 6]
        for item in high_priority[:5]:
            check = item["check"]
            f.write(f"- {check['check_name']} ({check['check_id']})\n")
            f.write(f"  - Severity: {check.get('severity', 'Unknown')}\n")
            f.write(f"  - Estimated Effort: {item['effort']}\n\n")
    
    def _write_detailed_evidence(self, f, framework: str):
        """Write detailed evidence section."""
        control_results = self._group_by_framework_controls(framework)
        
        for control_id in sorted(control_results.keys())[:10]:  # First 10 controls
            results = control_results[control_id]
            
            f.write(f"### {control_id}\n\n")
            
            for result in results:
                f.write(f"**{result['check_name']}** ({result['check_id']})\n")
                f.write(f"- Status: {result['status']}\n")
                f.write(f"- Executed: {result.get('timestamp', 'Unknown')}\n")
                
                if result["status"] == "PASS":
                    f.write("- Evidence: Check passed successfully\n")
                else:
                    f.write(f"- Findings: {len(result.get('findings', []))}\n")
                    for finding in result.get('findings', [])[:1]:
                        f.write(f"  - Resource: {finding.get('resource_id', 'Unknown')}\n")
                        f.write(f"  - Issue: {finding.get('details', 'No details')}\n")
                
                f.write("\n")
    
    def _write_all_checks_summary(self, f, framework: str):
        """Write summary of all checks."""
        f.write("| Check ID | Check Name | Status | Severity | Findings | Mapped Controls |\n")
        f.write("|----------|------------|--------|----------|----------|----------------|\n")
        
        for result in sorted(self.results, key=lambda x: x['check_id']):
            check_id = result['check_id']
            mappings = self.framework_mappings["check_mappings"].get(
                check_id, {}
            ).get("frameworks", {})
            
            controls = mappings.get(framework, [])
            control_str = ', '.join(controls[:3])
            if len(controls) > 3:
                control_str += '...'
            
            status_emoji = {
                "PASS": "✅",
                "FAIL": "❌",
                "ERROR": "⚠️"
            }.get(result["status"], "❓")
            
            findings_count = len(result.get("findings", []))
            
            f.write(f"| {check_id} | {result['check_name'][:40]}... | {status_emoji} | ")
            f.write(f"{result.get('severity', 'N/A')} | {findings_count} | {control_str} |\n")
    
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
    
    def _estimate_effort(self, check: Dict[str, Any]) -> str:
        """Estimate remediation effort."""
        service = check.get("service", "")
        findings = len(check.get("findings", []))
        
        if findings > 50:
            return "High"
        elif findings > 10:
            return "Medium"
        elif service in ["iam", "s3", "ec2"]:
            return "Low"
        else:
            return "Medium"