#!/usr/bin/env python3
"""Report generator for compliance check results."""

import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict
import pandas as pd
from tabulate import tabulate


class ReportGenerator:
    """Generates CSV and Markdown reports from compliance check results."""
    
    def __init__(self, results: List[Dict[str, Any]], nist_mappings: Dict[str, Any]):
        self.results = results
        self.nist_mappings = nist_mappings
        self.timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
    def generate_csv_report(self, output_dir: str = './reports') -> str:
        """Generate CSV report with check results and NIST mappings."""
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, f'compliance_results_{self.timestamp}.csv')
        
        with open(csv_path, 'w', newline='') as csvfile:
            fieldnames = [
                'check_id', 'check_name', 'status', 'severity', 'framework',
                'nist_controls', 'findings_count', 'affected_resources',
                'account_id', 'timestamp', 'details'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                findings_details = []
                if result['findings']:
                    for finding in result['findings']:
                        findings_details.append(f"{finding.get('type', 'Unknown')}: {finding.get('details', '')}")
                
                row = {
                    'check_id': result['check_id'],
                    'check_name': result['check_name'],
                    'status': result['status'],
                    'severity': result['severity'],
                    'framework': result['framework'],
                    'nist_controls': ', '.join(result['nist_mappings']),
                    'findings_count': len(result['findings']),
                    'affected_resources': ', '.join(result['affected_resources']),
                    'account_id': result['account_id'],
                    'timestamp': result['timestamp'],
                    'details': ' | '.join(findings_details) if findings_details else 'No issues found'
                }
                writer.writerow(row)
        
        print(f"CSV report generated: {csv_path}")
        return csv_path
    
    def generate_markdown_report(self, output_dir: str = './reports') -> str:
        """Generate detailed Markdown report organized by NIST control families."""
        os.makedirs(output_dir, exist_ok=True)
        md_path = os.path.join(output_dir, f'nist_compliance_report_{self.timestamp}.md')
        
        with open(md_path, 'w') as f:
            # Write header
            f.write("# NIST 800-53 Compliance Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Account ID:** {self.results[0]['account_id'] if self.results else 'Unknown'}\n\n")
            
            # Write executive summary
            self._write_executive_summary(f)
            
            # Write detailed findings by control family
            self._write_control_family_details(f)
            
            # Write appendix with all check details
            self._write_appendix(f)
        
        print(f"Markdown report generated: {md_path}")
        return md_path
    
    def _write_executive_summary(self, f):
        """Write executive summary section."""
        f.write("## Executive Summary\n\n")
        
        # Calculate statistics
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r['status'] == 'PASS')
        failed_checks = sum(1 for r in self.results if r['status'] == 'FAIL')
        error_checks = sum(1 for r in self.results if r['status'] == 'ERROR')
        
        # Summary table
        summary_data = [
            ['Total Security Checks', total_checks],
            ['Passed', passed_checks],
            ['Failed', failed_checks],
            ['Errors', error_checks],
            ['Pass Rate', f"{(passed_checks/total_checks)*100:.1f}%" if total_checks > 0 else "0%"]
        ]
        
        f.write(tabulate(summary_data, headers=['Metric', 'Value'], tablefmt='pipe'))
        f.write("\n\n")
        
        # Severity breakdown
        f.write("### Findings by Severity\n\n")
        severity_counts = defaultdict(int)
        for result in self.results:
            if result['status'] == 'FAIL':
                severity_counts[result['severity']] += 1
        
        severity_data = [[sev, count] for sev, count in severity_counts.items()]
        if severity_data:
            f.write(tabulate(severity_data, headers=['Severity', 'Count'], tablefmt='pipe'))
        else:
            f.write("No failed checks found.\n")
        f.write("\n\n")
        
        # Framework coverage
        f.write("### Security Framework Coverage\n\n")
        framework_counts = defaultdict(int)
        for result in self.results:
            framework_counts[result['framework']] += 1
        
        framework_data = [[fw, count] for fw, count in framework_counts.items()]
        f.write(tabulate(framework_data, headers=['Framework', 'Checks'], tablefmt='pipe'))
        f.write("\n\n")
    
    def _write_control_family_details(self, f):
        """Write detailed findings organized by NIST control families."""
        f.write("## NIST Control Family Analysis\n\n")
        
        # Group results by NIST control
        control_results = defaultdict(list)
        for result in self.results:
            for control in result['nist_mappings']:
                control_results[control].append(result)
        
        # Process each control family
        for family_id, family_info in self.nist_mappings['control_families'].items():
            f.write(f"### {family_id} - {family_info['name']}\n\n")
            
            # Process each control in the family
            family_has_results = False
            for control_id, control_info in family_info['controls'].items():
                if control_id in control_results:
                    family_has_results = True
                    f.write(f"#### {control_id}: {control_info['title']}\n\n")
                    
                    # Get all checks for this control
                    checks = control_results[control_id]
                    passed = sum(1 for c in checks if c['status'] == 'PASS')
                    failed = sum(1 for c in checks if c['status'] == 'FAIL')
                    
                    f.write(f"**Coverage:** {len(checks)} checks ({passed} passed, {failed} failed)\n\n")
                    
                    # Requirements coverage
                    if 'requirements' in control_info:
                        f.write("**Requirements:**\n")
                        for req in control_info['requirements']:
                            f.write(f"- {req}\n")
                        f.write("\n")
                    
                    # Failed checks details
                    failed_checks = [c for c in checks if c['status'] == 'FAIL']
                    if failed_checks:
                        f.write("**Failed Checks:**\n\n")
                        for check in failed_checks:
                            f.write(f"- **{check['check_name']}** ({check['check_id']})\n")
                            f.write(f"  - Framework: {check['framework']}\n")
                            f.write(f"  - Severity: {check['severity']}\n")
                            if check['findings']:
                                f.write(f"  - Findings:\n")
                                for finding in check['findings']:
                                    f.write(f"    - {finding.get('type', 'Unknown')}: {finding.get('details', '')}\n")
                            f.write("\n")
                    
                    # Passed checks summary
                    passed_checks = [c for c in checks if c['status'] == 'PASS']
                    if passed_checks:
                        f.write("**Passed Checks:**\n")
                        for check in passed_checks:
                            f.write(f"- {check['check_name']} ({check['check_id']})\n")
                        f.write("\n")
            
            if not family_has_results:
                f.write("*No security checks mapped to this control family.*\n\n")
    
    def _write_appendix(self, f):
        """Write appendix with all check details."""
        f.write("## Appendix: All Security Checks\n\n")
        
        # Create detailed table of all checks
        check_data = []
        for result in self.results:
            check_data.append([
                result['check_id'],
                result['check_name'],
                result['status'],
                result['severity'],
                result['framework'],
                ', '.join(result['nist_mappings']),
                len(result['findings'])
            ])
        
        headers = ['Check ID', 'Name', 'Status', 'Severity', 'Framework', 'NIST Controls', 'Findings']
        f.write(tabulate(check_data, headers=headers, tablefmt='pipe'))
        f.write("\n\n")
        
        # Detailed findings
        f.write("### Detailed Findings\n\n")
        for result in self.results:
            if result['findings']:
                f.write(f"#### {result['check_name']} ({result['check_id']})\n\n")
                for finding in result['findings']:
                    f.write(f"- **Type:** {finding.get('type', 'Unknown')}\n")
                    if 'resource' in finding:
                        f.write(f"- **Resource:** {finding['resource']}\n")
                    if 'region' in finding:
                        f.write(f"- **Region:** {finding['region']}\n")
                    f.write(f"- **Details:** {finding.get('details', 'No details available')}\n")
                    f.write("\n")
    
    def generate_summary_json(self, output_dir: str = './reports') -> str:
        """Generate JSON summary for programmatic processing."""
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, f'compliance_summary_{self.timestamp}.json')
        
        summary = {
            'metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'account_id': self.results[0]['account_id'] if self.results else 'Unknown',
                'total_checks': len(self.results)
            },
            'statistics': {
                'passed': sum(1 for r in self.results if r['status'] == 'PASS'),
                'failed': sum(1 for r in self.results if r['status'] == 'FAIL'),
                'error': sum(1 for r in self.results if r['status'] == 'ERROR')
            },
            'control_coverage': {},
            'results': self.results
        }
        
        # Calculate control coverage
        control_stats = defaultdict(lambda: {'total': 0, 'passed': 0, 'failed': 0})
        for result in self.results:
            for control in result['nist_mappings']:
                control_stats[control]['total'] += 1
                if result['status'] == 'PASS':
                    control_stats[control]['passed'] += 1
                elif result['status'] == 'FAIL':
                    control_stats[control]['failed'] += 1
        
        summary['control_coverage'] = dict(control_stats)
        
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        print(f"JSON summary generated: {json_path}")
        return json_path