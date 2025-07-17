#!/usr/bin/env python3
"""
Example usage of the AWS NIST Compliance Checker

This script demonstrates various ways to use the compliance checker
for both NIST 800-53 and NIST 800-171 frameworks.
"""

import os
import json
from datetime import datetime

# Set AWS credentials from .env file (if using)
from dotenv import load_dotenv
load_dotenv()

# Example 1: Basic compliance check (generates both NIST 800-53 and 800-171 reports by default)
print("Example 1: Running basic compliance check for both NIST frameworks...")
os.system("./run_compliance_check.sh")

# Example 2: Parallel execution for faster scans
print("\nExample 2: Running with parallel execution (20 workers)...")
os.system("./run_compliance_check.sh -p -w 20")

# Example 3: Generate only NIST 800-171 report
print("\nExample 3: Generating NIST 800-171 compliance report only...")
os.system("./run_compliance_check.sh -w 800-171")

# Example 4: High-severity checks with only NIST 800-53 report
print("\nExample 4: Running high-severity checks with NIST 800-53 report only...")
os.system("./run_compliance_check.sh -l HIGH -p -w 20 -w 800-53")

# Example 5: Generate both framework reports with markdown format only
print("\nExample 5: Generating both NIST framework reports (markdown only)...")
os.system("./run_compliance_check.sh -f markdown -w both")

# Example 6: Specific service checks (IAM and encryption)
print("\nExample 6: Running specific security checks...")
iam_checks = "CHECK-001,CHECK-002,CHECK-009,CHECK-010,CHECK-011,CHECK-032,CHECK-033,CHECK-048"
encryption_checks = "CHECK-006,CHECK-007,CHECK-014,CHECK-023,CHECK-026,CHECK-027,CHECK-028"
os.system(f"./run_compliance_check.sh -c '{iam_checks},{encryption_checks}' -p -w 15")

# Example 7: Generate all reports for audit
print("\nExample 7: Generating comprehensive audit package...")
os.system("./run_compliance_check.sh -f all -p -w 20")

# Example 8: Using Python to process results
print("\nExample 8: Processing compliance results programmatically...")

# Run check and capture results
os.system("./run_compliance_check.sh -f json -o ./temp_reports")

# Find the latest JSON report
import glob
json_files = glob.glob("./temp_reports/compliance_summary_*.json")
if json_files:
    latest_report = max(json_files, key=os.path.getctime)
    
    with open(latest_report, 'r') as f:
        results = json.load(f)
    
    # Analyze results
    total_checks = len(results.get('results', []))
    passed_checks = sum(1 for r in results.get('results', []) if r['status'] == 'PASS')
    failed_checks = sum(1 for r in results.get('results', []) if r['status'] == 'FAIL')
    
    print(f"\nCompliance Summary:")
    print(f"Total Checks: {total_checks}")
    print(f"Passed: {passed_checks} ({passed_checks/total_checks*100:.1f}%)")
    print(f"Failed: {failed_checks} ({failed_checks/total_checks*100:.1f}%)")
    
    # Show failed critical checks
    critical_failures = [
        r for r in results.get('results', []) 
        if r['status'] == 'FAIL' and r.get('severity') == 'CRITICAL'
    ]
    
    if critical_failures:
        print(f"\nCritical Failures ({len(critical_failures)}):")
        for failure in critical_failures:
            print(f"- {failure['check_name']} ({failure['check_id']})")
            print(f"  Affected Resources: {', '.join(failure.get('affected_resources', []))}")

# Example 9: Custom check filtering
print("\nExample 9: Running checks for specific AWS services...")

# Database security checks
db_checks = [
    "CHECK-014",  # RDS Encryption
    "CHECK-027",  # DynamoDB Encryption
    "CHECK-035",  # RDS Automated Backups
    "CHECK-043",  # Redshift Encryption
    "CHECK-050",  # Aurora Activity Streams
    "CHECK-059",  # DocumentDB Encryption
    "CHECK-060",  # Neptune Encryption
]

os.system(f"./run_compliance_check.sh -c '{','.join(db_checks)}' -p -w 10")

# Example 10: Scheduled compliance checking (cron example)
print("\nExample 10: Setting up scheduled compliance checks...")
print("""
# Add to crontab for daily compliance checks at 2 AM:
# 0 2 * * * cd /path/to/kovr-aws-nist-compliance && ./run_compliance_check.sh -l HIGH -p -w 20 -f csv

# Weekly comprehensive scan on Sundays:
# 0 3 * * 0 cd /path/to/kovr-aws-nist-compliance && ./run_compliance_check.sh -p -w 30 -f all
""")

# Example 11: Multi-account scanning
print("\nExample 11: Multi-account compliance scanning...")
accounts = [
    {"name": "Production", "access_key": "PROD_KEY", "secret_key": "PROD_SECRET"},
    {"name": "Staging", "access_key": "STAGE_KEY", "secret_key": "STAGE_SECRET"},
]

for account in accounts:
    print(f"\nScanning {account['name']} account...")
    # Note: Replace with actual credentials
    # os.system(f"./run_compliance_check.sh -k '{account['access_key']}' -s '{account['secret_key']}' -l HIGH")

# Example 12: Comparing compliance over time
print("\nExample 12: Tracking compliance improvement...")
print("""
# Save reports with date stamps for trend analysis:
TODAY=$(date +%Y%m%d)
./run_compliance_check.sh -o ./reports/$TODAY

# Compare with previous run:
# diff ./reports/20240115/compliance_results_enhanced_*.csv ./reports/20240122/compliance_results_enhanced_*.csv
""")

print("\n✅ All examples completed!")
print("\nKey Features Demonstrated:")
print("- Parallel execution for 70-80% faster scans")
print("- Dual NIST framework support (800-53 and 800-171)")
print("- Default generation of both framework reports")
print("- Framework-specific report generation options")
print("- Service-specific security assessments")
print("- Programmatic result processing")
print("- Scheduled compliance checking")
print("\nCheck the ./reports directory for all generated reports!")