# Quick Start Guide - AWS NIST Compliance Checker

## 🚀 5-Minute Setup

### 1. Clone and Setup (1 minute)

```bash
git clone <repository-url>
cd kovr-aws-nist-compliance
chmod +x setup.sh
./setup.sh
```

### 2. Configure AWS Credentials (1 minute)

**Option A: Environment Variables (Recommended)**

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEJr..." # Optional for temporary credentials
```

**Option B: .env File (Recommended for Local/Test)**

Create a `.env` file in the project root:

```
AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION_TOKEN="FwoGZXIvYXdzEJr..." # Optional
```

The `.env` file is gitignored by default. Tests in the `test/` folder will load credentials from `.env` automatically.

### 3. Run Your First Compliance Check (3 minutes)

```bash
# Run all checks and generate both NIST 800-53 and 800-171 reports (default)
./run_compliance_check.sh

# Run with parallel execution (faster!)
./run_compliance_check.sh -p -w 20

# Generate only NIST 800-53 report
./run_compliance_check.sh -w 800-53

# Generate only NIST 800-171 report
./run_compliance_check.sh -w 800-171

# Run only critical checks
./run_compliance_check.sh -l CRITICAL
```

## 📊 Understanding the Output

After running, you'll find these reports in the `./reports` directory:

**Default behavior**: Both NIST framework reports are generated automatically

1. **NIST 800-53 Report** (`nist_800-53_compliance_report_*.md`) - Organized by control families (AC, AU, IA, etc.)
2. **NIST 800-171 Report** (`nist_800-171_compliance_report_*.md`) - Organized by requirement families (3.1-3.14)
3. **CSV Report** (`compliance_results_*.csv`) - All check results in tabular format
4. **JSON Summary** (`compliance_summary_*.json`) - Machine-readable results
5. **Resource-level CSV** (`resources_*.csv`) - Per-resource compliance tracking

## 🎯 Common Use Cases

### Check Production Environment Only

```bash
# Run high-severity checks in production region with parallel execution
./run_compliance_check.sh -r us-east-1 -l HIGH -p -w 20
```

### Quick Security Audit

```bash
# Run only IAM and S3 checks (now 60+ checks available!)
./run_compliance_check.sh -c "CHECK-001,CHECK-002,CHECK-005,CHECK-006"

# Or run all encryption checks
./run_compliance_check.sh -c "CHECK-006,CHECK-007,CHECK-014,CHECK-023,CHECK-026,CHECK-027,CHECK-028"
```

### Generate Report for Management

```bash
# Generate both NIST frameworks for executive review (default)
./run_compliance_check.sh -o ./executive-reports

# Generate only NIST 800-53 report for FedRAMP
./run_compliance_check.sh -w 800-53 -o ./executive-reports

# Generate only NIST 800-171 report for DoD contractors
./run_compliance_check.sh -w 800-171 -o ./executive-reports
```

### Generate Resource-level Report

```bash
# Generate the resources report (resource-level compliance)
./run_compliance_check.sh -f resources
```

This will create a `resources_TIMESTAMP.csv` file in the `reports/` directory with detailed compliance data for every AWS resource tested.

### CI/CD Pipeline Integration

```bash
# Exit with non-zero code if any checks fail
./run_compliance_check.sh -l CRITICAL || exit 1
```

## 🔍 Key Security Checks (60+ Total)

### Critical Security Checks
| Check | What It Validates | Frameworks |
|-------|------------------|------------|
| CHECK-001 | Root account not used daily | NIST 800-53: AC-2, AC-6; NIST 800-171: 3.1.1 |
| CHECK-002 | MFA enabled on root | NIST 800-53: IA-2; NIST 800-171: 3.5.3 |
| CHECK-005 | S3 buckets not public | NIST 800-53: AC-3, SC-7; NIST 800-171: 3.1.3 |
| CHECK-017 | GuardDuty enabled | NIST 800-53: SI-4, SI-5 |
| CHECK-048 | IAM policy least privilege | NIST 800-53: AC-6; NIST 800-171: 3.1.5 |

### New Advanced Checks
- **Container Security**: EKS, ECS, ECR scanning
- **Database Protection**: RDS, DynamoDB, DocumentDB encryption
- **Analytics Security**: Kinesis, Athena, MSK protection
- **API Security**: AppSync, API Gateway authentication

## ⚡ Performance Tips

- **Enable Parallel Execution**: Use `-p -w 20` for 70-80% faster scans
- **Run Specific Checks**: Use `-c` to run only needed checks
- **Skip Regions**: Most checks scan all regions; limit with `-r`
- **Filter by Severity**: Use `-l HIGH` to focus on critical issues
- **Service Grouping**: Checks are intelligently grouped by AWS service

## 🔧 Troubleshooting

### "Permission Denied" Errors

Your IAM user needs read-only permissions for 40+ AWS services. Key permissions:

- `iam:Get*`, `iam:List*`
- `s3:Get*`, `s3:List*`
- `ec2:Describe*`
- `cloudtrail:Describe*`, `cloudtrail:Get*`
- `kms:List*`, `kms:Describe*`
- `lambda:List*`, `lambda:Get*`
- Plus 30+ more services (see README.md for full policy)

### "No Module Found" Errors

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Timeout Issues

```bash
# Run fewer checks at once
./run_compliance_check.sh -c "CHECK-001,CHECK-002"
```

## 📈 Next Steps

1. **Review Failed Checks**: Open the markdown report
2. **Prioritize Remediation**: Focus on CRITICAL/HIGH findings
3. **Schedule Regular Scans**: Add to cron for weekly runs
4. **Customize Checks**: Add your own checks in `security_checks/`

## 🆘 Getting Help

- Run with `--help` for all options
- Check `reports/` for detailed findings
- Review AWS CloudTrail for permission issues

---

**Ready to ensure compliance?** Run `./run_compliance_check.sh` now! 🚀
