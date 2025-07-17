# Quick Start Guide - AWS NIST 800-53 Compliance Checker

## 🚀 5-Minute Setup

### 1. Clone and Setup (1 minute)
```bash
git clone <repository-url>
cd aws-nist-compliance-poc
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

**Option B: AWS CLI Profile**
```bash
aws configure
# Follow prompts to enter credentials
```

### 3. Run Your First Compliance Check (3 minutes)
```bash
# Run all checks
./run_compliance_check.sh

# Or run only critical checks
./run_compliance_check.sh -l CRITICAL
```

## 📊 Understanding the Output

After running, you'll find three reports in the `./reports` directory:

1. **CSV Report** - Import into Excel for analysis
2. **Markdown Report** - Human-readable compliance report
3. **JSON Summary** - For programmatic processing

## 🎯 Common Use Cases

### Check Production Environment Only
```bash
# Run high-severity checks in production region
./run_compliance_check.sh -r us-east-1 -l HIGH
```

### Quick Security Audit
```bash
# Run only IAM and S3 checks
./run_compliance_check.sh -c "CHECK-001,CHECK-002,CHECK-005,CHECK-006"
```

### Generate Report for Management
```bash
# Generate only the markdown report
./run_compliance_check.sh -f markdown -o ./executive-reports
```

### CI/CD Pipeline Integration
```bash
# Exit with non-zero code if any checks fail
./run_compliance_check.sh -l CRITICAL || exit 1
```

## 🔍 What Each Check Does

| Check | What It Validates | Why It Matters |
|-------|------------------|----------------|
| CHECK-001 | Root account not used daily | Prevents unauthorized access |
| CHECK-002 | MFA enabled on root | Adds authentication layer |
| CHECK-003 | CloudTrail logging active | Enables security auditing |
| CHECK-005 | S3 buckets not public | Prevents data exposure |
| CHECK-008 | SSH properly restricted | Blocks unauthorized access |

## ⚡ Performance Tips

- **Run Specific Checks**: Use `-c` to run only needed checks
- **Skip Regions**: Most checks scan all regions; limit with `-r`
- **Parallel Execution**: Large environments may take 5-10 minutes

## 🔧 Troubleshooting

### "Permission Denied" Errors
Your IAM user needs these permissions:
- `iam:Get*`, `iam:List*`
- `s3:Get*`, `s3:List*`
- `ec2:Describe*`
- `cloudtrail:Describe*`, `cloudtrail:Get*`

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