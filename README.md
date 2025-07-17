# Kovr AWS NIST 800-53 Compliance Checker

A Python application that validates AWS environments for compliance with the NIST 800-53 security framework. This tool runs various security checks from popular frameworks (CIS Benchmark, OWASP, MITRE ATT&CK, AWS Well-Architected) and maps them to NIST 800-53 controls.

## Features

- **15 Pre-configured Security Checks**: Covering IAM, S3, EC2, CloudTrail, VPC, RDS, and AWS Config
- **Multiple Framework Support**: CIS AWS Benchmark, OWASP Cloud Security, MITRE ATT&CK, AWS Well-Architected
- **NIST 800-53 Mapping**: All checks are mapped to relevant NIST 800-53 controls
- **Multiple Report Formats**: CSV, Markdown, and JSON outputs
- **Flexible Authentication**: Supports AWS access keys, secret keys, and temporary session tokens
- **Git Integration**: Can download security checks from a git repository
- **Configurable Execution**: Filter by severity, specific checks, or skip certain checks

## Security Checks Included

| Check ID | Name | Framework | NIST Controls |
|----------|------|-----------|---------------|
| CHECK-001 | IAM Root Account Usage | CIS AWS Benchmark | AC-2, AC-6 |
| CHECK-002 | MFA on Root Account | CIS AWS Benchmark | IA-2 |
| CHECK-003 | CloudTrail Enabled | CIS AWS Benchmark | AU-2, AU-3 |
| CHECK-004 | CloudTrail Log File Validation | MITRE ATT&CK | AU-9 |
| CHECK-005 | S3 Bucket Public Access | OWASP Cloud Security | AC-3, SC-7 |
| CHECK-006 | S3 Bucket Encryption | AWS Well-Architected | SC-28 |
| CHECK-007 | EBS Volume Encryption | CIS AWS Benchmark | SC-28 |
| CHECK-008 | Security Group SSH Access | CIS AWS Benchmark | SC-7, AC-3 |
| CHECK-009 | IAM Password Policy | CIS AWS Benchmark | IA-5 |
| CHECK-010 | IAM Access Key Rotation | AWS Well-Architected | IA-5, AC-2 |
| CHECK-011 | Unused IAM Credentials | CIS AWS Benchmark | AC-2 |
| CHECK-012 | EC2 Instance Metadata Service V2 | AWS Security Best Practices | AC-3, CM-7 |
| CHECK-013 | VPC Flow Logs | MITRE ATT&CK | AU-2, AU-3 |
| CHECK-014 | RDS Encryption | CIS AWS Benchmark | SC-28 |
| CHECK-015 | Config Service Enabled | AWS Well-Architected | CM-2, CM-8 |

## Installation

### Prerequisites

- Python 3.7 or higher
- Git (optional, for downloading checks from repositories)
- AWS CLI configured or AWS credentials available

### Setup

1. Clone this repository:

```bash
git clone <repository-url>
cd aws-nist-compliance-poc
```

2. Run the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

This will:

- Create the necessary directory structure
- Set up a Python virtual environment
- Install required dependencies
- Make scripts executable

## Usage

### Basic Usage

1. Set your AWS credentials:

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # Optional, for temporary credentials
```

2. Run the compliance checker:

```bash
./run_compliance_check.sh
```

### Command Line Options

```bash
./run_compliance_check.sh [OPTIONS]

OPTIONS:
    -k, --access-key KEY        AWS Access Key ID
    -s, --secret-key KEY        AWS Secret Access Key
    -t, --session-token TOKEN   AWS Session Token (for temporary credentials)
    -r, --region REGION        AWS Region (default: us-east-1)
    -g, --git-repo URL         Git repository URL for security checks
    -b, --git-branch BRANCH    Git branch to use (default: main)
    -o, --output-dir DIR       Output directory for reports (default: ./reports)
    -c, --checks CHECK_IDS     Comma-separated list of specific check IDs to run
    -x, --skip-checks IDS      Comma-separated list of check IDs to skip
    -l, --severity LEVEL       Minimum severity level (LOW, MEDIUM, HIGH, CRITICAL)
    -f, --format FORMAT        Report format (all, csv, markdown, json)
    -h, --help                 Show help message
```

### Examples

1. **Run all checks with command line credentials:**

```bash
./run_compliance_check.sh -k "AKIAIOSFODNN7EXAMPLE" -s "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" -r "us-west-2"
```

2. **Run only HIGH and CRITICAL severity checks:**

```bash
./run_compliance_check.sh -l HIGH
```

3. **Run specific checks only:**

```bash
./run_compliance_check.sh -c "CHECK-001,CHECK-002,CHECK-005"
```

4. **Skip certain checks:**

```bash
./run_compliance_check.sh -x "CHECK-013,CHECK-014"
```

5. **Generate only CSV report:**

```bash
./run_compliance_check.sh -f csv
```

6. **Download checks from a git repository:**

```bash
./run_compliance_check.sh -g "https://github.com/your-org/security-checks.git" -b "main"
```

## Output Reports

The tool generates three types of reports in the `./reports` directory:

### 1. CSV Report (`compliance_results_TIMESTAMP.csv`)

- Tabular format with all check results
- Includes check details, status, affected resources, and NIST mappings
- Ideal for importing into spreadsheets or databases

### 2. Markdown Report (`nist_compliance_report_TIMESTAMP.md`)

- Detailed report organized by NIST control families
- Executive summary with statistics
- Control coverage analysis
- Detailed findings with remediation guidance
- Perfect for documentation and compliance reporting

### 3. JSON Summary (`compliance_summary_TIMESTAMP.json`)

- Machine-readable format
- Complete results with metadata
- Control coverage statistics
- Suitable for programmatic processing

## Report Structure

### CSV Fields

- `check_id`: Unique identifier for the check
- `check_name`: Descriptive name of the check
- `status`: PASS, FAIL, or ERROR
- `severity`: LOW, MEDIUM, HIGH, or CRITICAL
- `framework`: Source security framework
- `nist_controls`: Comma-separated NIST 800-53 controls
- `findings_count`: Number of issues found
- `affected_resources`: Resources that failed the check
- `account_id`: AWS account ID
- `timestamp`: When the check was run
- `details`: Specific finding details

### Markdown Report Sections

1. **Executive Summary**: Overall compliance statistics
2. **Findings by Severity**: Breakdown of failed checks by severity
3. **Security Framework Coverage**: Checks per framework
4. **NIST Control Family Analysis**: Detailed analysis by control family
5. **Appendix**: Complete list of all checks and detailed findings

## Extending the Tool

### Adding New Security Checks

1. Edit `security_checks/checks_config.json` to add new check definitions
2. Implement the check function in `src/aws_connector.py`
3. Map the check to appropriate NIST controls

Example check definition:

```json
{
  "id": "CHECK-016",
  "name": "Lambda Function Encryption",
  "description": "Ensure Lambda functions use encrypted environment variables",
  "category": "Compute Security",
  "framework": "AWS Security Best Practices",
  "severity": "MEDIUM",
  "nist_mappings": ["SC-28"],
  "service": "lambda",
  "check_function": "check_lambda_encryption"
}
```

### Adding New NIST Controls

Edit `mappings/nist_800_53_mappings.json` to add new control families or controls.

## Troubleshooting

### Common Issues

1. **"AWS credentials not found" error**
   - Ensure AWS credentials are properly set as environment variables
   - Check that both ACCESS_KEY_ID and SECRET_ACCESS_KEY are provided

2. **"No module named 'boto3'" error**
   - Run `./setup.sh` to install dependencies
   - Activate the virtual environment: `source .venv/bin/activate`

3. **Permission errors**
   - Ensure your AWS credentials have sufficient permissions to run the checks
   - Required permissions include read access to IAM, EC2, S3, CloudTrail, VPC, RDS, and Config

4. **Timeout errors**
   - Some checks iterate through all regions and may take time
   - Consider using `-c` option to run specific checks only

## Security Considerations

- **Credential Storage**: Never commit AWS credentials to version control
- **Permissions**: Use least-privilege IAM policies for the credentials
- **Session Tokens**: Prefer temporary session tokens over long-lived credentials
- **Report Storage**: Secure the generated reports as they contain security findings

## IAM Permissions and Troubleshooting

### Required AWS Permissions

The compliance checker needs read-only permissions. Create an IAM policy with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComplianceCheckerReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "ec2:Describe*",
        "s3:List*",
        "s3:GetBucket*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "rds:Describe*",
        "config:Describe*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Common Authentication Errors

#### "SignatureDoesNotMatch" Error

This error usually means there's an issue with your AWS credentials. Here's how to fix it:

1. **Check for Extra Spaces/Newlines**

   ```bash
   # Bad - has spaces or newlines
   export AWS_ACCESS_KEY_ID=" AKIAIOSFODNN7EXAMPLE "

   # Good - no extra spaces
   export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
   ```

2. **Verify Credentials Are Correct**

   ```bash
   # Test your credentials directly
   aws sts get-caller-identity
   ```

3. **Check System Time**
   AWS signatures are time-sensitive:

   ```bash
   # Check current time
   date

   # Sync time on Linux/Mac
   sudo ntpdate -s time.nist.gov
   ```

4. **Re-export Credentials Carefully**

   ```bash
   # First, unset existing credentials
   unset AWS_ACCESS_KEY_ID
   unset AWS_SECRET_ACCESS_KEY
   unset AWS_SESSION_TOKEN

   # Set them again carefully
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   ```

5. **Handle Special Characters**
   If your secret key has special characters (+, /, =):

   ```bash
   # Use single quotes to avoid shell interpretation
   export AWS_SECRET_ACCESS_KEY='abc123+def/456=GHI'
   ```

6. **Try Command Line Arguments**

   ```bash
   ./run_compliance_check.sh \
     -k "AKIAIOSFODNN7EXAMPLE" \
     -s "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
     -r "us-east-1"
   ```

### Creating Temporary Session Tokens

For enhanced security, use temporary credentials:

```bash
# With MFA
aws sts get-session-token \
  --serial-number arn:aws:iam::123456789012:mfa/username \
  --token-code 123456 \
  --duration-seconds 43200

# Export the temporary credentials
export AWS_ACCESS_KEY_ID="ASIATEMP..."
export AWS_SECRET_ACCESS_KEY="temp-secret..."
export AWS_SESSION_TOKEN="FwoGZXIvYXdzE..."
```

### Debug Script

Save this as `debug_aws_creds.sh` to troubleshoot credential issues:

```bash
#!/bin/bash
echo "Debugging AWS Credentials"
echo "========================"

# Check if credentials are set
echo -e "\n1. Environment variables:"
echo "AWS_ACCESS_KEY_ID length: ${#AWS_ACCESS_KEY_ID}"
echo "AWS_SECRET_ACCESS_KEY length: ${#AWS_SECRET_ACCESS_KEY}"

# Check for hidden characters
echo -e "\n2. Hidden characters check:"
echo "Access Key (between brackets): [${AWS_ACCESS_KEY_ID}]"

# Test AWS CLI
echo -e "\n3. Testing AWS CLI:"
aws sts get-caller-identity

# Check system time
echo -e "\n4. System time:"
date -u
```

### Quick Fix for Copy/Paste Issues

Create credentials without copy/paste errors:

```bash
# Create a temporary file
cat > ~/.aws_temp_creds << 'EOF'
export AWS_ACCESS_KEY_ID="PASTE_KEY_HERE"
export AWS_SECRET_ACCESS_KEY="PASTE_SECRET_HERE"
EOF

# Source it
source ~/.aws_temp_creds

# Clean up
rm ~/.aws_temp_creds

# Test
aws sts get-caller-identity
```

## License

This is a proof-of-concept tool for demonstration purposes.

## Contributing

To contribute to this POC:

1. Add new security checks in `aws_connector.py`
2. Update the checks configuration in `checks_config.json`
3. Ensure proper NIST control mappings
4. Test thoroughly before submitting changes
