# Kovr AWS Multi-Framework Compliance Checker

A comprehensive Python application that validates AWS environments for compliance with multiple security frameworks including NIST 800-53, NIST 800-171, CIS AWS Benchmark, MITRE ATT&CK, OWASP Cloud Security, AWS Well-Architected Framework, and more. This tool provides parallel execution, multi-framework mapping, and comprehensive reporting capabilities.

**New in v2.0**: 
- Expanded to 160 security checks (from 60)
- Enhanced NIST coverage: ~29% NIST 800-171 and growing NIST 800-53 coverage
- New check categories: Zero Trust, CSA CCM, SANS Top 20, advanced AWS services
- Improved parallel execution and reporting capabilities

## Features

- **160 Pre-configured Security Checks**: Comprehensive coverage across 50+ AWS services
- **Multi-Framework Support**: Maps to 10+ compliance frameworks:
  - NIST 800-53 Rev 5
  - NIST 800-171 Rev 2
  - CIS AWS Foundations Benchmark
  - MITRE ATT&CK Framework
  - OWASP Cloud Security
  - AWS Well-Architected Framework
  - NIST Cybersecurity Framework (CSF)
  - CSA Cloud Controls Matrix (CCM)
  - SANS Top 20 Critical Security Controls
  - Zero Trust Architecture (NIST SP 800-207)
- **Parallel Execution**: Multi-threaded check execution for 70-80% faster scans
- **Enhanced Reporting**: Framework-specific reports for NIST 800-53 and NIST 800-171
- **Multiple Report Formats**: CSV, Markdown (separate for each NIST framework), JSON, Resource-level CSV
- **Dual Framework Support**: Generates both NIST 800-53 and NIST 800-171 reports by default
- **Flexible Authentication**: Supports AWS access keys, secret keys, and temporary session tokens
- **Git Integration**: Can download security checks from a git repository
- **Configurable Execution**: Filter by severity, specific checks, or skip certain checks
- **Resource-level Reporting**: Detailed compliance tracking for every AWS resource
- **Intelligent Rate Limiting**: Avoids API throttling with service-aware scheduling

## Framework Coverage

### NIST Compliance Coverage
- **NIST 800-53 Rev 5**: 72+ unique controls covered
- **NIST 800-171 Rev 2**: 32 requirements covered (~29% of all 110 requirements)
- **FedRAMP High Baseline**: Growing coverage of key controls

### Coverage by NIST 800-171 Requirement Family
- Access Control (3.1): 5 requirements covered
- Audit and Accountability (3.3): 4 requirements covered  
- Configuration Management (3.4): 3 requirements covered
- Identification and Authentication (3.5): 4 requirements covered
- Media Protection (3.8): 1 requirement covered
- Physical Protection (3.10): 1 requirement covered
- Risk Assessment (3.11): 2 requirements covered
- Security Assessment (3.12): 1 requirement covered
- System and Communications Protection (3.13): 8 requirements covered
- System and Information Integrity (3.14): 3 requirements covered

*Note: Some NIST requirement families (Awareness and Training, Incident Response, Maintenance, Personnel Security) require organizational processes beyond AWS technical controls.*

## Security Checks Included

The tool includes 160 security checks across multiple categories:

### Identity and Access Management (IAM)
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-001 | IAM Root Account Usage | CRITICAL | NIST 800-53: AC-2, AC-6; NIST 800-171: 3.1.1, 3.1.5; CIS: 1.1 |
| CHECK-002 | MFA on Root Account | CRITICAL | NIST 800-53: IA-2; NIST 800-171: 3.5.3; CIS: 1.5, 1.6 |
| CHECK-009 | IAM Password Policy | MEDIUM | NIST 800-53: IA-5; NIST 800-171: 3.5.7; CIS: 1.8-1.14 |
| CHECK-010 | IAM Access Key Rotation | MEDIUM | NIST 800-53: IA-5, AC-2; NIST 800-171: 3.5.10 |
| CHECK-011 | Unused IAM Credentials | MEDIUM | NIST 800-53: AC-2; NIST 800-171: 3.1.1 |
| CHECK-032 | IAM Roles for Service Accounts | HIGH | NIST 800-53: AC-2, IA-2; NIST 800-171: 3.1.1 |
| CHECK-033 | Cross-Account Access Review | MEDIUM | NIST 800-53: AC-2, AC-3; NIST 800-171: 3.1.2 |
| CHECK-048 | IAM Policy Least Privilege Analysis | HIGH | NIST 800-53: AC-6; NIST 800-171: 3.1.5 |

### Logging and Monitoring
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-003 | CloudTrail Enabled | HIGH | NIST 800-53: AU-2, AU-3; NIST 800-171: 3.3.1, 3.3.2 |
| CHECK-004 | CloudTrail Log File Validation | MEDIUM | NIST 800-53: AU-9; NIST 800-171: 3.3.8 |
| CHECK-013 | VPC Flow Logs | MEDIUM | NIST 800-53: AU-2, AU-3; NIST 800-171: 3.3.1 |
| CHECK-021 | CloudWatch Alarms for Security Events | MEDIUM | NIST 800-53: IR-4, IR-5 |
| CHECK-036 | CloudWatch Logs Retention | MEDIUM | NIST 800-53: AU-4, AU-11 |
| CHECK-037 | API Gateway Logging | MEDIUM | NIST 800-53: AU-2, AU-3; NIST 800-171: 3.3.1 |
| CHECK-038 | Lambda Function Logging | MEDIUM | NIST 800-53: AU-2, AU-3 |
| CHECK-039 | CloudTrail KMS Encryption | HIGH | NIST 800-53: AU-9, SC-28 |
| CHECK-040 | S3 Bucket Logging | MEDIUM | NIST 800-53: AU-2, AU-3 |
| CHECK-044 | ALB Access Logging | MEDIUM | NIST 800-53: AU-2, AU-3; NIST 800-171: 3.3.1 |

### Data Protection and Encryption
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-005 | S3 Bucket Public Access | HIGH | NIST 800-53: AC-3, SC-7; NIST 800-171: 3.1.3, 3.13.5 |
| CHECK-006 | S3 Bucket Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-007 | EBS Volume Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-014 | RDS Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-023 | KMS Key Rotation | MEDIUM | NIST 800-53: SC-12, SC-13 |
| CHECK-024 | Secrets Manager Usage | HIGH | NIST 800-53: IA-5, SC-28 |
| CHECK-026 | EFS Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-027 | DynamoDB Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-028 | ElastiCache Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-043 | Redshift Cluster Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-046 | SQS Queue Encryption | MEDIUM | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-047 | SNS Topic Encryption | MEDIUM | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-052 | Athena Workgroup Encryption | MEDIUM | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-053 | Glue Data Catalog Encryption | MEDIUM | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-056 | Kinesis Stream Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-057 | MSK Cluster Encryption | HIGH | NIST 800-53: SC-8, SC-28 |
| CHECK-059 | DocumentDB Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |
| CHECK-060 | Neptune Database Encryption | HIGH | NIST 800-53: SC-28; NIST 800-171: 3.13.11 |

### Network Security
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-008 | Security Group SSH Access | HIGH | NIST 800-53: SC-7, AC-3; NIST 800-171: 3.1.3, 3.13.5 |
| CHECK-025 | VPC Endpoint Usage | MEDIUM | NIST 800-53: SC-7, AC-4 |
| CHECK-029 | Network ACL Rules | MEDIUM | NIST 800-53: SC-7, AC-4 |
| CHECK-030 | AWS WAF Enabled | MEDIUM | NIST 800-53: SC-7, SI-4 |
| CHECK-031 | CloudFront Security Headers | MEDIUM | NIST 800-53: SC-8 |
| CHECK-042 | EKS Cluster Public Access | HIGH | NIST 800-53: SC-7, AC-3; NIST 800-171: 3.13.1 |

### System and Information Integrity
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-012 | EC2 Instance Metadata Service V2 | MEDIUM | NIST 800-53: AC-3, CM-7; NIST 800-171: 3.4.6 |
| CHECK-016 | CloudWatch Anomaly Detection | MEDIUM | NIST 800-53: SI-4 |
| CHECK-017 | GuardDuty Enabled | HIGH | NIST 800-53: SI-4, SI-5 |
| CHECK-018 | AWS Inspector Assessments | MEDIUM | NIST 800-53: SI-2, SI-3 |
| CHECK-019 | Systems Manager Patch Compliance | HIGH | NIST 800-53: SI-2; NIST 800-171: 3.14.1 |
| CHECK-020 | Security Hub Enabled | HIGH | NIST 800-53: SI-4, SI-6 |
| CHECK-045 | ECR Image Scanning | HIGH | NIST 800-53: SI-2, SI-3; NIST 800-171: 3.14.1 |

### Configuration Management
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-015 | Config Service Enabled | MEDIUM | NIST 800-53: CM-2, CM-8; NIST 800-171: 3.4.1 |
| CHECK-049 | CloudFormation Stack Drift Detection | MEDIUM | NIST 800-53: CM-2, CM-3; NIST 800-171: 3.4.1 |

### Incident Response
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-022 | SNS Topics for Security Notifications | MEDIUM | NIST 800-53: IR-6; NIST 800-171: 3.6.2 |

### Backup and Recovery
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-034 | AWS Backup Plans | HIGH | NIST 800-53: CP-9, CP-10 |
| CHECK-035 | RDS Automated Backups | HIGH | NIST 800-53: CP-9 |

### Compute and Container Security
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-041 | Lambda Function Resource Policies | HIGH | NIST 800-53: AC-3, AC-4; NIST 800-171: 3.1.1 |
| CHECK-051 | ECS Task Definition Security | HIGH | NIST 800-53: CM-7, AC-6; NIST 800-171: 3.1.5 |

### Database Security
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-050 | Aurora Database Activity Streams | MEDIUM | NIST 800-53: AU-2, AU-3, AU-12 |

### Application Integration
| Check ID | Name | Severity | Frameworks |
|----------|------|----------|------------|
| CHECK-054 | Step Functions Logging | LOW | NIST 800-53: AU-2, AU-3 |
| CHECK-055 | EventBridge Rule Security | MEDIUM | NIST 800-53: AC-3, AC-4 |
| CHECK-058 | AppSync API Authentication | HIGH | NIST 800-53: IA-2, AC-3; NIST 800-171: 3.5.1 |

### New Check Categories (CHECK-061 to CHECK-160)

#### CIS AWS Foundations Benchmark Checks
- CHECK-061 to CHECK-070: IAM hardening, S3 security, encryption defaults, network restrictions

#### MITRE ATT&CK Framework Checks  
- CHECK-071 to CHECK-075: Threat detection, account monitoring, ransomware protection, DoS mitigation

#### AWS Well-Architected Framework Checks
- CHECK-076 to CHECK-085: Account segregation, service quotas, API security, auto-scaling

#### OWASP Cloud Security Checks
- CHECK-086 to CHECK-095: API gateway authentication, CORS validation, WAF rules, injection prevention

#### Zero Trust Architecture Checks
- CHECK-096 to CHECK-105: Micro-segmentation, continuous verification, device trust, least privilege

#### CSA Cloud Controls Matrix Checks
- CHECK-106 to CHECK-115: Security metrics, data retention, change detection, key management

#### SANS Top 20 Critical Controls
- CHECK-116 to CHECK-125: Asset inventory, centralized logging, continuous monitoring

#### Advanced AWS Service Checks
- CHECK-126 to CHECK-160: Coverage for 30+ additional AWS services including IoT, ML, Analytics, Blockchain, Quantum computing, and more

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

### AWS Credentials via .env (Recommended for Local/Test)

Create a `.env` file in the project root:

```
AWS_ACCESS_KEY_ID="your-access-key"
AWS_SECRET_ACCESS_KEY="your-secret-key"
AWS_SESSION_TOKEN="your-session-token"  # Optional
```

The `.env` file is gitignored by default. Tests in the `test/` folder will load credentials from `.env` automatically.

## Documentation

### Setup & Configuration
- [Quick Start Guide](docs/setup/quickstart.md) - Detailed setup and usage instructions
- [IAM Permissions Required](docs/setup/IAM_PERMISSIONS_REQUIRED.md) - Complete IAM role and policy guide

### Infrastructure as Code
- [CloudFormation Template](cloudformation/compliance-checker-role.yaml) - Deploy IAM role with CloudFormation
- [Terraform Module](terraform/compliance-checker-role.tf) - Deploy IAM role with Terraform

### Helper Scripts
- [setup.sh](setup.sh) - Initial Python environment setup
- [run_compliance_check.sh](run_compliance_check.sh) - Main execution wrapper script
- [setup-iam-role.sh](setup-iam-role.sh) - Interactive IAM role setup

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

By default, this generates compliance reports for both NIST 800-53 and NIST 800-171 frameworks.

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
    -f, --format FORMAT        Report format (all, csv, markdown, json, resources)
    -w, --framework FRAMEWORK  NIST framework reports to generate (both, 800-53, 800-171) (default: both)
    -p, --parallel             Enable parallel execution (default: true)
    --workers NUM              Number of parallel workers (default: 10)
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

5. **Generate only NIST 800-53 compliance report:**

```bash
./run_compliance_check.sh -w 800-53
```

6. **Generate only NIST 800-171 compliance report:**

```bash
./run_compliance_check.sh -w 800-171
```

7. **Generate only CSV report (no markdown):**

```bash
./run_compliance_check.sh -f csv
```

8. **Download checks from a git repository:**

```bash
./run_compliance_check.sh -g "https://github.com/your-org/security-checks.git" -b "main"
```

9. **Generate resource-level report:**

```bash
./run_compliance_check.sh -f resources
```

This will generate a `resources_TIMESTAMP.csv` file with detailed compliance data for every AWS resource tested.

8. **Run checks with parallel execution (faster):**

```bash
./run_compliance_check.sh -p -w 20
```

9. **Generate NIST 800-171 specific report:**

```bash
./run_compliance_check.sh --framework nist_800_171
```

10. **Generate multi-framework compliance report:**

```bash
./run_compliance_check.sh -f multi-framework
```

## Output Reports

The tool generates multiple types of reports in the `./reports` directory:

**Default Behavior**: When you run the tool without specifying a framework, it automatically generates reports for both NIST 800-53 and NIST 800-171 frameworks.

### 1. CSV Report (`compliance_results_TIMESTAMP.csv`)

- Comprehensive tabular format with all check results
- Includes NIST 800-53 control mappings
- Contains detailed findings and affected resources
- Ideal for importing into spreadsheets or compliance management systems

### 2. Framework-Specific Reports

#### NIST 800-53 Report (`nist_800-53_compliance_report_TIMESTAMP.md`)
- Organized by NIST 800-53 control families (AC, AU, IA, etc.)
- Executive summary with compliance percentages
- Detailed findings mapped to specific controls
- Shows both passed and failed checks for each control
- Perfect for FedRAMP and government compliance

#### NIST 800-171 Report (`nist_800-171_compliance_report_TIMESTAMP.md`)
- Organized by NIST 800-171 control families (3.1 through 3.14)
- Focused on Controlled Unclassified Information (CUI) protection
- Maps checks to NIST 800-171 basic security requirements
- Essential for DoD contractors and supply chain compliance
- Ideal for defense contractors and supply chain compliance

### 3. Cross-Framework Matrix (`cross_framework_matrix_TIMESTAMP.csv`)

- Shows how each check maps to multiple frameworks
- Enables compliance reuse across different standards
- Helps identify gaps in framework coverage

### 4. JSON Summary (`compliance_summary_TIMESTAMP.json`)

- Machine-readable format with complete results
- Multi-framework control coverage statistics
- Evidence packages for automated processing
- Suitable for API integration

### 5. Resource-level CSV Report (`resources_TIMESTAMP.csv`)

- Lists every AWS resource tested
- Shows compliance status per resource
- Tracks which checks were run on each resource
- Essential for asset inventory and audit trails

### 6. Evidence Summary (`evidence_summary_TIMESTAMP.json`)

- Audit-ready evidence packages
- Organized by critical controls
- Includes timestamps and check details
- Designed for compliance auditors

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

### Resource-level CSV Fields

- `resource_type`: Type of AWS resource (e.g., S3 Bucket, EC2 Volume, Security Group)
- `arn`: ARN or resource ID
- `status`: COMPLIANT, NON_COMPLIANT, or ERROR
- `compliance_score`: Percentage of checks passed
- `total_checks`, `passed_checks`, `failed_checks`, `error_checks`: Check counts
- `checks`: List of checks run on this resource
- `findings`: Detailed findings for this resource
- `date_checked`: Timestamp
- `account_id`, `region`: AWS account and region

## Architecture Overview

### Modular Design
The tool now features a modular architecture for better scalability:

```
security_checks/
├── base/                    # Base classes for all checks
├── checks/                  # Modular check implementations
│   ├── iam/                # Identity and access checks
│   ├── storage/            # S3, EBS, EFS checks
│   ├── network/            # VPC, security group checks
│   ├── database/           # RDS, DynamoDB checks
│   └── compute/            # EC2, Lambda, ECS checks
├── mappings/               # Framework mapping files
└── enhanced_checks_config.json  # Check configurations
```

### Parallel Execution Engine
- Intelligent service-based scheduling
- Rate limiting to avoid API throttling
- Progress tracking with estimated completion time
- Batch execution for large environments

### Multi-Framework Support
Each check can map to multiple compliance frameworks:
- NIST 800-53 Rev 5
- NIST 800-171 Rev 2
- CIS AWS Foundations Benchmark
- MITRE ATT&CK Framework
- OWASP Cloud Security
- AWS Well-Architected Framework
- NIST Cybersecurity Framework (CSF)
- CSA Cloud Controls Matrix
- SANS Top 20 Controls
- Zero Trust Architecture

## Extending the Tool

### Adding New Security Checks

1. Create a new check module in the appropriate category:
```python
# security_checks/checks/storage/new_s3_check.py
from security_checks.base import BaseSecurityCheck

class NewS3Check(BaseSecurityCheck):
    @property
    def check_id(self):
        return "CHECK-XXX"
    
    @property
    def frameworks(self):
        return {
            "nist_800_53": ["SC-28"],
            "nist_800_171": ["3.13.11"],
            "cis_aws": ["2.1.x"]
        }
```

2. Add check configuration to `enhanced_checks_config.json`
3. Map to all relevant compliance frameworks

### Adding New Frameworks

1. Add framework definition to `security_checks/mappings/frameworks.json`
2. Create control mappings file (e.g., `iso_27001_mappings.json`)
3. Update check configurations with new framework mappings

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
        "sts:GetCallerIdentity",
        "kms:List*",
        "kms:Describe*",
        "kms:GetKeyRotationStatus",
        "lambda:List*",
        "lambda:Get*",
        "eks:List*",
        "eks:Describe*",
        "ecs:List*",
        "ecs:Describe*",
        "elasticache:Describe*",
        "dynamodb:List*",
        "dynamodb:Describe*",
        "sns:List*",
        "sns:Get*",
        "sqs:List*",
        "sqs:Get*",
        "cloudwatch:Describe*",
        "cloudwatch:List*",
        "guardduty:List*",
        "guardduty:Get*",
        "inspector2:List*",
        "securityhub:Get*",
        "securityhub:List*",
        "ssm:List*",
        "ssm:Describe*",
        "backup:List*",
        "backup:Describe*",
        "logs:Describe*",
        "elasticloadbalancing:Describe*",
        "apigateway:GET",
        "cloudformation:List*",
        "cloudformation:Describe*",
        "athena:List*",
        "athena:Get*",
        "glue:Get*",
        "kinesis:List*",
        "kinesis:Describe*",
        "kafka:List*",
        "kafka:Describe*",
        "appsync:List*",
        "appsync:Get*",
        "docdb:Describe*",
        "neptune:Describe*",
        "redshift:Describe*",
        "events:List*",
        "events:Describe*",
        "states:List*",
        "states:Describe*",
        "efs:Describe*",
        "ecr:Describe*",
        "ecr:GetRepositoryPolicy",
        "wafv2:List*",
        "wafv2:Get*",
        "cloudfront:List*",
        "cloudfront:Get*",
        "secretsmanager:List*",
        "secretsmanager:Describe*"
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

## Test and Credential Conventions

- **AWS credentials** should be stored in a `.env` file (gitignored) for local development and testing.
- **Tests** should be placed in the `test/` folder and configured to load credentials from `.env`.

## License

This is a proof-of-concept tool for demonstration purposes.

## Contributing

To contribute to this POC:

1. Add new security checks in `aws_connector.py`
2. Update the checks configuration in `checks_config.json`
3. Ensure proper NIST control mappings
4. Test thoroughly before submitting changes
