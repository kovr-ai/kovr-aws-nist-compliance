# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Python application that validates AWS environments for compliance with the NIST 800-53
security framework. It runs 15 pre-configured security checks from frameworks like CIS AWS
Benchmark, OWASP Cloud Security, MITRE ATT&CK, and AWS Well-Architected, mapping them to
NIST 800-53 controls.

**Project Status**: This is a proof-of-concept (POC) application that provides the core compliance
checking engine. It's a CLI-first tool that generates comprehensive reports but lacks web UI,
real-time monitoring, and database persistence.

## Common Development Commands

### Setup and Installation

```bash
# Initial setup - creates virtual environment and installs dependencies
./setup.sh

# Activate virtual environment manually
source .venv/bin/activate

# Install dependencies manually
pip install -r requirements.txt
```

### Running the Application

```bash
# Basic run (requires AWS credentials in environment)
./run_compliance_check.sh

# Run with specific AWS credentials
./run_compliance_check.sh -k "ACCESS_KEY" -s "SECRET_KEY" -r "us-west-2"

# Run specific checks only
./run_compliance_check.sh -c "CHECK-001,CHECK-002,CHECK-005"

# Run with minimum severity filter
./run_compliance_check.sh -l HIGH

# Generate only specific report format
./run_compliance_check.sh -f csv
```

### Direct Python Execution

```bash
# Run main application directly
python3 src/main.py --region us-east-1 --format all

# Run with git repository download
python3 src/main.py --git-repo "https://github.com/org/checks.git" --git-branch main
```

## Architecture Overview

### Core Components

1. **src/main.py** - Entry point with CLI interface using Click framework
2. **src/aws_connector.py** - AWS service connections and authentication
3. **src/report_generator.py** - Generates CSV, Markdown, and JSON reports
4. **src/utils.py** - Shared utilities and helper functions
5. **security_checks/checks_config.json** - Configuration for all 15 security checks
6. **mappings/nist_800_53_mappings.json** - NIST 800-53 control mappings

### Key Architecture Patterns

- **Modular Design**: Each component has a specific responsibility
- **Configuration-Driven**: Security checks are defined in JSON configuration
- **Multi-Format Output**: Reports generated in CSV, Markdown, and JSON formats
- **Git Integration**: Can download security checks from remote git repositories
- **Virtual Environment**: Uses Python virtual environment for dependency isolation

### Security Check Flow

1. Load configurations from `security_checks/checks_config.json`
2. Initialize AWS connector with credentials
3. Create SecurityCheck instance with connector
4. Filter checks based on CLI options (severity, specific checks, skip checks)
5. Run each check through the SecurityCheck.run_check() method
6. Generate reports using ReportGenerator with NIST mappings
7. Output results to reports directory

### AWS Services Checked

- **IAM**: Root account usage, MFA, password policies, access key rotation
- **S3**: Public access, encryption settings
- **EC2**: EBS encryption, security groups, instance metadata service
- **CloudTrail**: Logging enabled, log file validation
- **VPC**: Flow logs configuration
- **RDS**: Database encryption
- **Config**: Configuration compliance tracking

### Report Generation

The application generates three types of reports:

- **CSV**: Tabular format with all check results (`compliance_results_TIMESTAMP.csv`)
- **Markdown**: Detailed report organized by NIST controls (`nist_compliance_report_TIMESTAMP.md`)
- **JSON**: Machine-readable summary (`compliance_summary_TIMESTAMP.json`)

### Authentication Methods

1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
2. Command line arguments (-k, -s, -t)
3. Default AWS credentials chain (AWS CLI, instance profiles, etc.)

## Key Configuration Files

- **requirements.txt**: Python dependencies including boto3, pandas, click
- **security_checks/checks_config.json**: Defines all 15 security checks with NIST mappings
- **mappings/nist_800_53_mappings.json**: NIST 800-53 control family definitions

## Adding New Security Checks

1. Add check definition to `security_checks/checks_config.json`
2. Implement check function in `src/aws_connector.py`
3. Map check to appropriate NIST controls
4. Update documentation if needed

## Error Handling

- Uses Python logging framework for structured logging
- Exits with code 0 (success), 1 (compliance failures), or 2 (errors)
- Graceful handling of AWS API errors and permission issues
- Temporary directory cleanup for git operations

## Security Checks Implemented

The application includes 15 pre-configured security checks:

1. **CHECK-001**: IAM Root Account Usage (AC-2, AC-6)
2. **CHECK-002**: MFA on Root Account (IA-2)
3. **CHECK-003**: CloudTrail Enabled (AU-2, AU-3)
4. **CHECK-004**: CloudTrail Log Validation (AU-9)
5. **CHECK-005**: S3 Bucket Public Access (AC-3, SC-7)
6. **CHECK-006**: S3 Bucket Encryption (SC-28)
7. **CHECK-007**: EBS Volume Encryption (SC-28)
8. **CHECK-008**: Security Group SSH Access (SC-7, AC-3)
9. **CHECK-009**: IAM Password Policy (IA-5)
10. **CHECK-010**: IAM Access Key Rotation (IA-5, AC-2)
11. **CHECK-011**: Unused IAM Credentials (AC-2)
12. **CHECK-012**: EC2 IMDSv2 Enforcement (AC-3, CM-7)
13. **CHECK-013**: VPC Flow Logs (AU-2, AU-3)
14. **CHECK-014**: RDS Encryption (SC-28)
15. **CHECK-015**: Config Service Enabled (CM-2, CM-8)

## Current State vs. Original Vision

### What's Been Built ✅

- **Core Application**: Fully functional compliance checker with 15 security checks
- **Multi-region scanning**: Scans all AWS regions by default
- **NIST 800-53 mapping**: All checks mapped to appropriate controls
- **Three report formats**: CSV, Markdown, JSON outputs
- **CLI interface**: Complete command-line tool with options
- **Git integration**: Support for downloading custom checks from repositories
- **Authentication**: Multiple AWS credential methods supported

### What's Missing ❌

From the original feature document (FEA-007), these components are not implemented:

- **Web Dashboard**: No UI, only CLI
- **Real-time Monitoring**: Only on-demand scanning
- **Claude AI Integration**: Placeholder for AI-powered test generation
- **Database Storage**: No persistence, only file outputs
- **User Assignment System**: No user management
- **Scheduling Service**: No automated scheduling
- **API Layer**: Direct execution only

## Next Development Priorities

### Priority 1: Complete Standalone Script POC

1. **Expand Check Coverage**
   - Add extensive suite of AWS tests for OWASP, MITRE, CIS, and AWS Well-Architected
   - Ensure the checks provide full coverage of all NIST 800-53 controls
   - Account for longer running scripts with many more checks

2. **Enhance Reports**
   - Add detailed findings for passed checks under each control
   - Include detailed check descriptions in CSV reports
   - Improve executive summary statistics

3. **Update Documentation**
   - Ensure README and scripts match new checks and code updates

### Priority 2: Web Application Foundation

1. **API Layer** (NestJS or FastAPI)
2. **Database Integration** (PostgreSQL + TimescaleDB)
3. **Frontend Dashboard** (React)

### Priority 3: Continuous Monitoring

1. **Scheduling Service** (Cron-based execution)
2. **Real-time Updates** (WebSocket integration)

### Priority 4: AI Integration

1. **Claude Integration** for test generation and remediation recommendations

## Code Patterns to Maintain

### Check Implementation Pattern

```python
def check_[service]_[issue](self) -> List[Dict[str, Any]]:
    findings = []
    try:
        # Get AWS client
        # Paginate through resources
        # Check compliance condition
        # Add findings if non-compliant
    except Exception as e:
        logger.error(f"Error: {str(e)}")
    return findings
```

### Report Generation Pattern

- Executive summary with statistics
- Findings grouped by NIST control families
- Detailed appendix with all checks

## Known Issues/Limitations

1. **Performance**: Full scan can take 5-10 minutes for large environments
2. **Rate Limiting**: No backoff strategy implemented
3. **Error Handling**: Basic, needs improvement for production
4. **Testing**: No unit tests yet
5. **Documentation**: API documentation needed

## Integration Points for Full Application

1. **System/Entity Context**: Need multi-tenant support
2. **Compliance Module**: Bidirectional sync with compliance pages
3. **User Management**: Assignment and ownership tracking
4. **Audit Trail**: All actions logged

## Development Notes

- Virtual environment is created in `.venv/` directory
- Reports are generated in `reports/` directory with timestamps
- Supports filtering by severity levels: LOW, MEDIUM, HIGH, CRITICAL
- Can run specific checks or skip certain checks
- Supports downloading checks from git repositories for extensibility
- **Design Decision**: Consolidated checks in one file vs modular (chose consolidated for POC simplicity)
- **Read-Only**: Only assessment, no remediation actions
- **Multi-Region**: Scans all regions by default

## Code Quality and Commit Hygiene

### Pre-commit Setup

This project uses pre-commit hooks to ensure code quality. To set up:

```bash
# One-time setup
./setup-pre-commit.sh

# Manual run
pre-commit run --all-files
```

### Pre-commit Checks

The following checks run automatically before each commit:

1. **General File Checks**
   - Remove trailing whitespace
   - Fix end-of-file issues
   - Check YAML/JSON syntax
   - Detect large files (>1MB)
   - Detect AWS credentials
   - Detect private keys

2. **Python Code Quality**
   - **Black**: Code formatting (100 char line length)
   - **isort**: Import sorting
   - **flake8**: Linting and style checks
   - **mypy**: Type checking
   - **bandit**: Security vulnerability scanning

3. **Shell Scripts**
   - **shellcheck**: Bash script linting

4. **Documentation**
   - **markdownlint**: Markdown formatting

5. **Commit Messages**
   - **gitlint**: Enforce conventional commit format

### Commit Message Format

Follow the conventional commit format:

```text
<type>: <subject>

<body>

<footer>
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, semicolons, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes
- `build`: Build system changes
- `revert`: Reverting a previous commit

**Example:**

```text
feat: add CloudWatch log group encryption check

Add new security check to verify CloudWatch log groups are encrypted
at rest using KMS. Maps to NIST 800-53 control SC-28.

Fixes #42
```

### Code Style Guidelines

1. **Python**
   - Line length: 100 characters
   - Use type hints for all functions
   - Follow PEP 8 with Black formatting
   - Import order: stdlib, third-party, local

2. **Documentation**
   - All functions must have docstrings
   - Use Google-style docstrings
   - Keep README and CLAUDE.md updated

3. **Security**
   - Never commit AWS credentials
   - No hardcoded secrets
   - Use environment variables for sensitive data

```text
