# CLI Reference Guide

## Overview

The AWS NIST Compliance Checker provides a comprehensive command-line interface for running security compliance checks across your AWS infrastructure, with support for both NIST 800-53 and NIST 800-171 frameworks.

## Basic Usage

```bash
./run_compliance_check.sh [OPTIONS]
```

## Command Line Options

### Authentication Options

| Option | Short | Environment Variable | Description |
|--------|-------|---------------------|-------------|
| `--access-key` | `-k` | `AWS_ACCESS_KEY_ID` | AWS Access Key ID |
| `--secret-key` | `-s` | `AWS_SECRET_ACCESS_KEY` | AWS Secret Access Key |
| `--session-token` | `-t` | `AWS_SESSION_TOKEN` | AWS Session Token (for temporary credentials) |
| `--region` | `-r` | `AWS_DEFAULT_REGION` | AWS Region (default: us-east-1) |

### Execution Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--parallel` | `-p` | `true` | Enable parallel execution for faster scans |
| `--workers` | `-w` | `10` | Number of parallel workers (1-30) |
| `--no-parallel` | | | Disable parallel execution |

### Check Selection Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--checks` | `-c` | Run specific check IDs only | `-c "CHECK-001,CHECK-002"` |
| `--skip-checks` | `-x` | Skip specific check IDs | `-x "CHECK-013,CHECK-050"` |
| `--severity` | `-l` | Minimum severity level | `-l HIGH` |

**Severity Levels:**
- `CRITICAL` - Immediate action required
- `HIGH` - Should be addressed soon
- `MEDIUM` - Plan to address
- `LOW` - Consider addressing

### Report Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `-f` | `all` | Report format to generate |
| `--output-dir` | `-o` | `./reports` | Output directory for reports |
| `--framework` | `-w` | `both` | NIST framework reports to generate |

**Report Formats:**
- `all` - Generate all report types
- `csv` - CSV with check results and NIST 800-53 mappings
- `markdown` - Human-readable markdown reports (separate for each NIST framework)
- `json` - Machine-readable JSON summary
- `resources` - Resource-level compliance CSV

**Framework Options:**
- `both` - Generate reports for both NIST 800-53 and 800-171 (default)
- `800-53` - Generate only NIST 800-53 Rev 5 report
- `800-171` - Generate only NIST 800-171 Rev 2 report

### Git Integration Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--git-repo` | `-g` | | Git repository URL for custom checks |
| `--git-branch` | `-b` | `main` | Git branch to use |

### Other Options

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Show help message and exit |

## Examples

### Basic Examples

```bash
# Run all checks with default settings (generates both NIST 800-53 and 800-171 reports)
./run_compliance_check.sh

# Run with specific AWS credentials
./run_compliance_check.sh -k "AKIAIOSFODNN7EXAMPLE" -s "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Run in specific region
./run_compliance_check.sh -r us-west-2
```

### Performance Optimization

```bash
# Fast scan with 20 parallel workers
./run_compliance_check.sh -p -w 20

# Run only high-severity checks with parallel execution
./run_compliance_check.sh -l HIGH -p -w 20

# Disable parallel execution for debugging
./run_compliance_check.sh --no-parallel
```

### Check Selection

```bash
# Run specific checks only
./run_compliance_check.sh -c "CHECK-001,CHECK-002,CHECK-005"

# Skip time-consuming checks
./run_compliance_check.sh -x "CHECK-019,CHECK-050"

# Run only critical severity checks
./run_compliance_check.sh -l CRITICAL
```

### Framework-Specific Reports

```bash
# Generate both NIST framework reports (default behavior)
./run_compliance_check.sh

# Generate NIST 800-53 report only
./run_compliance_check.sh -w 800-53

# Generate NIST 800-171 report only for CUI compliance
./run_compliance_check.sh -w 800-171

# Generate both frameworks with specific format
./run_compliance_check.sh -w both -f markdown
```

### Service-Specific Scans

```bash
# IAM security assessment
./run_compliance_check.sh -c "CHECK-001,CHECK-002,CHECK-009,CHECK-010,CHECK-011,CHECK-032,CHECK-033,CHECK-048"

# Data encryption compliance
./run_compliance_check.sh -c "CHECK-006,CHECK-007,CHECK-014,CHECK-023,CHECK-026,CHECK-027,CHECK-028"

# Database security audit
./run_compliance_check.sh -c "CHECK-014,CHECK-027,CHECK-035,CHECK-043,CHECK-050,CHECK-059,CHECK-060"
```

### Custom Output

```bash
# Generate only CSV report in custom directory
./run_compliance_check.sh -f csv -o ./audit-reports

# Generate resource-level compliance report
./run_compliance_check.sh -f resources

# Generate all report formats for both NIST frameworks
./run_compliance_check.sh -f all -w both
```

### Git Integration

```bash
# Use custom checks from git repository
./run_compliance_check.sh -g "https://github.com/org/security-checks.git" -b "production"
```

## Environment Variables

You can set these environment variables to avoid passing credentials on the command line:

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # Optional
export AWS_DEFAULT_REGION="us-east-1"
```

Or use a `.env` file in the project root:

```
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_SESSION_TOKEN=your-session-token
AWS_DEFAULT_REGION=us-east-1
```

## Exit Codes

- `0` - All checks passed
- `1` - One or more checks failed
- `2` - Error occurred during execution

## Performance Considerations

### Parallel Execution

- Default: 10 workers
- Recommended: 15-20 workers for most environments
- Maximum: 30 workers (may cause API throttling)

### Execution Time Estimates

| Scan Type | Checks | Regions | Serial Time | Parallel Time (20 workers) |
|-----------|--------|---------|-------------|---------------------------|
| Quick | 10 | 1 | ~2 min | ~30 sec |
| Standard | 60 | 1 | ~10 min | ~2 min |
| Full | 60 | All (20) | ~180 min | ~15 min |

### Memory Usage

- Base: ~100 MB
- Per worker: ~50 MB
- Total (20 workers): ~1.1 GB

## Advanced Usage

### Scheduled Scans (Cron)

```bash
# Daily high-priority scan at 2 AM
0 2 * * * cd /path/to/compliance-checker && ./run_compliance_check.sh -l HIGH -p -w 20 -f csv

# Weekly comprehensive scan on Sundays
0 3 * * 0 cd /path/to/compliance-checker && ./run_compliance_check.sh -p -w 30 -f all
```

### CI/CD Integration

```bash
#!/bin/bash
# ci-compliance-check.sh

# Run critical checks and fail build on violations
./run_compliance_check.sh -l CRITICAL -p -w 20 -f json -o ./ci-reports

# Check exit code
if [ $? -ne 0 ]; then
    echo "Critical compliance violations found!"
    exit 1
fi
```

### Multi-Account Scanning

```bash
#!/bin/bash
# scan-all-accounts.sh

ACCOUNTS=(
    "prod:PROD_ACCESS_KEY:PROD_SECRET_KEY"
    "staging:STAGE_ACCESS_KEY:STAGE_SECRET_KEY"
    "dev:DEV_ACCESS_KEY:DEV_SECRET_KEY"
)

for account in "${ACCOUNTS[@]}"; do
    IFS=':' read -r name access_key secret_key <<< "$account"
    echo "Scanning $name account..."
    ./run_compliance_check.sh -k "$access_key" -s "$secret_key" -l HIGH -o "./reports/$name"
done
```

## Troubleshooting

### Common Issues

1. **"Command not found"**
   ```bash
   chmod +x run_compliance_check.sh
   ```

2. **"No module named 'boto3'"**
   ```bash
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **"Access Denied" errors**
   - Check IAM permissions (see README.md)
   - Verify credentials are correct
   - Ensure region is correct

4. **Slow performance**
   - Enable parallel execution: `-p -w 20`
   - Run fewer checks: `-l HIGH`
   - Target specific regions: `-r us-east-1`

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
./run_compliance_check.sh

# Run single check for debugging
./run_compliance_check.sh -c "CHECK-001" --no-parallel
```

## See Also

- [README.md](../README.md) - Project overview and setup
- [quickstart.md](../quickstart.md) - Quick start guide
- [CLAUDE.md](../CLAUDE.md) - Architecture documentation