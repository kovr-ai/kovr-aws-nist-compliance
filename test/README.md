# Test Scripts

This directory contains test and verification scripts for the AWS NIST Compliance Checker.

## Scripts

### System Verification
- `verify_system.sh` - Verifies Python installation, dependencies, and system configuration
- `test_run.sh` - Runs a small subset of checks to verify basic functionality

## Running Tests

```bash
# Verify system setup
./test/verify_system.sh

# Run a quick test with 5 checks
./test/test_run.sh

# Run with test credentials from .env
cd test
source ../.env
./test_run.sh
```

## Python Tests

For development tests, see the `development/tests/` directory which contains:
- Unit test scripts
- Integration test scripts
- Performance test scripts
- Report generation tests