#!/bin/bash
# Test run with a small subset of checks

echo "Testing AWS NIST Compliance Checker with subset of checks"
echo "========================================================="

# Set test credentials if not already set
if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo "Note: AWS credentials not set. Some checks may fail."
    echo "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to test with real AWS account."
    echo ""
fi

# Run with just 5 checks to test
echo "Running checks CHECK-001 through CHECK-005..."
./run_compliance_check.sh \
    -c "CHECK-001,CHECK-002,CHECK-003,CHECK-004,CHECK-005" \
    -r "us-east-1" \
    -f "csv" \
    -p \
    --workers 5

echo ""
echo "Test complete! Check the reports/ directory for results."