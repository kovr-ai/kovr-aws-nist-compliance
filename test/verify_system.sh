#!/bin/bash
# Verify the system is working correctly

echo "AWS NIST Compliance Checker - System Verification"
echo "================================================="
echo ""

# Check Python
echo "1. Checking Python installation..."
python3 --version

# Check dependencies
echo ""
echo "2. Checking dependencies..."
python3 -c "import boto3; print(f'  ✓ boto3 {boto3.__version__}')"
python3 -c "import pandas; print(f'  ✓ pandas {pandas.__version__}')"
python3 -c "import click; print(f'  ✓ click {click.__version__}')"
python3 -c "import tqdm; print(f'  ✓ tqdm {tqdm.__version__}')" 2>/dev/null || echo "  - tqdm not installed (optional)"

# Check check loading
echo ""
echo "3. Checking security check loading..."
python3 -c "
import sys
import os
sys.path.insert(0, 'src')
from check_loader import CheckLoader
loader = CheckLoader()
checks = loader.get_all_checks()
loadable = sum(1 for c in checks if loader.get_check_class(c['id']))
print(f'  ✓ {len(checks)} total checks configured')
print(f'  ✓ {loadable} checks implemented ({loadable/len(checks)*100:.0f}%)')
" 2>/dev/null || echo "  ✗ Error loading checks"

# Check AWS credentials
echo ""
echo "4. Checking AWS credentials..."
if [ -n "$AWS_ACCESS_KEY_ID" ]; then
    echo "  ✓ AWS_ACCESS_KEY_ID is set"
else
    echo "  - AWS_ACCESS_KEY_ID not set"
fi

if [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "  ✓ AWS_SECRET_ACCESS_KEY is set"
else
    echo "  - AWS_SECRET_ACCESS_KEY not set"
fi

# Show how to run
echo ""
echo "5. System is ready! Run compliance checks with:"
echo ""
echo "   # Run all checks:"
echo "   ./run_compliance_check.sh"
echo ""
echo "   # Run specific checks:"
echo "   ./run_compliance_check.sh -c 'CHECK-001,CHECK-002,CHECK-003'"
echo ""
echo "   # Run high severity only:"
echo "   ./run_compliance_check.sh -l HIGH"
echo ""
echo "   # Run with more workers:"
echo "   ./run_compliance_check.sh -p --workers 30"
echo ""

# Test a single check if credentials are available
if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "6. Testing single check execution..."
    python3 src/main.py --checks CHECK-002 --format csv --single-region --no-parallel 2>&1 | grep -E "(Connected to AWS|Completed.*checks|ERROR)"
fi