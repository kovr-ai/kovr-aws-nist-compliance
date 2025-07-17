#!/bin/bash
# Setup script for AWS NIST 800-53 Compliance Checker

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Setting up AWS NIST 800-53 Compliance Checker...${NC}"

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Found Python $PYTHON_VERSION"

# Make scripts executable
chmod +x run_compliance_check.sh
chmod +x src/main.py

# Create virtual environment
echo -e "${YELLOW}Creating Python virtual environment...${NC}"
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Deactivate virtual environment
deactivate

echo -e "${GREEN}✓ Setup complete!${NC}"
echo
echo "To run compliance checks:"
echo "  1. Set AWS credentials:"
echo "     export AWS_ACCESS_KEY_ID='your-key'"
echo "     export AWS_SECRET_ACCESS_KEY='your-secret'"
echo "     export AWS_SESSION_TOKEN='your-token' # Optional"
echo
echo "  2. Run the compliance checker:"
echo "     ./run_compliance_check.sh"
echo
echo "For more options, run: ./run_compliance_check.sh --help"
