#!/bin/bash
# Setup script for pre-commit hooks

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Setting up pre-commit hooks for AWS NIST Compliance Checker...${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    echo -e "${YELLOW}Activating virtual environment...${NC}"
    source .venv/bin/activate
else
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv .venv
    source .venv/bin/activate
fi

# Install pre-commit
echo -e "${YELLOW}Installing pre-commit...${NC}"
pip install --upgrade pip
pip install pre-commit

# Install the git hook scripts
echo -e "${YELLOW}Installing git hooks...${NC}"
pre-commit install
pre-commit install --hook-type commit-msg

# Set up git commit template
echo -e "${YELLOW}Setting up git commit template...${NC}"
git config --local commit.template .gitmessage

# Run pre-commit on all files to check current state
echo -e "${YELLOW}Running pre-commit checks on all files...${NC}"
pre-commit run --all-files || true

echo -e "${GREEN}✓ Pre-commit setup complete!${NC}"
echo
echo "Pre-commit hooks are now active. They will run automatically on git commit."
echo "To run manually: pre-commit run --all-files"
echo
echo "Commit message format:"
echo "  <type>: <subject>"
echo "  "
echo "  <body>"
echo
echo "Types: feat, fix, docs, style, refactor, test, chore, perf, ci, build, revert"
