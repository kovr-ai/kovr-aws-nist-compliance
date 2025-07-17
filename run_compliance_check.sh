#!/bin/bash
# AWS NIST 800-53 Compliance Check Script
# This script sets up and runs compliance checks against an AWS environment

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
GIT_REPO=""
GIT_BRANCH="main"
OUTPUT_DIR="./reports"
AWS_REGION="us-east-1"
VENV_DIR=".venv"

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to show usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

AWS NIST Compliance Checker (800-53 and 800-171)

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
    -f, --format FORMAT        Report format (all, csv, nist-53, nist-171, multi-framework, json)
    -w, --framework FRAMEWORK  Deprecated - use --format instead
    -p, --parallel             Enable parallel execution (default: true)
    --workers NUM              Number of parallel workers (default: 20)
    -h, --help                 Show this help message

EXAMPLES:
    # Using environment variables for AWS credentials
    export AWS_ACCESS_KEY_ID="your-key"
    export AWS_SECRET_ACCESS_KEY="your-secret"
    export AWS_SESSION_TOKEN="your-token"
    $0

    # Using command line arguments
    $0 -k "key" -s "secret" -t "token" -r "us-west-2"

    # Download checks from git and run specific checks
    $0 -g "https://github.com/org/security-checks.git" -c "CHECK-001,CHECK-002"

    # Run only high and critical severity checks
    $0 -l HIGH

EOF
}

# Parse command line arguments
TEMP=$(getopt -o k:s:t:r:g:b:o:c:x:l:f:w:ph --long access-key:,secret-key:,session-token:,region:,git-repo:,git-branch:,output-dir:,checks:,skip-checks:,severity:,format:,framework:,parallel,workers:,help -n "$0" -- "$@")
eval set -- "$TEMP"

ACCESS_KEY=""
SECRET_KEY=""
SESSION_TOKEN=""
CHECKS=""
SKIP_CHECKS=""
SEVERITY=""
FORMAT="all"
FRAMEWORK="both"
PARALLEL="--parallel"
WORKERS="20"

while true; do
    case "$1" in
        -k|--access-key)
            ACCESS_KEY="$2"
            shift 2
            ;;
        -s|--secret-key)
            SECRET_KEY="$2"
            shift 2
            ;;
        -t|--session-token)
            SESSION_TOKEN="$2"
            shift 2
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -g|--git-repo)
            GIT_REPO="$2"
            shift 2
            ;;
        -b|--git-branch)
            GIT_BRANCH="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -c|--checks)
            CHECKS="$2"
            shift 2
            ;;
        -x|--skip-checks)
            SKIP_CHECKS="$2"
            shift 2
            ;;
        -l|--severity)
            SEVERITY="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -w|--framework)
            FRAMEWORK="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="--parallel"
            shift
            ;;
        --workers)
            WORKERS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error!"
            exit 1
            ;;
    esac
done

# Header
print_message "$BLUE" "
╔═══════════════════════════════════════════════════════════╗
║             AWS NIST Compliance Checker                   ║
║            Supporting 800-53 and 800-171                  ║
║                 Bash Wrapper v1.1.0                       ║
╚═══════════════════════════════════════════════════════════╝
"

# Check for required dependencies
print_message "$YELLOW" "Checking dependencies..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    print_message "$RED" "Error: Python 3 is required but not installed."
    exit 1
fi

# Check git (if repo specified)
if [ -n "$GIT_REPO" ] && ! command -v git &> /dev/null; then
    print_message "$RED" "Error: Git is required but not installed."
    exit 1
fi

# Set up AWS credentials
if [ -n "$ACCESS_KEY" ]; then
    export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
fi
if [ -n "$SECRET_KEY" ]; then
    export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"
fi
if [ -n "$SESSION_TOKEN" ]; then
    export AWS_SESSION_TOKEN="$SESSION_TOKEN"
fi

# Verify AWS credentials are available
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    print_message "$RED" "Error: AWS credentials not found."
    print_message "$YELLOW" "Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
    print_message "$YELLOW" "or use -k and -s command line options."
    exit 1
fi

# Create reports directory
mkdir -p "$OUTPUT_DIR"

# Set up Python virtual environment
print_message "$YELLOW" "Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install required packages
print_message "$YELLOW" "Installing required Python packages..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# Build command line arguments for Python script
PYTHON_ARGS=(
    "--region" "$AWS_REGION"
    "--output-dir" "$OUTPUT_DIR"
    "--format" "$FORMAT"
    "$PARALLEL"
    "--workers" "$WORKERS"
)

if [ -n "$GIT_REPO" ]; then
    PYTHON_ARGS+=("--git-repo" "$GIT_REPO" "--git-branch" "$GIT_BRANCH")
fi

if [ -n "$SEVERITY" ]; then
    PYTHON_ARGS+=("--severity" "$SEVERITY")
fi

# Add specific checks if provided
if [ -n "$CHECKS" ]; then
    IFS=',' read -ra CHECK_ARRAY <<< "$CHECKS"
    for check in "${CHECK_ARRAY[@]}"; do
        PYTHON_ARGS+=("--checks" "$check")
    done
fi

# Add skip checks if provided
if [ -n "$SKIP_CHECKS" ]; then
    IFS=',' read -ra SKIP_ARRAY <<< "$SKIP_CHECKS"
    for skip in "${SKIP_ARRAY[@]}"; do
        PYTHON_ARGS+=("--skip-checks" "$skip")
    done
fi

# Run the compliance checker
print_message "$GREEN" "Starting compliance checks..."
python3 src/main.py "${PYTHON_ARGS[@]}"

# Check exit code
EXIT_CODE=$?

# Deactivate virtual environment
deactivate

# Print completion message
if [ $EXIT_CODE -eq 0 ]; then
    print_message "$GREEN" "✓ Compliance checks completed successfully!"
elif [ $EXIT_CODE -eq 1 ]; then
    print_message "$YELLOW" "⚠ Compliance checks completed with failures."
else
    print_message "$RED" "✗ Error occurred during compliance checks."
fi

# Show report location
print_message "$BLUE" "Reports generated in: $OUTPUT_DIR"

exit $EXIT_CODE
