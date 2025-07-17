#!/bin/bash

# Script to package the AWS NIST Compliance application for distribution
# Creates a clean zip file with only user-facing files

set -e

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# Define package name and timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PACKAGE_NAME="kovr-aws-nist-compliance_${TIMESTAMP}.zip"
TEMP_DIR="kovr-aws-nist-compliance"
DIST_DIR="dist"

# Create dist directory if it doesn't exist
mkdir -p "$DIST_DIR"

# Clean up any existing temp directory
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

echo "Creating distribution package..."

# Copy source code
echo "Copying source code..."
mkdir -p "$TEMP_DIR/src"
cp -r src/*.py "$TEMP_DIR/src/"

# Copy security checks
echo "Copying security checks..."
mkdir -p "$TEMP_DIR/security_checks"
cp -r security_checks/base "$TEMP_DIR/security_checks/"
cp -r security_checks/checks "$TEMP_DIR/security_checks/"
cp security_checks/checks_config.json "$TEMP_DIR/security_checks/"
cp security_checks/enhanced_checks_config.json "$TEMP_DIR/security_checks/"
cp -r security_checks/mappings "$TEMP_DIR/security_checks/"
# Explicitly exclude backup/original config files
rm -f "$TEMP_DIR/security_checks/*_original.json" 2>/dev/null || true
rm -f "$TEMP_DIR/security_checks/complete_*.json" 2>/dev/null || true

# Copy root-level mappings directory if it exists
if [ -d "mappings" ]; then
    echo "Copying mappings..."
    mkdir -p "$TEMP_DIR/mappings"
    cp -r mappings/* "$TEMP_DIR/mappings/"
fi

# Copy user-facing scripts
echo "Copying scripts..."
cp run_compliance_check.sh "$TEMP_DIR/"
cp setup-iam-role.sh "$TEMP_DIR/"

# Copy infrastructure templates
echo "Copying infrastructure templates..."
if [ -d "cloudformation" ]; then
    mkdir -p "$TEMP_DIR/cloudformation"
    cp -r cloudformation/*.yaml "$TEMP_DIR/cloudformation/" 2>/dev/null || true
    cp -r cloudformation/*.yml "$TEMP_DIR/cloudformation/" 2>/dev/null || true
fi

if [ -d "terraform" ]; then
    mkdir -p "$TEMP_DIR/terraform"
    cp -r terraform/*.tf "$TEMP_DIR/terraform/" 2>/dev/null || true
fi

# Copy requirements
echo "Copying requirements..."
cp requirements.txt "$TEMP_DIR/"

# Copy user documentation
echo "Copying user documentation..."
cp README.md "$TEMP_DIR/"
cp LICENSE "$TEMP_DIR/"

# Copy setup documentation
if [ -d "docs/setup" ]; then
    mkdir -p "$TEMP_DIR/docs/setup"
    cp -r docs/setup/* "$TEMP_DIR/docs/setup/"
fi

# Copy example files
echo "Copying examples..."
mkdir -p "$TEMP_DIR/examples"
cp examples/example-usage.py "$TEMP_DIR/examples/"

# Copy test scripts for verification
echo "Copying test scripts..."
if [ -d "test" ]; then
    mkdir -p "$TEMP_DIR/test"
    # Only copy shell scripts and documentation, not Python test files
    cp test/*.sh "$TEMP_DIR/test/" 2>/dev/null || true
    cp test/README.md "$TEMP_DIR/test/" 2>/dev/null || true
fi

# Copy .gitignore
echo "Copying .gitignore..."
cp .gitignore "$TEMP_DIR/"

# Create reports directory (empty)
mkdir -p "$TEMP_DIR/reports"

# Create .env.example file
cat > "$TEMP_DIR/.env.example" << 'EOF'
# Example AWS credentials file
# Copy this to .env and fill in your values
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1
EOF

# Create the zip file
echo "Creating zip file: $DIST_DIR/$PACKAGE_NAME"
zip -r "$DIST_DIR/$PACKAGE_NAME" "$TEMP_DIR" -x "*.pyc" -x "*__pycache__*" -x "*.DS_Store"

# Clean up temp directory
rm -rf "$TEMP_DIR"

# Calculate file size
FILE_SIZE=$(ls -lh "$DIST_DIR/$PACKAGE_NAME" | awk '{print $5}')

echo ""
echo "✅ Package created successfully!"
echo "📦 File: $DIST_DIR/$PACKAGE_NAME"
echo "📏 Size: $FILE_SIZE"
echo ""
echo "Contents:"
echo "- Source code (src/)"
echo "- Security checks (security_checks/)"
echo "- Infrastructure templates (cloudformation/, terraform/)"
echo "- Setup and run scripts (run_compliance_check.sh, setup-iam-role.sh)"
echo "- User documentation (README.md, docs/setup/)"
echo "- Example usage scripts (examples/)"
echo "- Test verification scripts (test/*.sh)"
echo "- Requirements file"
echo "- License"
echo "- .gitignore"
echo "- .env.example"
echo ""
echo "Not included (development artifacts):"
echo "- development/"
echo "- docs/development/"
echo "- .claude/"
echo "- .git/"
echo "- Python test files (test/*.py)"
echo "- Original/backup config files (*_original.json)"
echo "- Pre-commit configuration"
echo "- .DS_Store files"
echo "- __pycache__ directories"