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

# Copy root-level mappings directory
echo "Copying mappings..."
mkdir -p "$TEMP_DIR/mappings"
cp -r mappings/* "$TEMP_DIR/mappings/"

# Copy user-facing scripts
echo "Copying scripts..."
cp run_compliance_check.sh "$TEMP_DIR/"
cp setup.sh "$TEMP_DIR/"

# Copy requirements
echo "Copying requirements..."
cp requirements.txt "$TEMP_DIR/"

# Copy user documentation only
echo "Copying user documentation..."
cp README.md "$TEMP_DIR/"
cp quickstart.md "$TEMP_DIR/"
cp LICENSE "$TEMP_DIR/"

# Copy example files
echo "Copying examples..."
cp example-usage.py "$TEMP_DIR/"

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
echo "- Setup and run scripts"
echo "- User documentation (README.md, quickstart.md)"
echo "- Example usage script"
echo "- Requirements file"
echo "- License"
echo "- .gitignore"
echo ""
echo "Not included (development artifacts):"
echo "- CLAUDE.md"
echo "- .claude/"
echo "- .git/"
echo "- llm-docs/"
echo "- Pre-commit configuration"
echo "- Development notes"
echo "- .DS_Store files"