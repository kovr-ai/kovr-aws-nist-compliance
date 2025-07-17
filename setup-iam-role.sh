#!/bin/bash
# Setup IAM role for AWS NIST Compliance Checker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
ROLE_NAME="AWSNISTComplianceChecker"
STACK_NAME="aws-nist-compliance-checker-role"

echo -e "${GREEN}AWS NIST Compliance Checker - IAM Role Setup${NC}"
echo "============================================="

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    echo "Please install AWS CLI: https://aws.amazon.com/cli/"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    echo "Please configure AWS credentials using 'aws configure'"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "us-east-1")

echo -e "\n${YELLOW}Current AWS Account:${NC} $ACCOUNT_ID"
echo -e "${YELLOW}Region:${NC} $REGION"

# Menu
echo -e "\n${GREEN}Select setup method:${NC}"
echo "1) Quick setup with AWS managed policies (Recommended)"
echo "2) Setup with custom least-privilege policy"
echo "3) Deploy using CloudFormation"
echo "4) Generate Terraform configuration"
echo "5) Exit"

read -p "Enter your choice [1-5]: " choice

case $choice in
    1)
        echo -e "\n${GREEN}Setting up with AWS managed policies...${NC}"
        
        # Create trust policy
        cat > /tmp/trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
        
        # Create role
        echo "Creating IAM role..."
        aws iam create-role \
            --role-name $ROLE_NAME \
            --assume-role-policy-document file:///tmp/trust-policy.json \
            --description "Role for AWS NIST Compliance Checker" 2>/dev/null || \
            echo -e "${YELLOW}Role already exists, continuing...${NC}"
        
        # Attach policies
        echo "Attaching SecurityAudit policy..."
        aws iam attach-role-policy \
            --role-name $ROLE_NAME \
            --policy-arn arn:aws:iam::aws:policy/SecurityAudit
        
        echo "Attaching ViewOnlyAccess policy..."
        aws iam attach-role-policy \
            --role-name $ROLE_NAME \
            --policy-arn arn:aws:iam::aws:policy/ViewOnlyAccess
        
        # Create instance profile
        echo "Creating instance profile..."
        aws iam create-instance-profile \
            --instance-profile-name ${ROLE_NAME}-InstanceProfile 2>/dev/null || \
            echo -e "${YELLOW}Instance profile already exists, continuing...${NC}"
        
        aws iam add-role-to-instance-profile \
            --instance-profile-name ${ROLE_NAME}-InstanceProfile \
            --role-name $ROLE_NAME 2>/dev/null || true
        
        echo -e "\n${GREEN}✓ Setup complete!${NC}"
        echo -e "\n${YELLOW}Role ARN:${NC} arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
        echo -e "${YELLOW}Instance Profile ARN:${NC} arn:aws:iam::${ACCOUNT_ID}:instance-profile/${ROLE_NAME}-InstanceProfile"
        
        # Cleanup
        rm -f /tmp/trust-policy.json
        ;;
        
    2)
        echo -e "\n${GREEN}Setting up with custom least-privilege policy...${NC}"
        echo -e "${YELLOW}Note: This requires the custom policy from IAM_PERMISSIONS_REQUIRED.md${NC}"
        echo "Please create the custom policy manually and attach it to the role."
        echo -e "\n${YELLOW}Role name to use:${NC} $ROLE_NAME"
        ;;
        
    3)
        echo -e "\n${GREEN}Deploying CloudFormation stack...${NC}"
        
        if [ ! -f "cloudformation/compliance-checker-role.yaml" ]; then
            echo -e "${RED}Error: CloudFormation template not found${NC}"
            echo "Please ensure you're running this from the project root directory"
            exit 1
        fi
        
        echo "Creating CloudFormation stack..."
        aws cloudformation create-stack \
            --stack-name $STACK_NAME \
            --template-body file://cloudformation/compliance-checker-role.yaml \
            --capabilities CAPABILITY_NAMED_IAM \
            --parameters ParameterKey=RoleName,ParameterValue=$ROLE_NAME \
            --region $REGION
        
        echo -e "\n${YELLOW}Stack creation initiated!${NC}"
        echo "Monitor progress with:"
        echo "  aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION"
        echo ""
        echo "Or in the AWS Console:"
        echo "  https://console.aws.amazon.com/cloudformation/home?region=${REGION}#/stacks"
        ;;
        
    4)
        echo -e "\n${GREEN}Terraform configuration${NC}"
        echo "The Terraform configuration is available at: terraform/compliance-checker-role.tf"
        echo ""
        echo "To deploy with Terraform:"
        echo "  cd terraform"
        echo "  terraform init"
        echo "  terraform plan"
        echo "  terraform apply"
        ;;
        
    5)
        echo "Exiting..."
        exit 0
        ;;
        
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

# Show how to use the role
echo -e "\n${GREEN}How to use the role:${NC}"
echo ""
echo "1. From an EC2 instance:"
echo "   - Launch instance with instance profile: ${ROLE_NAME}-InstanceProfile"
echo ""
echo "2. From your local machine:"
echo "   aws sts assume-role \\"
echo "     --role-arn arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME} \\"
echo "     --role-session-name compliance-check"
echo ""
echo "3. With the compliance checker:"
echo "   export AWS_ROLE_ARN=arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo "   ./run_compliance_check.sh"