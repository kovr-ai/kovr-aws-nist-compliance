# IAM Role and Permissions Required for AWS NIST Compliance Checker

## Overview
This document outlines the IAM role and permissions required to run the AWS NIST Compliance Checker. The tool performs read-only security assessments across multiple AWS services.

## IAM Role Trust Policy

```json
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
        "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Required IAM Policies

### Option 1: AWS Managed Policies (Recommended for Quick Setup)

Attach these AWS managed policies to your IAM role:

1. **SecurityAudit** - Provides read-only access to security configuration
2. **ViewOnlyAccess** - Provides read-only access to all AWS services

### Option 2: Custom Policy (Least Privilege)

Create a custom policy with the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CoreSecurityServices",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:SimulateCustomPolicy",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ComputeServices",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:Get*",
        "ecs:Describe*",
        "ecs:List*",
        "eks:Describe*",
        "eks:List*",
        "lambda:Get*",
        "lambda:List*",
        "lightsail:Get*",
        "batch:Describe*",
        "batch:List*",
        "autoscaling:Describe*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "StorageServices",
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:Describe*",
        "ebs:Describe*",
        "efs:Describe*",
        "glacier:Get*",
        "glacier:List*",
        "glacier:Describe*",
        "fsx:Describe*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DatabaseServices",
      "Effect": "Allow",
      "Action": [
        "rds:Describe*",
        "rds:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "dynamodb:Get*",
        "elasticache:Describe*",
        "elasticache:List*",
        "redshift:Describe*",
        "redshift:View*",
        "docdb:Describe*",
        "docdb:List*",
        "neptune:Describe*",
        "neptune:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "NetworkingServices",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:Describe*",
        "elbv2:Describe*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "wafv2:Get*",
        "wafv2:List*",
        "wafv2:Describe*",
        "shield:Get*",
        "shield:List*",
        "shield:Describe*",
        "directconnect:Describe*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityServices",
      "Effect": "Allow",
      "Action": [
        "guardduty:Get*",
        "guardduty:List*",
        "inspector2:Get*",
        "inspector2:List*",
        "inspector2:BatchGetAccountStatus",
        "securityhub:Get*",
        "securityhub:List*",
        "securityhub:Describe*",
        "macie2:Get*",
        "macie2:List*",
        "access-analyzer:Get*",
        "access-analyzer:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LoggingMonitoring",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudtrail:Describe*",
        "cloudtrail:LookupEvents",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "logs:Describe*",
        "logs:Get*",
        "logs:List*",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ManagementGovernance",
      "Effect": "Allow",
      "Action": [
        "config:Get*",
        "config:List*",
        "config:Describe*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudformation:DetectStackDrift",
        "cloudformation:DetectStackResourceDrift",
        "ssm:Get*",
        "ssm:List*",
        "ssm:Describe*",
        "backup:Get*",
        "backup:List*",
        "backup:Describe*",
        "organizations:Describe*",
        "organizations:List*",
        "controltower:Describe*",
        "controltower:List*",
        "ram:Get*",
        "ram:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EncryptionServices",
      "Effect": "Allow",
      "Action": [
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "secretsmanager:Get*",
        "secretsmanager:List*",
        "secretsmanager:Describe*",
        "acm:Describe*",
        "acm:Get*",
        "acm:List*",
        "cloudhsm:Describe*",
        "cloudhsm:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IntegrationServices",
      "Effect": "Allow",
      "Action": [
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*",
        "events:Describe*",
        "events:List*",
        "states:Describe*",
        "states:List*",
        "states:Get*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AnalyticsServices",
      "Effect": "Allow",
      "Action": [
        "athena:Get*",
        "athena:List*",
        "athena:BatchGet*",
        "glue:Get*",
        "glue:List*",
        "glue:BatchGet*",
        "kinesis:Describe*",
        "kinesis:Get*",
        "kinesis:List*",
        "kafka:Describe*",
        "kafka:Get*",
        "kafka:List*",
        "emr:Describe*",
        "emr:List*",
        "emr:Get*",
        "lakeformation:Get*",
        "lakeformation:List*",
        "lakeformation:Describe*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "APIServices",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "appsync:Get*",
        "appsync:List*",
        "amplify:Get*",
        "amplify:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ContainerServices",
      "Effect": "Allow",
      "Action": [
        "ecr:Get*",
        "ecr:List*",
        "ecr:Describe*",
        "ecr:BatchGet*",
        "apprunner:Describe*",
        "apprunner:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "MLServices",
      "Effect": "Allow",
      "Action": [
        "sagemaker:Describe*",
        "sagemaker:List*",
        "sagemaker:Get*",
        "comprehend:Describe*",
        "comprehend:List*",
        "forecast:Describe*",
        "forecast:List*",
        "personalize:Describe*",
        "personalize:List*",
        "polly:Describe*",
        "polly:List*",
        "textract:Get*",
        "textract:List*",
        "translate:Get*",
        "translate:List*",
        "lex:Describe*",
        "lex:List*",
        "lex:Get*",
        "lexv2:Describe*",
        "lexv2:List*",
        "lexv2:Get*",
        "kendra:Describe*",
        "kendra:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OtherServices",
      "Effect": "Allow",
      "Action": [
        "workspaces:Describe*",
        "cognito:Describe*",
        "cognito:List*",
        "cognito:Get*",
        "mediastore:Get*",
        "mediastore:List*",
        "mediaconvert:Get*",
        "mediaconvert:List*",
        "elastictranscoder:List*",
        "elastictranscoder:Read*",
        "datasync:Describe*",
        "datasync:List*",
        "transfer:Describe*",
        "transfer:List*",
        "migrationhub:Describe*",
        "migrationhub:List*",
        "gamelift:Describe*",
        "gamelift:List*",
        "gamelift:Get*",
        "robomaker:Describe*",
        "robomaker:List*",
        "iot:Describe*",
        "iot:List*",
        "iot:Get*",
        "iotanalytics:Describe*",
        "iotanalytics:List*",
        "iotanalytics:Get*",
        "groundstation:Describe*",
        "groundstation:List*",
        "groundstation:Get*",
        "braket:Get*",
        "braket:Search*",
        "qldb:Describe*",
        "qldb:List*",
        "qldb:Get*",
        "managedblockchain:List*",
        "managedblockchain:Get*",
        "outposts:Get*",
        "outposts:List*",
        "ce:Get*",
        "ce:Describe*",
        "ce:List*",
        "resource-groups:Get*",
        "resource-groups:List*",
        "tag:Get*",
        "service-quotas:Get*",
        "service-quotas:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Creating the IAM Role

### Using AWS CLI

```bash
# Create the assume role policy document
cat > trust-policy.json << EOF
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
        "AWS": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create the IAM role
aws iam create-role \
  --role-name AWSNISTComplianceChecker \
  --assume-role-policy-document file://trust-policy.json \
  --description "Role for AWS NIST Compliance Checker"

# Attach AWS managed policies (Option 1)
aws iam attach-role-policy \
  --role-name AWSNISTComplianceChecker \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-role-policy \
  --role-name AWSNISTComplianceChecker \
  --policy-arn arn:aws:iam::aws:policy/ViewOnlyAccess

# OR create and attach custom policy (Option 2)
aws iam create-policy \
  --policy-name AWSNISTComplianceCheckerPolicy \
  --policy-document file://custom-policy.json \
  --description "Custom policy for AWS NIST Compliance Checker"

aws iam attach-role-policy \
  --role-name AWSNISTComplianceChecker \
  --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AWSNISTComplianceCheckerPolicy
```

### Using AWS Console

1. Navigate to IAM Console
2. Click "Roles" → "Create role"
3. Select "AWS account" as trusted entity type
4. Enter your account ID
5. Name the role "AWSNISTComplianceChecker"
6. Attach policies:
   - SecurityAudit
   - ViewOnlyAccess
   OR
   - Create and attach the custom policy above

## Using the Role

### From EC2 Instance
1. Launch EC2 instance with the IAM role attached
2. Run the compliance checker - it will use the instance profile

### From Local Machine or CI/CD
```bash
# Assume the role
aws sts assume-role \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/AWSNISTComplianceChecker \
  --role-session-name compliance-check-session

# Export the temporary credentials
export AWS_ACCESS_KEY_ID=<AssumedRoleAccessKeyId>
export AWS_SECRET_ACCESS_KEY=<AssumedRoleSecretAccessKey>
export AWS_SESSION_TOKEN=<AssumedRoleSessionToken>

# Run the compliance checker
./run_compliance_check.sh
```

### In GitHub Actions
```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v1
  with:
    role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/AWSNISTComplianceChecker
    aws-region: us-east-1

- name: Run compliance check
  run: ./run_compliance_check.sh
```

## Security Best Practices

1. **Use IAM Roles** instead of IAM Users when possible
2. **Enable MFA** for users who can assume this role
3. **Use External ID** for cross-account access
4. **Enable CloudTrail** to audit role usage
5. **Review and rotate** credentials regularly
6. **Restrict role assumption** to specific principals
7. **Use SCPs** in AWS Organizations for additional controls

## Troubleshooting

### Common Permission Errors

1. **"Access Denied" for specific service**
   - Ensure the service actions are included in the policy
   - Check if the service requires region-specific permissions

2. **"Invalid token" errors**
   - Ensure session token is exported if using temporary credentials
   - Check if credentials have expired

3. **"Not authorized to perform sts:AssumeRole"**
   - Verify the trust policy includes your principal
   - Check if MFA is required for role assumption

## Notes

- This tool performs **read-only** operations
- No data is modified or deleted
- All API calls are logged in CloudTrail
- The tool respects AWS API rate limits
- Multi-region checks require permissions in all regions