variable "role_name" {
  description = "Name for the IAM role"
  type        = string
  default     = "AWSNISTComplianceChecker"
}

variable "external_id" {
  description = "External ID for cross-account access (optional)"
  type        = string
  default     = ""
}

variable "trusted_account_id" {
  description = "AWS Account ID that can assume this role (leave empty for same account)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Purpose     = "Compliance-Checking"
    ManagedBy   = "Terraform"
    Application = "AWS-NIST-Compliance-Checker"
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = var.trusted_account_id != "" ? var.trusted_account_id : data.aws_caller_identity.current.account_id
}

# Trust policy for the role
data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    effect = "Allow"
    
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    
    actions = ["sts:AssumeRole"]
    
    dynamic "condition" {
      for_each = var.external_id != "" ? [1] : []
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [var.external_id]
      }
    }
  }
  
  statement {
    effect = "Allow"
    
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    
    actions = ["sts:AssumeRole"]
  }
}

# IAM Role
resource "aws_iam_role" "compliance_checker" {
  name               = var.role_name
  description        = "Role for AWS NIST Compliance Checker - Read-only access to assess security compliance"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  tags               = var.tags
}

# Attach AWS managed policies
resource "aws_iam_role_policy_attachment" "security_audit" {
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
  role       = aws_iam_role.compliance_checker.name
}

resource "aws_iam_role_policy_attachment" "view_only" {
  policy_arn = "arn:aws:iam::aws:policy/ViewOnlyAccess"
  role       = aws_iam_role.compliance_checker.name
}

# Enhanced permissions policy
data "aws_iam_policy_document" "enhanced_permissions" {
  statement {
    sid    = "AdditionalSecurityServices"
    effect = "Allow"
    
    actions = [
      # Additional Inspector v2 permissions
      "inspector2:BatchGetAccountStatus",
      "inspector2:ListCoverage",
      "inspector2:ListFindings",
      
      # Additional GuardDuty permissions
      "guardduty:GetMasterAccount",
      "guardduty:ListDetectors",
      "guardduty:GetDetector",
      
      # Additional Config permissions
      "config:GetComplianceDetailsByConfigRule",
      "config:DescribeComplianceByConfigRule",
      
      # CloudFormation drift detection
      "cloudformation:DetectStackDrift",
      "cloudformation:DetectStackResourceDrift",
      "cloudformation:DescribeStackDriftDetectionStatus",
      
      # SSM compliance
      "ssm:ListComplianceItems",
      "ssm:ListResourceComplianceSummaries",
      
      # Access Analyzer
      "access-analyzer:ListAnalyzers",
      "access-analyzer:ListFindings",
      
      # Organizations (for multi-account setup)
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
    ]
    
    resources = ["*"]
  }
}

resource "aws_iam_policy" "enhanced_compliance" {
  name        = "${var.role_name}-EnhancedPermissions"
  description = "Enhanced permissions for AWS NIST Compliance Checker"
  policy      = data.aws_iam_policy_document.enhanced_permissions.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "enhanced_compliance" {
  policy_arn = aws_iam_policy.enhanced_compliance.arn
  role       = aws_iam_role.compliance_checker.name
}

# Instance profile for EC2 instances
resource "aws_iam_instance_profile" "compliance_checker" {
  name = "${var.role_name}-InstanceProfile"
  role = aws_iam_role.compliance_checker.name
  tags = var.tags
}

# Outputs
output "role_arn" {
  description = "ARN of the IAM role for compliance checking"
  value       = aws_iam_role.compliance_checker.arn
}

output "role_name" {
  description = "Name of the IAM role"
  value       = aws_iam_role.compliance_checker.name
}

output "instance_profile_arn" {
  description = "ARN of the instance profile for EC2 instances"
  value       = aws_iam_instance_profile.compliance_checker.arn
}

output "instance_profile_name" {
  description = "Name of the instance profile"
  value       = aws_iam_instance_profile.compliance_checker.name
}

output "assume_role_command" {
  description = "AWS CLI command to assume this role"
  value       = "aws sts assume-role --role-arn ${aws_iam_role.compliance_checker.arn} --role-session-name compliance-check-session"
}

output "policy_summary" {
  description = "Summary of attached policies"
  value = {
    managed_policies = [
      "SecurityAudit",
      "ViewOnlyAccess"
    ]
    custom_policies = [
      aws_iam_policy.enhanced_compliance.name
    ]
  }
}