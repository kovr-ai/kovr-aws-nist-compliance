# Example Git Repository Structure for Custom Security Checks

# This shows how to structure a git repository that can be used with the -g option

custom-security-checks/
├── README.md
├── security_checks/
│   └── checks_config.json         # Custom check definitions
├── mappings/
│   └── nist_800_53_mappings.json  # Extended NIST mappings
└── custom_checks/
    ├── __init__.py
    ├── lambda_checks.py            # Custom Lambda security checks
    ├── eks_checks.py              # Custom EKS security checks
    └── advanced_s3_checks.py      # Advanced S3 security checks

# Example custom checks_config.json with additional checks

{
  "security_checks": [
    {
      "id": "CUSTOM-001",
      "name": "Lambda Function URL Authentication",
      "description": "Ensure Lambda function URLs require authentication",
      "category": "Serverless Security",
      "framework": "Custom Security Framework",
      "severity": "HIGH",
      "nist_mappings": ["AC-3", "SC-7"],
      "service": "lambda",
      "check_function": "check_lambda_url_auth"
    },
    {
      "id": "CUSTOM-002",
      "name": "EKS Cluster Public Endpoint",
      "description": "Ensure EKS clusters do not have public API endpoints",
      "category": "Container Security",
      "framework": "Kubernetes Security Benchmark",
      "severity": "HIGH",
      "nist_mappings": ["SC-7", "AC-3"],
      "service": "eks",
      "check_function": "check_eks_public_endpoint"
    },
    {
      "id": "CUSTOM-003",
      "name": "S3 Object Lock Configuration",
      "description": "Ensure critical S3 buckets have Object Lock enabled",
      "category": "Data Protection",
      "framework": "Data Governance Framework",
      "severity": "MEDIUM",
      "nist_mappings": ["AU-9", "SC-28"],
      "service": "s3",
      "check_function": "check_s3_object_lock"
    }
  ]
}

# Example custom check implementation (lambda_checks.py)

"""
def check_lambda_url_auth(self) -> List[Dict[str, Any]]:
    '''Check if Lambda function URLs require authentication.'''
    findings = []
    try:
        lambda_client = self.aws.get_client('lambda')

        # List all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']

                try:
                    # Check if function has URL config
                    url_config = lambda_client.get_function_url_config(
                        FunctionName=function_name
                    )

                    # Check if auth type is NONE (public)
                    if url_config['AuthType'] == 'NONE':
                        findings.append({
                            'type': 'PUBLIC_LAMBDA_URL',
                            'resource': function['FunctionArn'],
                            'details': f'Lambda function {function_name} has public URL without authentication'
                        })

                except lambda_client.exceptions.ResourceNotFoundException:
                    # Function doesn't have URL config, which is fine
                    pass

    except Exception as e:
        logger.error(f'Error checking Lambda URLs: {str(e)}')

    return findings
"""
