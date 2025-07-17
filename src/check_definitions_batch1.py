#!/usr/bin/env python3
"""Definitions for security checks batch 1 (CHECK-041 to CHECK-060)."""

BATCH_1_CHECKS = [
    # CHECK-041
    {
        'name': 'EC2 Malware Protection',
        'description': 'Ensure EC2 instances have malware protection enabled',
        'detailed_description': 'This check verifies that EC2 instances have appropriate malware protection solutions deployed. Malware protection is essential for preventing, detecting, and responding to malicious software that could compromise system integrity or data confidentiality.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'MITRE ATT&CK', 'version': 'v12', 'control': 'T1204'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'IVS-07', 'mapping': 'Malicious Code Protection'},
                {'name': 'SANS Top 20', 'control': 'Control 8', 'mapping': 'Malware Defenses'},
                {'name': 'AWS Security Hub', 'control': 'EC2.26', 'mapping': 'Anti-malware protection should be enabled'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Continuous threat monitoring'},
                {'name': 'NIST CSF', 'control': 'DE.CM-4', 'mapping': 'Malicious code is detected'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['SI-3'],
        'service': 'ssm',
        'type': 'compliance',
        'remediation': {
            'text': 'Deploy anti-malware solutions like AWS GuardDuty, CrowdStrike, or Trend Micro on all EC2 instances.',
            'url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-compliance.html'
        }
    },
    
    # CHECK-042
    {
        'name': 'Automated Vulnerability Remediation',
        'description': 'Ensure automated vulnerability scanning and remediation is configured',
        'detailed_description': 'This check verifies that automated vulnerability scanning and remediation processes are in place. Automated remediation helps quickly address security vulnerabilities before they can be exploited, reducing the window of exposure.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'CIS Benchmark', 'version': 'v8', 'control': '7.4'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'TVM-04', 'mapping': 'Vulnerability Scanning'},
                {'name': 'SANS Top 20', 'control': 'Control 7', 'mapping': 'Continuous Vulnerability Management'},
                {'name': 'AWS Security Hub', 'control': 'SSM.2', 'mapping': 'Instances should have patch compliance status'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Automated security response'},
                {'name': 'NIST CSF', 'control': 'RS.MI-3', 'mapping': 'Newly identified vulnerabilities are mitigated'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['SI-2'],
        'service': 'ssm',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable AWS Inspector for continuous vulnerability scanning and integrate with Systems Manager for automated patching.',
            'url': 'https://docs.aws.amazon.com/inspector/latest/user/findings-understanding-automating-remediations.html'
        }
    },
    
    # CHECK-043
    {
        'name': 'CloudWatch Logs Integration',
        'description': 'Ensure all critical services send logs to CloudWatch',
        'detailed_description': 'This check verifies that all critical AWS services and applications are configured to send logs to CloudWatch Logs for centralized monitoring and analysis. Comprehensive logging is essential for security monitoring, troubleshooting, and compliance.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'AWS Well-Architected', 'version': 'Security Pillar', 'control': 'SEC04'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'LOG-01', 'mapping': 'Logging and Monitoring'},
                {'name': 'SANS Top 20', 'control': 'Control 6', 'mapping': 'Log Management'},
                {'name': 'AWS Security Hub', 'control': 'CloudWatch.1', 'mapping': 'Log group retention period should be at least 1 year'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Comprehensive visibility'},
                {'name': 'NIST CSF', 'control': 'DE.AE-3', 'mapping': 'Event data are collected from multiple sources'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['SI-4'],
        'service': 'logs',
        'type': 'compliance',
        'remediation': {
            'text': 'Configure all EC2 instances, containers, and Lambda functions to send logs to CloudWatch Logs.',
            'url': 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html'
        }
    },
    
    # CHECK-044
    {
        'name': 'Security Function Verification',
        'description': 'Ensure security functions are verified to be operating correctly',
        'detailed_description': 'This check verifies that critical security functions are regularly tested and verified to ensure they are operating as expected. This includes testing of security controls, incident response procedures, and backup/recovery processes.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'NIST CSF', 'version': '1.1', 'control': 'PR.IP-1'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'GRM-09', 'mapping': 'Security Testing'},
                {'name': 'SANS Top 20', 'control': 'Control 18', 'mapping': 'Penetration Testing'},
                {'name': 'AWS Security Hub', 'control': 'Config.1', 'mapping': 'AWS Config should be enabled'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Continuous verification'},
                {'name': 'MITRE ATT&CK', 'control': 'Multiple', 'mapping': 'Detection validation'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['SI-6'],
        'service': 'config',
        'type': 'compliance',
        'remediation': {
            'text': 'Implement regular testing of security controls using AWS Config rules and custom Lambda functions.',
            'url': 'https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html'
        }
    },
    
    # CHECK-045
    {
        'name': 'Software Integrity Verification',
        'description': 'Ensure software and firmware integrity is verified',
        'detailed_description': 'This check verifies that mechanisms are in place to validate the integrity of software and firmware. This includes checking for unauthorized modifications, ensuring software comes from trusted sources, and validating digital signatures.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'CIS Benchmark', 'version': 'v8', 'control': '2.5'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'CCC-05', 'mapping': 'Change Detection'},
                {'name': 'SANS Top 20', 'control': 'Control 2', 'mapping': 'Inventory of Software Assets'},
                {'name': 'AWS Security Hub', 'control': 'SSM.3', 'mapping': 'Instances should have association compliance status'},
                {'name': 'Zero Trust', 'control': 'Section 3.2', 'mapping': 'Supply chain security'},
                {'name': 'MITRE ATT&CK', 'control': 'T1195', 'mapping': 'Supply Chain Compromise'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['SI-7'],
        'service': 'ssm',
        'type': 'compliance',
        'remediation': {
            'text': 'Use AWS Systems Manager to validate software inventory and implement file integrity monitoring.',
            'url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-inventory.html'
        }
    },
    
    # CHECK-046
    {
        'name': 'Container Image Scanning',
        'description': 'Ensure container images are scanned for vulnerabilities',
        'detailed_description': 'This check verifies that all container images are scanned for vulnerabilities before deployment. Container scanning helps identify security issues, outdated packages, and misconfigurations in container images.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'OWASP', 'version': 'Container Security', 'control': 'CS-2'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'AIS-05', 'mapping': 'Application Vulnerability Scanning'},
                {'name': 'SANS Top 20', 'control': 'Control 7', 'mapping': 'Continuous Vulnerability Management'},
                {'name': 'AWS Security Hub', 'control': 'ECR.1', 'mapping': 'ECR repositories should have image scanning enabled'},
                {'name': 'Zero Trust', 'control': 'Section 3.2', 'mapping': 'Container security'},
                {'name': 'NIST CSF', 'control': 'ID.RA-1', 'mapping': 'Asset vulnerabilities are identified'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['SI-3', 'SI-7'],
        'service': 'ecr',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable image scanning in Amazon ECR and integrate with CI/CD pipelines for automated scanning.',
            'url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html'
        }
    },
    
    # CHECK-047
    {
        'name': 'Data Loss Prevention',
        'description': 'Ensure DLP controls are implemented for sensitive data',
        'detailed_description': 'This check verifies that Data Loss Prevention (DLP) controls are implemented to prevent unauthorized data exfiltration. This includes monitoring for sensitive data patterns, blocking unauthorized transfers, and alerting on suspicious activities.',
        'category': 'System and Information Integrity',
        'frameworks': {
            'primary': {'name': 'CSA CCM v4', 'version': '4.0', 'control': 'DSI-06'},
            'additional': [
                {'name': 'SANS Top 20', 'control': 'Control 13', 'mapping': 'Data Protection'},
                {'name': 'AWS Security Hub', 'control': 'Macie.1', 'mapping': 'Amazon Macie should be enabled'},
                {'name': 'Zero Trust', 'control': 'Section 3.2', 'mapping': 'Data-centric security'},
                {'name': 'NIST CSF', 'control': 'PR.DS-5', 'mapping': 'Protections against data leaks'},
                {'name': 'MITRE ATT&CK', 'control': 'T1041', 'mapping': 'Exfiltration Over C2 Channel'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['SI-4', 'SC-7'],
        'service': 'macie',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable Amazon Macie for sensitive data discovery and implement VPC endpoint policies to control data movement.',
            'url': 'https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html'
        }
    },
    
    # CHECK-048
    {
        'name': 'Incident Response Plan Testing',
        'description': 'Ensure incident response plans are regularly tested',
        'detailed_description': 'This check verifies that incident response plans are documented, up-to-date, and regularly tested through tabletop exercises or simulations. Regular testing ensures teams are prepared to respond effectively to security incidents.',
        'category': 'Incident Response',
        'frameworks': {
            'primary': {'name': 'NIST CSF', 'version': '1.1', 'control': 'RS.RP-1'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'SEF-04', 'mapping': 'Incident Response Testing'},
                {'name': 'SANS Top 20', 'control': 'Control 17', 'mapping': 'Incident Response Management'},
                {'name': 'AWS Well-Architected', 'control': 'SEC10', 'mapping': 'Prepare for incidents'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Incident response readiness'},
                {'name': 'MITRE ATT&CK', 'control': 'Multiple', 'mapping': 'Response planning'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['IR-3'],
        'service': 'organizations',
        'type': 'compliance',
        'remediation': {
            'text': 'Document incident response procedures and conduct regular testing using AWS incident response simulations.',
            'url': 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
        }
    },
    
    # CHECK-049
    {
        'name': 'Automated Incident Response',
        'description': 'Ensure automated incident response capabilities are configured',
        'detailed_description': 'This check verifies that automated incident response mechanisms are in place to quickly respond to security events. This includes automated remediation, isolation of compromised resources, and notification of security teams.',
        'category': 'Incident Response',
        'frameworks': {
            'primary': {'name': 'AWS Security Best Practices', 'version': '2022', 'control': 'IR-2'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'SEF-05', 'mapping': 'Incident Response Automation'},
                {'name': 'SANS Top 20', 'control': 'Control 17', 'mapping': 'Incident Response Management'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Automated response'},
                {'name': 'NIST CSF', 'control': 'RS.MI-2', 'mapping': 'Incidents are mitigated'},
                {'name': 'MITRE ATT&CK', 'control': 'Multiple', 'mapping': 'Automated detection and response'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['IR-4'],
        'service': 'events',
        'type': 'compliance',
        'remediation': {
            'text': 'Configure EventBridge rules with Lambda functions for automated incident response actions.',
            'url': 'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html'
        }
    },
    
    # CHECK-050
    {
        'name': 'Security Event Correlation',
        'description': 'Ensure security events are correlated across services',
        'detailed_description': 'This check verifies that security events from multiple sources are correlated to identify complex attack patterns. Event correlation helps detect sophisticated attacks that may not be apparent from individual events.',
        'category': 'Incident Response',
        'frameworks': {
            'primary': {'name': 'MITRE ATT&CK', 'version': 'v12', 'control': 'Multiple'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'LOG-09', 'mapping': 'Log Correlation'},
                {'name': 'SANS Top 20', 'control': 'Control 6', 'mapping': 'Log Management'},
                {'name': 'AWS Security Hub', 'control': 'SecurityHub.1', 'mapping': 'Security Hub should be enabled'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Holistic monitoring'},
                {'name': 'NIST CSF', 'control': 'DE.AE-3', 'mapping': 'Event data are correlated'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['IR-4', 'SI-4'],
        'service': 'securityhub',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable Security Hub with custom insights and integrate with SIEM solutions for advanced correlation.',
            'url': 'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-insights.html'
        }
    },
    
    # CHECK-051
    {
        'name': 'Forensic Data Collection',
        'description': 'Ensure forensic data collection capabilities are configured',
        'detailed_description': 'This check verifies that mechanisms are in place to collect and preserve forensic data during security incidents. This includes memory dumps, disk snapshots, and detailed logs that can be used for investigation.',
        'category': 'Incident Response',
        'frameworks': {
            'primary': {'name': 'NIST SP 800-86', 'version': 'Rev 1', 'control': 'Collection'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'SEF-03', 'mapping': 'Forensic Collection'},
                {'name': 'SANS Top 20', 'control': 'Control 17', 'mapping': 'Incident Response Management'},
                {'name': 'AWS Well-Architected', 'control': 'SEC10', 'mapping': 'Incident investigation'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Evidence collection'},
                {'name': 'MITRE ATT&CK', 'control': 'Multiple', 'mapping': 'Detection artifacts'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['IR-5'],
        'service': 'ec2',
        'type': 'compliance',
        'remediation': {
            'text': 'Configure EBS snapshot automation and enable VPC Flow Logs for forensic analysis capabilities.',
            'url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-snapshots.html'
        }
    },
    
    # CHECK-052
    {
        'name': 'Threat Intelligence Integration',
        'description': 'Ensure threat intelligence feeds are integrated',
        'detailed_description': 'This check verifies that threat intelligence feeds are integrated into security monitoring systems. Threat intelligence helps identify known malicious indicators and provides context for security events.',
        'category': 'Risk Assessment',
        'frameworks': {
            'primary': {'name': 'MITRE ATT&CK', 'version': 'v12', 'control': 'Intelligence'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'TVM-08', 'mapping': 'Threat Intelligence'},
                {'name': 'SANS Top 20', 'control': 'Control 8', 'mapping': 'Malware Defenses'},
                {'name': 'AWS Security Hub', 'control': 'GuardDuty.1', 'mapping': 'GuardDuty should be enabled'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Threat awareness'},
                {'name': 'NIST CSF', 'control': 'ID.RA-2', 'mapping': 'Threat intelligence is received'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['RA-3'],
        'service': 'guardduty',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable GuardDuty threat intelligence and integrate custom threat lists for enhanced detection.',
            'url': 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload_lists.html'
        }
    },
    
    # CHECK-053
    {
        'name': 'Risk Assessment Automation',
        'description': 'Ensure automated risk assessments are performed',
        'detailed_description': 'This check verifies that automated risk assessment processes are in place to continuously evaluate security posture. Automated assessments help identify new risks and prioritize remediation efforts.',
        'category': 'Risk Assessment',
        'frameworks': {
            'primary': {'name': 'NIST CSF', 'version': '1.1', 'control': 'ID.RA-1'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'GRM-02', 'mapping': 'Risk Assessments'},
                {'name': 'SANS Top 20', 'control': 'Control 1', 'mapping': 'Inventory and Control'},
                {'name': 'AWS Security Hub', 'control': 'SecurityHub.1', 'mapping': 'Continuous assessment'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Continuous risk evaluation'},
                {'name': 'AWS Well-Architected', 'control': 'SEC01', 'mapping': 'Risk assessment'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['RA-5'],
        'service': 'securityhub',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable Security Hub compliance standards and configure custom security scores for risk tracking.',
            'url': 'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html'
        }
    },
    
    # CHECK-054
    {
        'name': 'Supply Chain Risk Management',
        'description': 'Ensure supply chain risks are assessed and managed',
        'detailed_description': 'This check verifies that supply chain risk management processes are in place for third-party services and dependencies. This includes assessing vendor security, monitoring for vulnerabilities in dependencies, and maintaining software bill of materials.',
        'category': 'Risk Assessment',
        'frameworks': {
            'primary': {'name': 'NIST SP 800-161', 'version': 'Rev 1', 'control': 'SCRM'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'STA-02', 'mapping': 'Supply Chain Security'},
                {'name': 'SANS Top 20', 'control': 'Control 2', 'mapping': 'Software Inventory'},
                {'name': 'Zero Trust', 'control': 'Section 3.2', 'mapping': 'Supply chain security'},
                {'name': 'MITRE ATT&CK', 'control': 'T1195', 'mapping': 'Supply Chain Compromise'},
                {'name': 'NIST CSF', 'control': 'ID.SC-1', 'mapping': 'Cyber supply chain risk management'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['RA-3', 'SA-12'],
        'service': 'codeartifact',
        'type': 'compliance',
        'remediation': {
            'text': 'Use AWS CodeArtifact for dependency management and enable vulnerability scanning in CI/CD pipelines.',
            'url': 'https://docs.aws.amazon.com/codeartifact/latest/ug/welcome.html'
        }
    },
    
    # CHECK-055
    {
        'name': 'Privileged Access Management',
        'description': 'Ensure privileged access is properly managed and monitored',
        'detailed_description': 'This check verifies that privileged access management (PAM) controls are implemented. This includes just-in-time access, session recording, and monitoring of privileged activities.',
        'category': 'Access Control',
        'frameworks': {
            'primary': {'name': 'CSA CCM v4', 'version': '4.0', 'control': 'IAM-08'},
            'additional': [
                {'name': 'SANS Top 20', 'control': 'Control 4', 'mapping': 'Controlled Use of Admin Privileges'},
                {'name': 'Zero Trust', 'control': 'Section 3.1', 'mapping': 'Privileged access controls'},
                {'name': 'AWS Security Hub', 'control': 'IAM.21', 'mapping': 'IAM policies should not allow admin access'},
                {'name': 'NIST CSF', 'control': 'PR.AC-4', 'mapping': 'Access permissions are managed'},
                {'name': 'MITRE ATT&CK', 'control': 'T1078', 'mapping': 'Valid Accounts'}
            ]
        },
        'severity': 'CRITICAL',
        'nist_mappings': ['AC-2', 'AC-6'],
        'service': 'iam',
        'type': 'compliance',
        'remediation': {
            'text': 'Implement AWS SSO with temporary elevated access and enable CloudTrail for privileged action monitoring.',
            'url': 'https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html'
        }
    },
    
    # CHECK-056
    {
        'name': 'Least Privilege Analysis',
        'description': 'Ensure IAM policies follow least privilege principle',
        'detailed_description': 'This check verifies that IAM policies grant only the minimum permissions required for users and services to perform their functions. Regular analysis helps identify and remove excessive permissions.',
        'category': 'Access Control',
        'frameworks': {
            'primary': {'name': 'Zero Trust', 'version': 'NIST SP 800-207', 'control': 'Section 3.1'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'IAM-02', 'mapping': 'Least Privilege'},
                {'name': 'SANS Top 20', 'control': 'Control 4', 'mapping': 'Controlled Use of Admin Privileges'},
                {'name': 'AWS Security Hub', 'control': 'IAM.1', 'mapping': 'IAM policies should not allow * actions'},
                {'name': 'NIST CSF', 'control': 'PR.AC-4', 'mapping': 'Access permissions are managed'},
                {'name': 'AWS Well-Architected', 'control': 'SEC03', 'mapping': 'Grant least privilege'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['AC-3', 'AC-6'],
        'service': 'accessanalyzer',
        'type': 'compliance',
        'remediation': {
            'text': 'Use IAM Access Analyzer to identify and remove unused permissions from policies.',
            'url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html'
        }
    },
    
    # CHECK-057
    {
        'name': 'Service Control Policies',
        'description': 'Ensure SCPs are used to enforce organizational policies',
        'detailed_description': 'This check verifies that Service Control Policies (SCPs) are implemented at the organization level to prevent actions that violate security policies. SCPs provide preventive guardrails across all accounts.',
        'category': 'Access Control',
        'frameworks': {
            'primary': {'name': 'AWS Well-Architected', 'version': 'Security Pillar', 'control': 'SEC01'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'GRM-06', 'mapping': 'Policy Enforcement'},
                {'name': 'SANS Top 20', 'control': 'Control 1', 'mapping': 'Inventory and Control'},
                {'name': 'Zero Trust', 'control': 'Section 3.1', 'mapping': 'Policy enforcement'},
                {'name': 'NIST CSF', 'control': 'PR.AC-4', 'mapping': 'Access permissions are managed'},
                {'name': 'AWS Security Hub', 'control': 'Organizations.1', 'mapping': 'SCPs should be used'}
            ]
        },
        'severity': 'HIGH',
        'nist_mappings': ['AC-3', 'CM-7'],
        'service': 'organizations',
        'type': 'compliance',
        'remediation': {
            'text': 'Implement SCPs to prevent high-risk actions like disabling CloudTrail or deleting backups.',
            'url': 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html'
        }
    },
    
    # CHECK-058
    {
        'name': 'Session Manager Configuration',
        'description': 'Ensure Session Manager is configured for secure access',
        'detailed_description': 'This check verifies that AWS Systems Manager Session Manager is properly configured for secure remote access to EC2 instances. Session Manager provides auditable access without requiring SSH keys or bastion hosts.',
        'category': 'Access Control',
        'frameworks': {
            'primary': {'name': 'Zero Trust', 'version': 'NIST SP 800-207', 'control': 'Section 3.1'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'IAM-09', 'mapping': 'Remote Access'},
                {'name': 'SANS Top 20', 'control': 'Control 4', 'mapping': 'Controlled Admin Access'},
                {'name': 'AWS Security Hub', 'control': 'SSM.1', 'mapping': 'EC2 instances should be managed by SSM'},
                {'name': 'NIST CSF', 'control': 'PR.AC-5', 'mapping': 'Network integrity is protected'},
                {'name': 'MITRE ATT&CK', 'control': 'T1021', 'mapping': 'Remote Services'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['AC-17', 'AU-2'],
        'service': 'ssm',
        'type': 'compliance',
        'remediation': {
            'text': 'Configure Session Manager with KMS encryption and CloudWatch logging for all sessions.',
            'url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html'
        }
    },
    
    # CHECK-059
    {
        'name': 'Resource Tagging Compliance',
        'description': 'Ensure resources are tagged according to organizational standards',
        'detailed_description': 'This check verifies that AWS resources are properly tagged for cost allocation, security classification, and compliance tracking. Consistent tagging enables better resource management and policy enforcement.',
        'category': 'Configuration Management',
        'frameworks': {
            'primary': {'name': 'AWS Well-Architected', 'version': 'Operational Excellence', 'control': 'OPS02'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'IVS-04', 'mapping': 'Asset Management'},
                {'name': 'SANS Top 20', 'control': 'Control 1', 'mapping': 'Asset Inventory'},
                {'name': 'AWS Security Hub', 'control': 'Config.1', 'mapping': 'Tagging compliance'},
                {'name': 'NIST CSF', 'control': 'ID.AM-1', 'mapping': 'Assets are identified and managed'},
                {'name': 'Zero Trust', 'control': 'Section 3.2', 'mapping': 'Asset classification'}
            ]
        },
        'severity': 'LOW',
        'nist_mappings': ['CM-8', 'PM-5'],
        'service': 'resourcegroupstaggingapi',
        'type': 'compliance',
        'remediation': {
            'text': 'Implement tag policies in Organizations and use Config rules to enforce tagging standards.',
            'url': 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_tag-policies.html'
        }
    },
    
    # CHECK-060
    {
        'name': 'CloudFormation Drift Detection',
        'description': 'Ensure infrastructure drift is detected and remediated',
        'detailed_description': 'This check verifies that CloudFormation drift detection is used to identify resources that have been modified outside of Infrastructure as Code. Drift detection helps maintain configuration consistency and security.',
        'category': 'Configuration Management',
        'frameworks': {
            'primary': {'name': 'AWS Well-Architected', 'version': 'Reliability Pillar', 'control': 'REL11'},
            'additional': [
                {'name': 'CSA CCM v4', 'control': 'CCC-03', 'mapping': 'Change Management'},
                {'name': 'SANS Top 20', 'control': 'Control 3', 'mapping': 'Data Access Control'},
                {'name': 'Zero Trust', 'control': 'Section 3.3', 'mapping': 'Configuration validation'},
                {'name': 'NIST CSF', 'control': 'PR.IP-1', 'mapping': 'Baseline configuration is maintained'},
                {'name': 'AWS Security Hub', 'control': 'CloudFormation.1', 'mapping': 'Stacks should be monitored'}
            ]
        },
        'severity': 'MEDIUM',
        'nist_mappings': ['CM-3', 'CM-6'],
        'service': 'cloudformation',
        'type': 'compliance',
        'remediation': {
            'text': 'Enable CloudFormation drift detection and create alarms for configuration changes.',
            'url': 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html'
        }
    }
] 