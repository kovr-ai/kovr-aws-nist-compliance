# Batch 1 Security Checks Summary

Total checks: 20

## Checks by Category:

### Access Control (4 checks)
- **CHECK-055**: Privileged Access Management (CRITICAL)
  - NIST: AC-2, AC-6
  - Primary Framework: CSA CCM v4
- **CHECK-056**: Least Privilege Analysis (HIGH)
  - NIST: AC-3, AC-6
  - Primary Framework: Zero Trust
- **CHECK-057**: Service Control Policies (HIGH)
  - NIST: AC-3, CM-7
  - Primary Framework: AWS Well-Architected
- **CHECK-058**: Session Manager Configuration (MEDIUM)
  - NIST: AC-17, AU-2
  - Primary Framework: Zero Trust

### Configuration Management (2 checks)
- **CHECK-059**: Resource Tagging Compliance (LOW)
  - NIST: CM-8, PM-5
  - Primary Framework: AWS Well-Architected
- **CHECK-060**: CloudFormation Drift Detection (MEDIUM)
  - NIST: CM-3, CM-6
  - Primary Framework: AWS Well-Architected

### Incident Response (4 checks)
- **CHECK-048**: Incident Response Plan Testing (MEDIUM)
  - NIST: IR-3
  - Primary Framework: NIST CSF
- **CHECK-049**: Automated Incident Response (HIGH)
  - NIST: IR-4
  - Primary Framework: AWS Security Best Practices
- **CHECK-050**: Security Event Correlation (HIGH)
  - NIST: IR-4, SI-4
  - Primary Framework: MITRE ATT&CK
- **CHECK-051**: Forensic Data Collection (MEDIUM)
  - NIST: IR-5
  - Primary Framework: NIST SP 800-86

### Risk Assessment (3 checks)
- **CHECK-052**: Threat Intelligence Integration (MEDIUM)
  - NIST: RA-3
  - Primary Framework: MITRE ATT&CK
- **CHECK-053**: Risk Assessment Automation (MEDIUM)
  - NIST: RA-5
  - Primary Framework: NIST CSF
- **CHECK-054**: Supply Chain Risk Management (HIGH)
  - NIST: RA-3, SA-12
  - Primary Framework: NIST SP 800-161

### System and Information Integrity (7 checks)
- **CHECK-041**: EC2 Malware Protection (HIGH)
  - NIST: SI-3
  - Primary Framework: MITRE ATT&CK
- **CHECK-042**: Automated Vulnerability Remediation (HIGH)
  - NIST: SI-2
  - Primary Framework: CIS Benchmark
- **CHECK-043**: CloudWatch Logs Integration (MEDIUM)
  - NIST: SI-4
  - Primary Framework: AWS Well-Architected
- **CHECK-044**: Security Function Verification (MEDIUM)
  - NIST: SI-6
  - Primary Framework: NIST CSF
- **CHECK-045**: Software Integrity Verification (HIGH)
  - NIST: SI-7
  - Primary Framework: CIS Benchmark
- **CHECK-046**: Container Image Scanning (HIGH)
  - NIST: SI-3, SI-7
  - Primary Framework: OWASP
- **CHECK-047**: Data Loss Prevention (HIGH)
  - NIST: SI-4, SC-7
  - Primary Framework: CSA CCM v4

## AWS Services Used:
accessanalyzer, cloudformation, codeartifact, config, ec2, ecr, events, guardduty, iam, logs, macie, organizations, resourcegroupstaggingapi, securityhub, ssm

## Framework Coverage:
- CSA CCM v4: 20 checks
- SANS Top 20: 20 checks
- Zero Trust: 20 checks
- NIST CSF: 18 checks
- AWS Security Hub: 16 checks
- MITRE ATT&CK: 12 checks
- AWS Well-Architected: 8 checks
- CIS Benchmark: 2 checks
- OWASP: 1 checks
- AWS Security Best Practices: 1 checks
- NIST SP 800-86: 1 checks
- NIST SP 800-161: 1 checks
