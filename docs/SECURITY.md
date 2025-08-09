# Security Best Practices Guide

## Overview

The AWS Security Posture Advisor MCP Server is designed with security-first principles following the AWS Well-Architected Security Pillar. This guide provides comprehensive security best practices for deployment, configuration, and operation of the server.

## Table of Contents

1. [Authentication and Authorization](#authentication-and-authorization)
2. [Network Security](#network-security)
3. [Data Protection](#data-protection)
4. [Logging and Monitoring](#logging-and-monitoring)
5. [Deployment Security](#deployment-security)
6. [Operational Security](#operational-security)
7. [Compliance Considerations](#compliance-considerations)
8. [Incident Response](#incident-response)

---

## Authentication and Authorization

### AWS Credential Management

#### Recommended Approach: IAM Roles

**Best Practice**: Use IAM roles instead of long-term access keys.

```bash
# For EC2 instances
# Attach IAM role to EC2 instance - no credentials needed in environment

# For ECS/Fargate
# Use task roles for container-level permissions

# For Lambda
# Use execution roles with least privilege permissions
```

#### AWS Profile Configuration

For development and testing environments:

```bash
# Configure AWS profile with least privilege
aws configure --profile security-advisor
# Set environment variable
export AWS_SECURITY_ADVISOR_PROFILE_NAME=security-advisor
```

#### Environment Variables (Not Recommended for Production)

If you must use environment variables, ensure they are properly secured:

```bash
# Use temporary credentials when possible
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...  # For temporary credentials
export AWS_REGION=us-east-1
```

### IAM Policy Design

#### Minimal Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityServicesReadOnly",
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:DescribeStandards",
        "securityhub:GetInsights",
        "guardduty:GetFindings",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "config:GetComplianceDetailsByConfigRule",
        "config:DescribeConfigRules",
        "config:GetResourceConfigHistory",
        "inspector2:ListFindings",
        "inspector2:GetFindings",
        "cloudtrail:LookupEvents",
        "macie2:GetFindings",
        "macie2:DescribeClassificationJob"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityVerification",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Network Security

### VPC Configuration

#### Private Subnet Deployment

Deploy the MCP server in private subnets:

```yaml
# CloudFormation example
SecurityAdvisorSubnet:
  Type: AWS::EC2::Subnet
  Properties:
    VpcId: !Ref VPC
    CidrBlock: 10.0.1.0/24
    MapPublicIpOnLaunch: false
    AvailabilityZone: !Select [0, !GetAZs '']
```

#### Security Groups

Restrict network access to essential ports only:

```yaml
SecurityAdvisorSecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Security group for AWS Security Posture Advisor
    VpcId: !Ref VPC
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        SourceSecurityGroupId: !Ref ClientSecurityGroup
        Description: HTTPS access from MCP clients
    SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0
        Description: HTTPS to AWS APIs
```

---

## Data Protection

### Data Classification

The MCP server handles the following data types:

| Data Type | Classification | Protection Level |
|-----------|----------------|------------------|
| AWS Security Findings | Confidential | Encrypt in transit and at rest |
| Compliance Reports | Confidential | Encrypt in transit and at rest |
| Audit Logs | Internal | Encrypt in transit and at rest |
| Configuration Data | Internal | Encrypt in transit |
| Temporary Analysis Data | Confidential | Encrypt in memory, auto-purge |

### Encryption

#### In Transit

All communications use TLS 1.3:

```python
# Environment configuration
export AWS_SECURITY_ADVISOR_TLS_VERSION=1.3
export AWS_SECURITY_ADVISOR_CIPHER_SUITES=ECDHE+AESGCM:ECDHE+CHACHA20
```

#### At Rest

Use AWS KMS for encryption at rest:

```python
# Environment configuration
export AWS_SECURITY_ADVISOR_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
export AWS_SECURITY_ADVISOR_ENCRYPT_LOGS=true
```

---

## Logging and Monitoring

### Audit Logging

#### Comprehensive Audit Trail

All security operations are logged:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "action": "assess_security_posture",
  "user_context": "arn:aws:sts::123456789012:assumed-role/SecurityAnalyst/user",
  "parameters": {
    "scope": "account",
    "target": "123456****12",
    "frameworks": ["CIS", "NIST"]
  },
  "result": "success",
  "duration_ms": 15420,
  "findings_count": 127,
  "risk_level": "MEDIUM"
}
```

---

## Deployment Security

### Container Security

#### Base Image Security

Use minimal, security-hardened base images:

```dockerfile
# Use AWS Lambda Python runtime or distroless images
FROM public.ecr.aws/lambda/python:3.11

# Or use distroless for minimal attack surface
FROM gcr.io/distroless/python3-debian11

# Avoid using latest tags
FROM python:3.11.7-slim-bullseye
```

---

## Operational Security

### Access Control

#### Role-Based Access Control (RBAC)

Implement RBAC for different user types:

```json
{
  "SecurityAnalyst": {
    "permissions": [
      "assess_security_posture",
      "analyze_security_findings",
      "check_compliance_status"
    ]
  },
  "SecurityManager": {
    "permissions": [
      "*",
      "generate_security_report"
    ]
  },
  "ReadOnlyUser": {
    "permissions": [
      "health_check",
      "get_server_info"
    ]
  }
}
```

---

## Compliance Considerations

### Regulatory Compliance

#### SOC 2 Type II

For SOC 2 compliance:

- Enable comprehensive audit logging
- Implement access controls and monitoring
- Document security procedures
- Regular security assessments

#### PCI DSS

For PCI DSS environments:

- Network segmentation
- Encrypted data transmission
- Regular vulnerability scanning
- Access logging and monitoring

#### HIPAA

For HIPAA compliance:

- Encrypt all PHI data
- Implement access controls
- Audit trail requirements
- Business Associate Agreements (BAAs)

---

## Incident Response

### Security Incident Procedures

#### Detection

Monitor for security incidents:

1. **Failed authentication attempts**
2. **Unusual API access patterns**
3. **Data exfiltration attempts**
4. **Configuration changes**
5. **Performance anomalies**

#### Response Procedures

1. **Immediate Response** (0-1 hour):
   - Isolate affected systems
   - Preserve evidence
   - Notify security team

2. **Investigation** (1-4 hours):
   - Analyze logs and audit trails
   - Determine scope of impact
   - Identify root cause

3. **Containment** (4-8 hours):
   - Implement containment measures
   - Patch vulnerabilities
   - Update security controls

4. **Recovery** (8-24 hours):
   - Restore normal operations
   - Validate security controls
   - Monitor for recurrence

---

## Security Checklist

### Pre-Deployment Checklist

- [ ] IAM roles configured with least privilege
- [ ] Network security groups properly configured
- [ ] TLS 1.3 enabled for all communications
- [ ] Encryption at rest configured
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Secrets properly managed
- [ ] Container security scanning completed
- [ ] Infrastructure as Code security validated
- [ ] Backup and recovery procedures tested

### Post-Deployment Checklist

- [ ] Health checks passing
- [ ] Audit logs flowing to centralized system
- [ ] Monitoring dashboards operational
- [ ] Security alerts configured
- [ ] Access controls validated
- [ ] Performance baselines established
- [ ] Incident response procedures tested
- [ ] Documentation updated
- [ ] Security assessment completed
- [ ] Compliance requirements validated

---

## Additional Resources

### AWS Security Documentation

- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

### Security Tools and Services

- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [AWS Config](https://aws.amazon.com/config/)
- [AWS CloudTrail](https://aws.amazon.com/cloudtrail/)
- [AWS GuardDuty](https://aws.amazon.com/guardduty/)

### Compliance Frameworks

- [CIS Controls](https://www.cisecurity.org/controls/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
- [PCI DSS](https://www.pcisecuritystandards.org/)

---

**Note**: This security guide should be regularly updated to reflect changes in the threat landscape, AWS services, and organizational security requirements.