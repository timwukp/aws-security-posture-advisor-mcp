# Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting information for the AWS Security Posture Advisor MCP Server. It covers common issues, diagnostic procedures, and solutions for various deployment and operational scenarios.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Installation Issues](#installation-issues)
3. [Authentication and Authorization](#authentication-and-authorization)
4. [AWS Service Integration](#aws-service-integration)
5. [Performance Issues](#performance-issues)
6. [MCP Client Integration](#mcp-client-integration)
7. [Logging and Monitoring](#logging-and-monitoring)
8. [Error Messages](#error-messages)
9. [Advanced Troubleshooting](#advanced-troubleshooting)

---

## Quick Diagnostics

### Health Check

Always start with the health check tool to verify basic functionality:

```bash
# Using MCP client
{
  "tool": "health_check"
}
```

Expected healthy response:
```json
{
  "server_name": "AWS Security Posture Advisor",
  "version": "0.1.0",
  "status": "healthy",
  "configuration": {
    "aws_region": "us-east-1",
    "log_level": "INFO",
    "read_only_mode": true
  },
  "services": {
    "mcp_server": "operational",
    "logging": "operational",
    "configuration": "operational"
  }
}
```

### Server Information

Get detailed server capabilities:

```bash
# Using MCP client
{
  "tool": "get_server_info"
}
```

### Environment Check

Verify environment configuration:

```bash
# Check environment variables
env | grep AWS_SECURITY_ADVISOR
env | grep AWS_REGION
env | grep FASTMCP_LOG_LEVEL

# Check AWS credentials
aws sts get-caller-identity

# Check Python environment
python --version
pip list | grep -E "(mcp|boto3|pydantic|loguru)"
```

---

## Installation Issues

### Package Installation Problems

#### Issue: `pip install` fails with dependency conflicts

**Symptoms:**
```
ERROR: pip's dependency resolver does not currently consider all the packages that are installed
```

**Solution:**
```bash
# Create clean virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Upgrade pip and install
pip install --upgrade pip setuptools wheel
pip install awslabs.aws-security-posture-advisor

# Or install from source
git clone https://github.com/awslabs/aws-security-posture-advisor-mcp
cd aws-security-posture-advisor-mcp
pip install -e .
```

#### Issue: Python version compatibility

**Symptoms:**
```
ERROR: Package requires Python >=3.10 but you are using Python 3.9
```

**Solution:**
```bash
# Check Python version
python --version

# Install Python 3.10+ using pyenv
pyenv install 3.11.7
pyenv local 3.11.7

# Or use conda
conda create -n security-advisor python=3.11
conda activate security-advisor
```

---

## Authentication and Authorization

### AWS Credentials Issues

#### Issue: No credentials configured

**Symptoms:**
```json
{
  "detail": "AWS credentials not configured",
  "error_type": "AuthenticationError"
}
```

**Diagnostic Steps:**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Check credential sources
aws configure list

# Check environment variables
env | grep AWS_
```

**Solutions:**

**Option 1: AWS Profile**
```bash
# Configure profile
aws configure --profile security-advisor
export AWS_SECURITY_ADVISOR_PROFILE_NAME=security-advisor
```

**Option 2: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_REGION=us-east-1
```

**Option 3: IAM Role (Recommended)**
```bash
# For EC2 instances - attach IAM role to instance
# For ECS/Fargate - use task roles
# For Lambda - use execution roles
```

#### Issue: Insufficient permissions

**Symptoms:**
```json
{
  "detail": "User: arn:aws:iam::123456789012:user/test is not authorized to perform: securityhub:GetFindings",
  "error_type": "AuthorizationError"
}
```

**Diagnostic Steps:**
```bash
# Check current identity
aws sts get-caller-identity

# Test specific permissions
aws securityhub get-findings --max-results 1
aws guardduty list-detectors
aws config describe-config-rules --max-results 1
```

**Solution:**
Apply the required IAM policy (see [Security Guide](SECURITY.md#iam-policy-design)).

---

## AWS Service Integration

### Security Hub Issues

#### Issue: Security Hub not enabled

**Symptoms:**
```json
{
  "detail": "SecurityHub is not enabled in this account/region",
  "error_type": "ServiceError"
}
```

**Diagnostic Steps:**
```bash
# Check Security Hub status
aws securityhub describe-hub

# List available standards
aws securityhub describe-standards
```

**Solution:**
```bash
# Enable Security Hub
aws securityhub enable-security-hub

# Enable standards
aws securityhub batch-enable-standards \
    --standards-subscription-requests StandardsArn=arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard/v/1.0.0
```

---

## Performance Issues

### Slow Response Times

#### Issue: Tools taking too long to respond

**Symptoms:**
- Timeouts on tool execution
- High latency in responses

**Diagnostic Steps:**
```bash
# Check server logs
tail -f /var/log/security-advisor/server.log

# Monitor AWS API calls
export AWS_SECURITY_ADVISOR_DEBUG_API_CALLS=true

# Check resource utilization
top -p $(pgrep -f security-advisor)
```

**Solutions:**

**1. Reduce scope:**
```json
{
  "tool": "assess_security_posture",
  "scope": "region",
  "target": "us-east-1",
  "severity_threshold": "HIGH"
}
```

**2. Increase timeouts:**
```bash
export AWS_SECURITY_ADVISOR_TIMEOUT=600
export AWS_SECURITY_ADVISOR_MAX_RETRIES=5
```

**3. Enable caching:**
```bash
export AWS_SECURITY_ADVISOR_ENABLE_CACHE=true
export AWS_SECURITY_ADVISOR_CACHE_TTL=300
```

---

## Error Messages

### Common Error Messages and Solutions

#### AuthenticationError: AWS credentials not configured

**Cause:** No AWS credentials found
**Solution:** Configure AWS credentials (see [Authentication section](#aws-credentials-issues))

#### ValidationError: Invalid scope 'invalid'

**Cause:** Invalid parameter value
**Solution:** Use valid values: `account`, `region`, `service`, `workload`

#### ServiceError: SecurityHub is not enabled

**Cause:** AWS Security Hub not enabled in account/region
**Solution:** Enable Security Hub in AWS console or CLI

---

## Advanced Troubleshooting

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
export FASTMCP_LOG_LEVEL=DEBUG
export AWS_SECURITY_ADVISOR_DEBUG=true
export AWS_SECURITY_ADVISOR_TRACE_API_CALLS=true
```

### Network Debugging

#### Issue: Network connectivity problems

**Diagnostic Steps:**
```bash
# Test AWS API connectivity
curl -I https://securityhub.us-east-1.amazonaws.com
curl -I https://guardduty.us-east-1.amazonaws.com

# Check DNS resolution
nslookup securityhub.us-east-1.amazonaws.com

# Test with specific endpoint
aws securityhub describe-hub --endpoint-url https://securityhub.us-east-1.amazonaws.com
```

**Solutions:**
1. Check firewall rules
2. Verify VPC endpoints configuration
3. Check proxy settings

---

## Getting Help

### Log Collection

When reporting issues, collect the following information:

```bash
#!/bin/bash
# Log collection script

echo "=== System Information ===" > debug-info.txt
uname -a >> debug-info.txt
python --version >> debug-info.txt

echo "=== Environment Variables ===" >> debug-info.txt
env | grep -E "(AWS|FASTMCP|SECURITY_ADVISOR)" >> debug-info.txt

echo "=== Package Versions ===" >> debug-info.txt
pip list | grep -E "(mcp|boto3|pydantic|loguru)" >> debug-info.txt

echo "=== AWS Configuration ===" >> debug-info.txt
aws configure list >> debug-info.txt
aws sts get-caller-identity >> debug-info.txt

echo "=== Recent Logs ===" >> debug-info.txt
tail -100 /var/log/security-advisor/server.log >> debug-info.txt

echo "=== Health Check ===" >> debug-info.txt
# Run health check and append results
```

### Support Channels

1. **GitHub Issues**: [Report bugs and feature requests](https://github.com/awslabs/aws-security-posture-advisor-mcp/issues)
2. **Documentation**: [Read the full documentation](https://github.com/awslabs/aws-security-posture-advisor-mcp#readme)
3. **AWS Support**: For AWS service-specific issues
4. **Community Forums**: AWS Developer Forums, Stack Overflow

---

This troubleshooting guide should help resolve most common issues. For complex problems or issues not covered here, please refer to the support channels listed above.