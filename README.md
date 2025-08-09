# AWS Security Posture Advisor MCP Server

A Model Context Protocol (MCP) server that provides intelligent security insights by orchestrating multiple AWS security services for comprehensive security assessments, threat analysis, compliance monitoring, and automated remediation recommendations.

## Features

- **Comprehensive Security Assessment**: Unified view across Security Hub, GuardDuty, Config, Inspector, CloudTrail, and Macie
- **Intelligent Threat Analysis**: ML-powered correlation and attack pattern identification
- **Multi-Framework Compliance**: Support for CIS, NIST, SOC2, and PCI-DSS standards
- **Automated Remediation**: Prioritized recommendations with cost-benefit analysis
- **Incident Investigation**: Root cause analysis and attack path tracing
- **Executive Reporting**: Customizable security reports and metrics
- **Security-First Design**: Built following AWS Well-Architected Security Pillar principles
- **Enterprise Ready**: Comprehensive audit logging, error handling, and monitoring

## Quick Start

### Prerequisites

- Python 3.10 or higher
- AWS CLI configured with appropriate credentials
- AWS services enabled: Security Hub, GuardDuty (recommended: Config, Inspector)

### Installation

#### Option 1: Install from PyPI (Recommended)

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package
pip install awslabs.aws-security-posture-advisor
```

#### Option 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/awslabs/aws-security-posture-advisor-mcp
cd aws-security-posture-advisor-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .
```

#### Option 3: Using Docker

```bash
# Pull the image
docker pull awslabs/aws-security-posture-advisor:latest

# Run with AWS credentials
docker run -e AWS_REGION=us-east-1 \
           -e AWS_ACCESS_KEY_ID=your-key \
           -e AWS_SECRET_ACCESS_KEY=your-secret \
           awslabs/aws-security-posture-advisor:latest
```

### Verification

Test the installation:

```bash
# Check if the command is available
awslabs.aws-security-posture-advisor --help

# Or run directly with Python
python -m awslabs.aws_security_posture_advisor.server --help

# Test AWS connectivity
aws sts get-caller-identity
```

## Configuration

### AWS Prerequisites

Before using the server, ensure the following AWS services are enabled:

#### Required Services
- **AWS Security Hub**: Must be enabled with at least one security standard
- **AWS Identity and Access Management (IAM)**: For authentication and authorization

#### Recommended Services
- **Amazon GuardDuty**: For threat detection and behavioral analysis
- **AWS Config**: For compliance monitoring and configuration assessment
- **Amazon Inspector**: For vulnerability assessments
- **AWS CloudTrail**: For incident investigation and audit trails
- **Amazon Macie**: For data classification and privacy protection

#### Enable Services

```bash
# Enable Security Hub
aws securityhub enable-security-hub

# Enable GuardDuty
aws guardduty create-detector --enable

# Enable Config (requires S3 bucket and IAM role)
aws configservice put-configuration-recorder \
    --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/config-role

# Enable Inspector v2
aws inspector2 enable --resource-types ECR EC2
```

### AWS Credentials Configuration

The server supports multiple AWS credential mechanisms following boto3 standards:

#### Option 1: AWS Profile (Recommended for Development)

```bash
# Configure AWS profile
aws configure --profile security-advisor
AWS Access Key ID [None]: AKIA...
AWS Secret Access Key [None]: ...
Default region name [None]: us-east-1
Default output format [None]: json

# Set environment variable
export AWS_SECURITY_ADVISOR_PROFILE_NAME=security-advisor
```

#### Option 2: IAM Roles (Recommended for Production)

For EC2, ECS, Lambda, or other AWS services:

```bash
# No additional configuration needed
# The server will automatically use the attached IAM role
export AWS_REGION=us-east-1
```

#### Option 3: Environment Variables

```bash
# Temporary credentials (recommended)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...  # For temporary credentials
export AWS_REGION=us-east-1

# Or long-term credentials (not recommended for production)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

### Environment Variables

#### Core Configuration

```bash
# AWS Configuration
export AWS_REGION=us-east-1                                    # AWS region to operate in
export AWS_SECURITY_ADVISOR_PROFILE_NAME=your-profile          # AWS profile name (optional)

# Server Configuration
export AWS_SECURITY_ADVISOR_READ_ONLY=true                     # Enable read-only mode (default: true)
export AWS_SECURITY_ADVISOR_AUDIT_LOGGING=true                 # Enable audit logging (default: true)
export FASTMCP_LOG_LEVEL=INFO                                  # Log level (DEBUG, INFO, WARNING, ERROR)
```

#### Advanced Configuration

```bash
# Performance Configuration
export AWS_SECURITY_ADVISOR_MAX_CONCURRENT=10                  # Max concurrent AWS API calls
export AWS_SECURITY_ADVISOR_TIMEOUT=300                        # Request timeout in seconds
export AWS_SECURITY_ADVISOR_MAX_RETRIES=3                      # Max retry attempts
export AWS_SECURITY_ADVISOR_BACKOFF_FACTOR=2                   # Exponential backoff factor

# Caching Configuration
export AWS_SECURITY_ADVISOR_ENABLE_CACHE=true                  # Enable response caching
export AWS_SECURITY_ADVISOR_CACHE_TTL=300                      # Cache TTL in seconds
export AWS_SECURITY_ADVISOR_CACHE_SIZE=1000                    # Max cache entries

# Logging Configuration
export AWS_SECURITY_ADVISOR_LOG_TO_FILE=true                   # Enable file logging
export AWS_SECURITY_ADVISOR_LOG_DIR=/var/log/security-advisor  # Log directory
export AWS_SECURITY_ADVISOR_LOG_ROTATION=true                  # Enable log rotation
export AWS_SECURITY_ADVISOR_LOG_MAX_SIZE=100MB                 # Max log file size

# Security Configuration
export AWS_SECURITY_ADVISOR_ENCRYPT_LOGS=true                  # Encrypt log files
export AWS_SECURITY_ADVISOR_SANITIZE_LOGS=true                 # Sanitize sensitive data in logs
export AWS_SECURITY_ADVISOR_REQUIRE_TLS=true                   # Require TLS for all connections
```

### Configuration File

Create a configuration file for persistent settings:

```bash
# Create configuration directory
mkdir -p ~/.aws-security-advisor

# Create configuration file
cat > ~/.aws-security-advisor/config.yaml << EOF
aws:
  region: us-east-1
  profile: security-advisor
  
server:
  read_only: true
  audit_logging: true
  log_level: INFO
  
performance:
  max_concurrent: 10
  timeout: 300
  enable_cache: true
  cache_ttl: 300
  
security:
  encrypt_logs: true
  sanitize_logs: true
  require_tls: true
EOF

# Set configuration file path
export AWS_SECURITY_ADVISOR_CONFIG_FILE=~/.aws-security-advisor/config.yaml
```

## Usage

### Running the Server

```bash
# Run directly
awslabs.aws-security-posture-advisor

# Or using Python module
python -m awslabs.aws_security_posture_advisor.server
```

### MCP Client Configuration

#### Kiro IDE

Add to your `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "aws-security-posture-advisor": {
      "command": "awslabs.aws-security-posture-advisor",
      "env": {
        "AWS_REGION": "us-east-1",
        "FASTMCP_LOG_LEVEL": "INFO"
      },
      "disabled": false,
      "autoApprove": ["health_check", "get_server_info"]
    }
  }
}
```

#### Cursor IDE

Add to your MCP settings:

```json
{
  "mcpServers": {
    "aws-security-posture-advisor": {
      "command": "awslabs.aws-security-posture-advisor",
      "env": {
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Available Tools

### Core Assessment Tools

- `assess_security_posture`: Comprehensive security assessment across AWS infrastructure
- `analyze_security_findings`: Intelligent threat analysis with correlation and remediation
- `check_compliance_status`: Multi-framework compliance assessment and gap analysis
- `recommend_security_improvements`: Prioritized security recommendations with ROI analysis

### Advanced Security Tools

- `investigate_security_incident`: Security incident analysis and root cause identification
- `generate_security_report`: Executive and technical security reporting
- `validate_security_controls`: Automated security control validation

### Utility Tools

- `health_check`: Server health and connectivity verification
- `get_server_info`: Detailed server capabilities and configuration

## Required IAM Permissions

The server requires the following AWS IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
        "macie2:DescribeClassificationJob",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Development

### Setup Development Environment

```bash
git clone https://github.com/awslabs/aws-security-posture-advisor-mcp
cd aws-security-posture-advisor-mcp

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
black --check .
mypy .
```

### Project Structure

```
awslabs/
├── aws_security_posture_advisor/
│   ├── __init__.py
│   ├── server.py                    # Main FastMCP server
│   ├── core/
│   │   ├── aws/                     # AWS service integrations
│   │   ├── intelligence/            # Intelligence engines
│   │   ├── common/                  # Shared utilities
│   │   └── kb/                      # Knowledge base
│   └── scripts/                     # Utility scripts
├── tests/                           # Test suite
└── docs/                           # Documentation
```

## Security Considerations

- **Read-Only by Default**: Server operates in read-only mode by default
- **Credential Security**: No long-term credentials stored; uses IAM roles and profiles
- **Audit Logging**: Comprehensive audit trail for all security operations
- **Data Sanitization**: Sensitive data automatically sanitized in logs
- **Least Privilege**: Minimal required IAM permissions

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Support

For issues and questions:

- GitHub Issues: [Report a bug or request a feature](https://github.com/awslabs/aws-security-posture-advisor-mcp/issues)
- Documentation: [Read the full documentation](https://github.com/awslabs/aws-security-posture-advisor-mcp#readme)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.