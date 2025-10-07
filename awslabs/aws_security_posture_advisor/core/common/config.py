"""Configuration management following AWS Labs patterns.

This module provides centralized configuration management for the AWS Security
Posture Advisor MCP server, following AWS Labs best practices for environment
variable handling and secure configuration.
"""

import os
from pathlib import Path
from typing import Optional
from loguru import logger


def get_server_directory() -> Path:
    """Get the server directory for logs and cache files.
    
    Returns:
        Path: Server directory path
    """
    # Follow AWS Labs pattern for server directory
    home_dir = Path.home()
    server_dir = home_dir / ".aws-security-posture-advisor"
    server_dir.mkdir(exist_ok=True)
    return server_dir


# AWS Configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_PROFILE = os.getenv('AWS_SECURITY_ADVISOR_PROFILE_NAME')

# Security Configuration
READ_ONLY_MODE = os.getenv('AWS_SECURITY_ADVISOR_READ_ONLY', 'true').lower() == 'true'
ENABLE_AUDIT_LOGGING = os.getenv('AWS_SECURITY_ADVISOR_AUDIT_LOGGING', 'true').lower() == 'true'
SANITIZE_LOGS = os.getenv('AWS_SECURITY_ADVISOR_SANITIZE_LOGS', 'true').lower() == 'true'
ENCRYPT_LOGS = os.getenv('AWS_SECURITY_ADVISOR_ENCRYPT_LOGS', 'false').lower() == 'true'
REQUIRE_TLS = os.getenv('AWS_SECURITY_ADVISOR_REQUIRE_TLS', 'true').lower() == 'true'
ENABLE_RATE_LIMITING = os.getenv('AWS_SECURITY_ADVISOR_RATE_LIMITING', 'true').lower() == 'true'
MAX_REQUEST_SIZE = int(os.getenv('AWS_SECURITY_ADVISOR_MAX_REQUEST_SIZE', '1048576'))  # 1MB default

# Logging Configuration
LOG_LEVEL = os.getenv('FASTMCP_LOG_LEVEL', 'INFO').upper()
LOG_TO_FILE = os.getenv('AWS_SECURITY_ADVISOR_LOG_TO_FILE', 'true').lower() == 'true'

# Performance Configuration
MAX_CONCURRENT_REQUESTS = int(os.getenv('AWS_SECURITY_ADVISOR_MAX_CONCURRENT', '10'))
REQUEST_TIMEOUT_SECONDS = int(os.getenv('AWS_SECURITY_ADVISOR_TIMEOUT', '300'))
CACHE_TTL_SECONDS = int(os.getenv('AWS_SECURITY_ADVISOR_CACHE_TTL', '3600'))

# Intelligence Engine Configuration
RISK_CORRELATION_ENABLED = os.getenv('AWS_SECURITY_ADVISOR_RISK_CORRELATION', 'true').lower() == 'true'
COMPLIANCE_INTELLIGENCE_ENABLED = os.getenv('AWS_SECURITY_ADVISOR_COMPLIANCE_INTEL', 'true').lower() == 'true'
REMEDIATION_ADVISOR_ENABLED = os.getenv('AWS_SECURITY_ADVISOR_REMEDIATION', 'true').lower() == 'true'

# Supported compliance frameworks
SUPPORTED_FRAMEWORKS = ['CIS', 'NIST', 'SOC2', 'PCI-DSS']

# Default assessment parameters
DEFAULT_SEVERITY_THRESHOLD = 'MEDIUM'
DEFAULT_TIME_RANGE_DAYS = 30
DEFAULT_COMPLIANCE_FRAMEWORK = 'CIS'


def validate_configuration() -> None:
    """Validate configuration settings and log warnings for potential issues."""
    
    # Validate log level
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if LOG_LEVEL not in valid_log_levels:
        logger.warning(f"Invalid log level '{LOG_LEVEL}', defaulting to INFO")
    
    # Validate AWS region format
    if not AWS_REGION or len(AWS_REGION) < 3:
        logger.warning(f"Invalid AWS region '{AWS_REGION}', may cause AWS API issues")
    
    # Validate performance settings
    if MAX_CONCURRENT_REQUESTS < 1 or MAX_CONCURRENT_REQUESTS > 100:
        logger.warning(f"MAX_CONCURRENT_REQUESTS ({MAX_CONCURRENT_REQUESTS}) should be between 1-100")
    
    if REQUEST_TIMEOUT_SECONDS < 30 or REQUEST_TIMEOUT_SECONDS > 900:
        logger.warning(f"REQUEST_TIMEOUT_SECONDS ({REQUEST_TIMEOUT_SECONDS}) should be between 30-900")
    
    # Log configuration summary (without sensitive data)
    logger.info(f"Configuration loaded - Region: {AWS_REGION}, ReadOnly: {READ_ONLY_MODE}, LogLevel: {LOG_LEVEL}")


def get_aws_profile() -> Optional[str]:
    """Get AWS profile name with validation.
    
    Returns:
        Optional[str]: AWS profile name if configured
    """
    if AWS_PROFILE:
        logger.debug(f"Using AWS profile: {AWS_PROFILE}")
    else:
        logger.debug("Using default AWS credentials")
    
    return AWS_PROFILE


def is_read_only_mode() -> bool:
    """Check if server is running in read-only mode.
    
    Returns:
        bool: True if read-only mode is enabled
    """
    return READ_ONLY_MODE


def get_supported_frameworks() -> list[str]:
    """Get list of supported compliance frameworks.
    
    Returns:
        list[str]: List of supported framework names
    """
    return SUPPORTED_FRAMEWORKS.copy()


def is_framework_supported(framework: str) -> bool:
    """Check if compliance framework is supported.
    
    Args:
        framework: Framework name to check
        
    Returns:
        bool: True if framework is supported
    """
    return framework.upper() in [f.upper() for f in SUPPORTED_FRAMEWORKS]