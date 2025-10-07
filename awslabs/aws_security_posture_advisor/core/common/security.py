"""Security-first data handling for AWS Security Posture Advisor.

This module provides comprehensive input validation, data sanitization,
and security controls for handling sensitive security data.
"""

import re
import json
import hashlib
import secrets
import asyncio
from typing import Any, Dict, List, Optional, Union, Set
from datetime import datetime, timezone
from functools import wraps
from loguru import logger
from pydantic import BaseModel, Field, validator

from .errors import ValidationError, SecurityAdvisorError


# Sensitive data patterns that should be redacted
SENSITIVE_PATTERNS = {
    'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
    'aws_secret_key': re.compile(r'[A-Za-z0-9/+=]{40}'),
    'aws_session_token': re.compile(r'[A-Za-z0-9/+=]{100,}'),
    'aws_account_id': re.compile(r'\b\d{12}\b'),  # AWS Account IDs
    'aws_arn': re.compile(r'arn:aws[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9-_/:.*]+'),
    'aws_resource_id': re.compile(r'\b(i-[0-9a-f]{8,17}|vol-[0-9a-f]{8,17}|sg-[0-9a-f]{8,17}|vpc-[0-9a-f]{8,17}|subnet-[0-9a-f]{8,17})\b'),
    'aws_s3_bucket': re.compile(r'\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-][a-z0-9-]+\.amazonaws\.com\b'),
    'password': re.compile(r'(?i)(password|passwd|pwd)["\s]*[:=]["\s]*[^\s"]+|["\'][^"\']+["\']|secret\d+|mypassword\d+'),
    'api_key': re.compile(r'(?i)(api[_-]?key|apikey)["\s]*[:=]["\s]*[^\s"]+|secret\d+|sk-[a-zA-Z0-9]+'),
    'private_key': re.compile(r'-----BEGIN[A-Z\s]+PRIVATE KEY-----.*?-----END[A-Z\s]+PRIVATE KEY-----', re.DOTALL),
    'certificate': re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.DOTALL),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    'phone': re.compile(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}'),
    'ssn': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),
    'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    'jwt_token': re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
    'bearer_token': re.compile(r'Bearer\s+[A-Za-z0-9_-]+', re.IGNORECASE),
    'authorization_header': re.compile(r'Authorization:\s*[^\r\n]+', re.IGNORECASE),
}

# AWS ARN patterns for validation
AWS_ARN_PATTERN = re.compile(
    r'^arn:aws[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12})?:[a-zA-Z0-9-_/:.*]+$'
)

# AWS Account ID pattern
AWS_ACCOUNT_ID_PATTERN = re.compile(r'^[0-9]{12}$')

# AWS Region pattern
AWS_REGION_PATTERN = re.compile(r'^[a-z0-9-]+[0-9]$')

# Maximum lengths for various input types
MAX_LENGTHS = {
    'string': 10000,
    'list': 1000,
    'dict_keys': 100,
    'arn': 2048,
    'account_id': 12,
    'region': 50,
    'finding_id': 256,
    'resource_id': 1024
}


class DataSanitizer:
    """Handles data sanitization and redaction of sensitive information."""
    
    def __init__(self, redaction_char: str = '*', preserve_structure: bool = True):
        """Initialize data sanitizer.
        
        Args:
            redaction_char: Character to use for redaction
            preserve_structure: Whether to preserve data structure when redacting
        """
        self.redaction_char = redaction_char
        self.preserve_structure = preserve_structure
    
    def sanitize_text(self, text: str, context: str = "general") -> str:
        """Sanitize text by redacting sensitive information.
        
        Args:
            text: Text to sanitize
            context: Context for logging purposes
            
        Returns:
            str: Sanitized text with sensitive data redacted
        """
        if not isinstance(text, str):
            return str(text)
        
        sanitized = text
        redacted_patterns = []
        
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(sanitized)
            if matches:
                redacted_patterns.append(pattern_name)
                if self.preserve_structure:
                    # Replace with same-length redaction
                    sanitized = pattern.sub(
                        lambda m: self.redaction_char * len(m.group(0)),
                        sanitized
                    )
                else:
                    # Replace with fixed redaction
                    sanitized = pattern.sub(f'[REDACTED_{pattern_name.upper()}]', sanitized)
        
        if redacted_patterns:
            logger.debug(f"Redacted {len(redacted_patterns)} sensitive patterns in {context}: {redacted_patterns}")
        
        return sanitized
    
    def sanitize_dict(self, data: Dict[str, Any], context: str = "dict") -> Dict[str, Any]:
        """Recursively sanitize dictionary data.
        
        Args:
            data: Dictionary to sanitize
            context: Context for logging purposes
            
        Returns:
            Dict[str, Any]: Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            sanitized_key = self.sanitize_text(str(key), f"{context}.key")
            
            # Sanitize value based on type
            if isinstance(value, str):
                sanitized_value = self.sanitize_text(value, f"{context}.{key}")
            elif isinstance(value, dict):
                sanitized_value = self.sanitize_dict(value, f"{context}.{key}")
            elif isinstance(value, list):
                sanitized_value = self.sanitize_list(value, f"{context}.{key}")
            else:
                sanitized_value = value
            
            sanitized[sanitized_key] = sanitized_value
        
        return sanitized
    
    def sanitize_list(self, data: List[Any], context: str = "list") -> List[Any]:
        """Recursively sanitize list data.
        
        Args:
            data: List to sanitize
            context: Context for logging purposes
            
        Returns:
            List[Any]: Sanitized list
        """
        if not isinstance(data, list):
            return data
        
        sanitized = []
        
        for i, item in enumerate(data):
            if isinstance(item, str):
                sanitized_item = self.sanitize_text(item, f"{context}[{i}]")
            elif isinstance(item, dict):
                sanitized_item = self.sanitize_dict(item, f"{context}[{i}]")
            elif isinstance(item, list):
                sanitized_item = self.sanitize_list(item, f"{context}[{i}]")
            else:
                sanitized_item = item
            
            sanitized.append(sanitized_item)
        
        return sanitized
    
    def sanitize_any(self, data: Any, context: str = "data") -> Any:
        """Sanitize data of any type.
        
        Args:
            data: Data to sanitize
            context: Context for logging purposes
            
        Returns:
            Any: Sanitized data
        """
        if isinstance(data, str):
            return self.sanitize_text(data, context)
        elif isinstance(data, dict):
            return self.sanitize_dict(data, context)
        elif isinstance(data, list):
            return self.sanitize_list(data, context)
        else:
            return data


class InputValidator:
    """Validates and sanitizes input parameters for MCP tools."""
    
    def __init__(self):
        """Initialize input validator."""
        self.sanitizer = DataSanitizer()
    
    def validate_string(
        self,
        value: Any,
        param_name: str,
        max_length: Optional[int] = None,
        pattern: Optional[re.Pattern] = None,
        required: bool = True
    ) -> str:
        """Validate string parameter.
        
        Args:
            value: Value to validate
            param_name: Parameter name for error messages
            max_length: Maximum allowed length
            pattern: Regex pattern to match
            required: Whether parameter is required
            
        Returns:
            str: Validated and sanitized string
            
        Raises:
            ValidationError: If validation fails
        """
        if value is None:
            if required:
                raise ValidationError(param_name, value, "Parameter is required")
            return ""
        
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception as e:
                raise ValidationError(param_name, value, f"Cannot convert to string: {e}")
        
        # Check length
        max_len = max_length or MAX_LENGTHS.get('string', 10000)
        if len(value) > max_len:
            raise ValidationError(param_name, value, f"String too long (max {max_len} characters)")
        
        # Check pattern
        if pattern and not pattern.match(value):
            raise ValidationError(param_name, value, f"String does not match required pattern")
        
        # Sanitize
        sanitized = self.sanitizer.sanitize_text(value, f"param.{param_name}")
        
        return sanitized
    
    def validate_aws_arn(self, value: Any, param_name: str, required: bool = True) -> str:
        """Validate AWS ARN parameter.
        
        Args:
            value: Value to validate
            param_name: Parameter name for error messages
            required: Whether parameter is required
            
        Returns:
            str: Validated ARN
            
        Raises:
            ValidationError: If validation fails
        """
        validated = self.validate_string(
            value, param_name, 
            max_length=MAX_LENGTHS['arn'],
            pattern=AWS_ARN_PATTERN,
            required=required
        )
        
        if validated and not AWS_ARN_PATTERN.match(validated):
            raise ValidationError(param_name, value, "Invalid AWS ARN format")
        
        return validated


# Global instances for convenience
_global_sanitizer = DataSanitizer()
_global_validator = InputValidator()


def sanitize_data(data: Any, context: str = "data") -> Any:
    """Convenience function to sanitize data using global sanitizer.
    
    Args:
        data: Data to sanitize
        context: Context for logging
        
    Returns:
        Any: Sanitized data
    """
    return _global_sanitizer.sanitize_any(data, context)