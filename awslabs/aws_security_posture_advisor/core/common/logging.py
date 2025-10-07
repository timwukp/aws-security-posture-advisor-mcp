"""Logging configuration following AWS Labs patterns.

This module provides centralized logging configuration for the AWS Security
Posture Advisor MCP server, implementing structured logging with security
considerations and audit trail capabilities.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger

from .config import (
    ENABLE_AUDIT_LOGGING,
    LOG_LEVEL,
    LOG_TO_FILE,
    get_server_directory,
)


def setup_logging() -> None:
    """Set up logging configuration following AWS Labs patterns.
    
    Configures loguru with appropriate handlers, formatters, and security
    considerations for the MCP server environment.
    """
    # Remove default handler
    logger.remove()
    
    # Console handler with structured format
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )
    
    logger.add(
        sys.stderr,
        format=console_format,
        level=LOG_LEVEL,
        colorize=True,
        backtrace=LOG_LEVEL == "DEBUG",  # Only enable in debug mode
        diagnose=LOG_LEVEL == "DEBUG",   # Only enable in debug mode for security
    )
    
    # File handler if enabled
    if LOG_TO_FILE:
        log_dir = get_server_directory()
        log_file = log_dir / "aws-security-posture-advisor.log"
        
        # Structured JSON format for file logging
        file_format = (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
            "{level: <8} | "
            "{name}:{function}:{line} | "
            "{message}"
        )
        
        logger.add(
            log_file,
            format=file_format,
            level=LOG_LEVEL,
            rotation="10 MB",
            retention="7 days",
            compression="gz",
            backtrace=LOG_LEVEL == "DEBUG",  # Only enable in debug mode
            diagnose=LOG_LEVEL == "DEBUG",   # Only enable in debug mode for security
        )
        
        logger.info(f"File logging enabled: {log_file}")
    
    # Audit log handler if enabled
    if ENABLE_AUDIT_LOGGING:
        audit_log_file = get_server_directory() / "audit.log"
        
        # JSON format for audit logs
        audit_format = "{message}"
        
        logger.add(
            audit_log_file,
            format=audit_format,
            level="INFO",
            rotation="50 MB",
            retention="30 days",
            compression="gz",
            filter=lambda record: record["extra"].get("audit", False),
        )
        
        logger.info(f"Audit logging enabled: {audit_log_file}")
    
    logger.info(f"Logging initialized - Level: {LOG_LEVEL}, File: {LOG_TO_FILE}, Audit: {ENABLE_AUDIT_LOGGING}")


def sanitize_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize sensitive data from log entries.
    
    Removes or masks sensitive information like credentials, tokens, and
    personally identifiable information before logging.
    
    Args:
        data: Dictionary containing potentially sensitive data
        
    Returns:
        Dict[str, Any]: Sanitized data safe for logging
    """
    sensitive_keys = {
        'password', 'token', 'secret', 'key', 'credential', 'auth',
        'access_key', 'secret_key', 'session_token', 'api_key',
        'authorization', 'x-api-key', 'x-auth-token'
    }
    
    def _sanitize_value(key: str, value: Any) -> Any:
        """Sanitize individual values based on key names."""
        if isinstance(key, str) and any(sensitive in key.lower() for sensitive in sensitive_keys):
            if isinstance(value, str) and len(value) > 8:
                return f"{value[:4]}***{value[-4:]}"
            else:
                return "***"
        elif isinstance(value, dict):
            return {k: _sanitize_value(k, v) for k, v in value.items()}
        elif isinstance(value, list):
            return [_sanitize_value("", item) for item in value]
        else:
            return value
    
    return {k: _sanitize_value(k, v) for k, v in data.items()}


def audit_log(action: str, details: Dict[str, Any], user_context: Optional[str] = None) -> None:
    """Log security audit events.
    
    Creates structured audit log entries for security-relevant operations
    with proper sanitization and formatting.
    
    Args:
        action: Action being performed (e.g., 'assess_security_posture')
        details: Additional details about the action
        user_context: Optional user context information
    """
    if not ENABLE_AUDIT_LOGGING:
        return
    
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user_context": user_context or "unknown",
        "details": sanitize_sensitive_data(details),
        "server": "aws-security-posture-advisor"
    }
    
    # Use loguru's bind to add audit flag
    logger.bind(audit=True).info(json.dumps(audit_entry, default=str))


def log_aws_api_call(service: str, operation: str, duration_ms: float, success: bool, error: Optional[str] = None) -> None:
    """Log AWS API calls for monitoring and debugging.
    
    Args:
        service: AWS service name (e.g., 'SecurityHub')
        operation: AWS operation name (e.g., 'GetFindings')
        duration_ms: Call duration in milliseconds
        success: Whether the call was successful
        error: Optional error message if call failed
    """
    log_data = {
        "aws_service": service,
        "aws_operation": operation,
        "duration_ms": duration_ms,
        "success": success
    }
    
    if error:
        log_data["error"] = error
        logger.warning(f"AWS API call failed: {service}.{operation} ({duration_ms:.1f}ms) - {error}")
    else:
        logger.debug(f"AWS API call: {service}.{operation} ({duration_ms:.1f}ms)")


def log_intelligence_operation(engine: str, operation: str, input_size: int, output_size: int, duration_ms: float) -> None:
    """Log intelligence engine operations for performance monitoring.
    
    Args:
        engine: Intelligence engine name (e.g., 'RiskCorrelation')
        operation: Operation name (e.g., 'correlate_findings')
        input_size: Size of input data
        output_size: Size of output data
        duration_ms: Operation duration in milliseconds
    """
    logger.info(
        f"Intelligence operation: {engine}.{operation} "
        f"(input: {input_size}, output: {output_size}, {duration_ms:.1f}ms)"
    )


def log_mcp_tool_execution(tool_name: str, parameters: Dict[str, Any], duration_ms: float, success: bool) -> None:
    """Log MCP tool executions for audit and monitoring.
    
    Args:
        tool_name: Name of the MCP tool executed
        parameters: Tool parameters (will be sanitized)
        duration_ms: Execution duration in milliseconds
        success: Whether execution was successful
    """
    sanitized_params = sanitize_sensitive_data(parameters)
    
    audit_log(
        action=f"mcp_tool_execution",
        details={
            "tool_name": tool_name,
            "parameters": sanitized_params,
            "duration_ms": duration_ms,
            "success": success
        }
    )
    
    if success:
        logger.info(f"MCP tool executed: {tool_name} ({duration_ms:.1f}ms)")
    else:
        logger.error(f"MCP tool failed: {tool_name} ({duration_ms:.1f}ms)")


class SecurityLogger:
    """Security-focused logger with context management.
    
    Provides a context-aware logger that automatically handles sensitive
    data sanitization and audit trail generation.
    """
    
    def __init__(self, context: Optional[str] = None):
        """Initialize SecurityLogger with optional context.
        
        Args:
            context: Optional context identifier (e.g., session ID)
        """
        self.context = context
    
    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message with context."""
        self._log("info", message, **kwargs)
    
    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message with context."""
        self._log("warning", message, **kwargs)
    
    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message with context."""
        self._log("error", message, **kwargs)
    
    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message with context."""
        self._log("debug", message, **kwargs)
    
    def _log(self, level: str, message: str, **kwargs: Any) -> None:
        """Internal logging method with sanitization."""
        sanitized_kwargs = sanitize_sensitive_data(kwargs)
        
        if self.context:
            message = f"[{self.context}] {message}"
        
        getattr(logger, level)(message, **sanitized_kwargs)