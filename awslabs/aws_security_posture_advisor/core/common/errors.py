"""Error handling classes following AWS Labs patterns.

This module provides a comprehensive error handling framework for the AWS Security
Posture Advisor MCP server, following AWS Labs MCP server patterns and best practices.
"""

import asyncio
import random
import time
from typing import Any, Dict, Optional, Callable, TypeVar, Union, List
from functools import wraps
from mcp.types import JSONRPCError, ErrorData
from pydantic import BaseModel
from loguru import logger
from botocore.exceptions import ClientError

T = TypeVar('T')


class SecurityAdvisorError(Exception):
    """Base exception for all Security Advisor errors.
    
    This is the root exception class that all other Security Advisor exceptions
    inherit from. It provides a standardized way to convert exceptions to MCP
    Failure responses.
    """
    
    def __init__(self, message: str, error_type: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        """Initialize SecurityAdvisorError.
        
        Args:
            message: Human-readable error message
            error_type: Optional error type classification
            context: Optional additional context information
        """
        super().__init__(message)
        self.message = message
        self.error_type = error_type or self.__class__.__name__
        self.context = context or {}
    
    def as_error_data(self) -> ErrorData:
        """Convert exception to MCP ErrorData.
        
        Returns:
            ErrorData: MCP-compliant error data
        """
        return ErrorData(
            code=-32000,  # Server error code range
            message=self.message,
            data={"error_type": self.error_type, "context": self.context}
        )


class AWSServiceError(SecurityAdvisorError):
    """Errors from AWS service interactions.
    
    This exception is raised when there are issues communicating with AWS services
    or when AWS services return errors.
    """
    
    def __init__(self, service: str, operation: str, aws_error: Exception, message: Optional[str] = None):
        """Initialize AWSServiceError.
        
        Args:
            service: AWS service name (e.g., 'SecurityHub', 'GuardDuty')
            operation: AWS operation that failed (e.g., 'GetFindings')
            aws_error: Original AWS exception
            message: Optional custom error message
        """
        self.service = service
        self.operation = operation
        self.aws_error = aws_error
        
        if message is None:
            message = f"AWS {service} {operation} failed: {str(aws_error)}"
        
        super().__init__(
            message=message,
            error_type="AWSServiceError",
            context={
                "service": service,
                "operation": operation,
                "aws_error_type": type(aws_error).__name__,
                "aws_error_message": str(aws_error)
            }
        )


class AuthenticationError(SecurityAdvisorError):
    """Errors related to AWS authentication and authorization.
    
    This exception is raised when there are issues with AWS credentials,
    IAM permissions, or role assumptions.
    """
    
    def __init__(self, message: str, credential_type: Optional[str] = None):
        """Initialize AuthenticationError.
        
        Args:
            message: Human-readable error message
            credential_type: Type of credential that failed (e.g., 'profile', 'role')
        """
        super().__init__(
            message=message,
            error_type="AuthenticationError",
            context={"credential_type": credential_type} if credential_type else {}
        )


class IntelligenceEngineError(SecurityAdvisorError):
    """Errors from intelligence processing engines.
    
    This exception is raised when there are issues with the risk correlation,
    compliance intelligence, or remediation advisor engines.
    """
    
    def __init__(self, engine: str, operation: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize IntelligenceEngineError.
        
        Args:
            engine: Intelligence engine name (e.g., 'RiskCorrelation', 'ComplianceIntelligence')
            operation: Operation that failed (e.g., 'correlate_findings')
            message: Human-readable error message
            details: Optional additional error details
        """
        super().__init__(
            message=f"{engine} {operation} failed: {message}",
            error_type="IntelligenceEngineError",
            context={
                "engine": engine,
                "operation": operation,
                "details": details or {}
            }
        )


class ComplianceFrameworkError(SecurityAdvisorError):
    """Errors related to compliance framework processing.
    
    This exception is raised when there are issues with compliance framework
    mapping, assessment, or reporting.
    """
    
    def __init__(self, framework: str, message: str, control_id: Optional[str] = None):
        """Initialize ComplianceFrameworkError.
        
        Args:
            framework: Compliance framework name (e.g., 'CIS', 'NIST')
            message: Human-readable error message
            control_id: Optional specific control that failed
        """
        super().__init__(
            message=f"Compliance framework {framework} error: {message}",
            error_type="ComplianceFrameworkError",
            context={
                "framework": framework,
                "control_id": control_id
            }
        )


class RemediationError(SecurityAdvisorError):
    """Errors during remediation execution.
    
    This exception is raised when there are issues with remediation
    recommendation generation or execution.
    """
    
    def __init__(self, remediation_id: str, message: str, step: Optional[str] = None):
        """Initialize RemediationError.
        
        Args:
            remediation_id: Unique identifier for the remediation
            message: Human-readable error message
            step: Optional specific remediation step that failed
        """
        super().__init__(
            message=f"Remediation {remediation_id} failed: {message}",
            error_type="RemediationError",
            context={
                "remediation_id": remediation_id,
                "step": step
            }
        )


class ValidationError(SecurityAdvisorError):
    """Errors related to input validation.
    
    This exception is raised when MCP tool parameters fail validation
    or when data doesn't meet expected formats.
    """
    
    def __init__(self, parameter: str, value: Any, message: str):
        """Initialize ValidationError.
        
        Args:
            parameter: Parameter name that failed validation
            value: Invalid value (will be sanitized in context)
            message: Human-readable error message
        """
        super().__init__(
            message=f"Validation failed for parameter '{parameter}': {message}",
            error_type="ValidationError",
            context={
                "parameter": parameter,
                "value_type": type(value).__name__,
                "message": message
            }
        )


class SecurityAdvisorErrorResponse(BaseModel):
    """Standardized error response format for MCP tools.
    
    This model provides a consistent error response format that can be
    returned from MCP tools when errors occur.
    """
    
    detail: str
    error_type: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_exception(cls, error: SecurityAdvisorError) -> "SecurityAdvisorErrorResponse":
        """Create error response from SecurityAdvisorError.
        
        Args:
            error: SecurityAdvisorError instance
            
        Returns:
            SecurityAdvisorErrorResponse: Standardized error response
        """
        return cls(
            detail=error.message,
            error_type=error.error_type,
            context=error.context
        )


# Convenience functions for common error scenarios
def aws_service_unavailable(service: str) -> AWSServiceError:
    """Create error for when AWS service is unavailable.
    
    Args:
        service: AWS service name
        
    Returns:
        AWSServiceError: Configured error instance
    """
    return AWSServiceError(
        service=service,
        operation="ServiceCheck",
        aws_error=Exception("Service unavailable"),
        message=f"AWS {service} service is currently unavailable"
    )


def invalid_credentials() -> AuthenticationError:
    """Create error for invalid AWS credentials.
    
    Returns:
        AuthenticationError: Configured error instance
    """
    return AuthenticationError(
        message="AWS credentials are not configured or invalid. Please check your AWS configuration.",
        credential_type="credentials"
    )


def insufficient_permissions(service: str, operation: str) -> AuthenticationError:
    """Create error for insufficient IAM permissions.
    
    Args:
        service: AWS service name
        operation: AWS operation that was denied
        
    Returns:
        AuthenticationError: Configured error instance
    """
    return AuthenticationError(
        message=f"Insufficient permissions for {service}:{operation}. Please check your IAM policies.",
        credential_type="permissions"
    )


def unsupported_framework(framework: str) -> ComplianceFrameworkError:
    """Create error for unsupported compliance framework.
    
    Args:
        framework: Unsupported framework name
        
    Returns:
        ComplianceFrameworkError: Configured error instance
    """
    return ComplianceFrameworkError(
        framework=framework,
        message=f"Compliance framework '{framework}' is not supported. Supported frameworks: CIS, NIST, SOC2, PCI-DSS"
    )


class RetryableError(SecurityAdvisorError):
    """Base class for errors that can be retried.
    
    This exception indicates that the operation might succeed if retried,
    typically due to transient issues like network problems or rate limiting.
    """
    
    def __init__(self, message: str, retry_after: Optional[float] = None, **kwargs):
        """Initialize RetryableError.
        
        Args:
            message: Human-readable error message
            retry_after: Suggested retry delay in seconds
            **kwargs: Additional context for parent class
        """
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ThrottlingError(RetryableError):
    """Error indicating API rate limiting or throttling."""
    
    def __init__(self, service: str, retry_after: Optional[float] = None):
        """Initialize ThrottlingError.
        
        Args:
            service: AWS service being throttled
            retry_after: Suggested retry delay in seconds
        """
        super().__init__(
            message=f"AWS {service} API is being throttled",
            error_type="ThrottlingError",
            retry_after=retry_after,
            context={"service": service}
        )


class ServiceUnavailableError(RetryableError):
    """Error indicating AWS service is temporarily unavailable."""
    
    def __init__(self, service: str, retry_after: Optional[float] = None):
        """Initialize ServiceUnavailableError.
        
        Args:
            service: AWS service that is unavailable
            retry_after: Suggested retry delay in seconds
        """
        super().__init__(
            message=f"AWS {service} service is temporarily unavailable",
            error_type="ServiceUnavailableError",
            retry_after=retry_after,
            context={"service": service}
        )


class SecurityAdvisorErrorResponse(BaseModel):
    """Standardized error response format for MCP tools."""
    
    detail: str
    error_type: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_exception(cls, error: SecurityAdvisorError) -> "SecurityAdvisorErrorResponse":
        """Create error response from SecurityAdvisorError."""
        return cls(
            detail=error.message,
            error_type=error.error_type,
            context=error.context
        )


def exponential_backoff_with_jitter(max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
    """Decorator for exponential backoff with jitter retry logic.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except RetryableError as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = _calculate_backoff_delay(attempt, base_delay, max_delay)
                        logger.warning(f"Retrying {func.__name__} after {delay:.2f}s (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                    else:
                        logger.error(f"Max retries exceeded for {func.__name__}")
                        break
                except Exception as e:
                    # Non-retryable error, fail immediately
                    raise e
            
            # If we get here, all retries failed
            raise last_exception or SecurityAdvisorError("All retry attempts failed")
        
        return wrapper
    return decorator


def _calculate_backoff_delay(attempt: int, base_delay: float = 1.0, max_delay: float = 60.0) -> float:
    """Calculate exponential backoff delay with jitter.
    
    Args:
        attempt: Current attempt number (0-based)
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        
    Returns:
        float: Delay in seconds with jitter applied
    """
    delay = min(base_delay * (2 ** attempt), max_delay)
    jitter = random.uniform(0.1, 0.3) * delay
    return delay + jitter


def handle_aws_client_error(service: str, operation: str):
    """Decorator to handle AWS ClientError exceptions.
    
    Args:
        service: AWS service name
        operation: AWS operation name
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                raise _convert_client_error(e, service, operation)
        return wrapper
    return decorator


def _convert_client_error(error: ClientError, service: str, operation: str) -> SecurityAdvisorError:
    """Convert AWS ClientError to appropriate SecurityAdvisorError.
    
    Args:
        error: Boto3 ClientError
        service: AWS service name
        operation: AWS operation name
        
    Returns:
        SecurityAdvisorError: Appropriate error type based on AWS error
    """
    error_code = error.response.get('Error', {}).get('Code', 'Unknown')
    
    if error_code in ['Throttling', 'ThrottlingException', 'TooManyRequestsException']:
        return ThrottlingError(service)
    elif error_code in ['ServiceUnavailable', 'InternalServerError']:
        return ServiceUnavailableError(service)
    elif error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']:
        return AuthenticationError(
            message=f"Access denied for {service}:{operation}",
            credential_type="permissions"
        )
    else:
        return AWSServiceError(
            service=service,
            operation=operation,
            aws_error=error,
            message=str(error)
        )


class GracefulDegradationMixin:
    """Mixin for graceful degradation when services are unavailable."""
    
    def __init__(self):
        self._degraded_services = set()
    
    def mark_service_degraded(self, service: str):
        """Mark a service as degraded."""
        self._degraded_services.add(service)
        logger.warning(f"Service {service} marked as degraded")
    
    def is_service_degraded(self, service: str) -> bool:
        """Check if a service is marked as degraded."""
        return service in self._degraded_services
    
    def clear_service_degradation(self, service: str):
        """Clear degradation status for a service."""
        self._degraded_services.discard(service)
        logger.info(f"Service {service} degradation cleared")


class PartialResultError(SecurityAdvisorError):
    """Error indicating partial results due to service issues."""
    
    def __init__(self, message: str, partial_data: Optional[Dict[str, Any]] = None):
        """Initialize PartialResultError.
        
        Args:
            message: Human-readable error message
            partial_data: Any partial data that was successfully retrieved
        """
        super().__init__(
            message=message,
            error_type="PartialResultError",
            context={"partial_data": partial_data or {}}
        )
        self.partial_data = partial_data or {}
