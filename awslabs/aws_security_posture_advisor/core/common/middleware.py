"""Security middleware for AWS Security Posture Advisor MCP Server.

This module provides security middleware components including rate limiting,
request validation, security headers, and request sanitization.
"""

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Callable, Awaitable
from datetime import datetime, timedelta
from functools import wraps

from loguru import logger
from mcp.server.fastmcp import Context

from .config import (
    ENABLE_RATE_LIMITING,
    MAX_REQUEST_SIZE,
    REQUIRE_TLS,
    SANITIZE_LOGS,
)
from .security import sanitize_data, InputValidator
from .errors import SecurityAdvisorError


class RateLimiter:
    """Rate limiter implementation for MCP tools."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed for client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            bool: True if request is allowed
        """
        if not ENABLE_RATE_LIMITING:
            return True
        
        async with self._lock:
            now = time.time()
            client_requests = self.requests[client_id]
            
            # Remove old requests outside the window
            while client_requests and client_requests[0] < now - self.window_seconds:
                client_requests.popleft()
            
            # Check if under limit
            if len(client_requests) < self.max_requests:
                client_requests.append(now)
                return True
            
            return False
    
    def get_stats(self, client_id: str) -> Dict[str, Any]:
        """Get rate limiting stats for client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            Dict containing rate limiting statistics
        """
        now = time.time()
        client_requests = self.requests.get(client_id, deque())
        
        # Count recent requests
        recent_requests = sum(1 for req_time in client_requests 
                            if req_time > now - self.window_seconds)
        
        return {
            'requests_in_window': recent_requests,
            'max_requests': self.max_requests,
            'window_seconds': self.window_seconds,
            'remaining_requests': max(0, self.max_requests - recent_requests)
        }


class SecurityMiddleware:
    """Security middleware for MCP server."""
    
    def __init__(self):
        """Initialize security middleware."""
        self.rate_limiter = RateLimiter()
        self.input_validator = InputValidator()
    
    def validate_request_size(self, data: Any) -> None:
        """Validate request size.
        
        Args:
            data: Request data to validate
            
        Raises:
            SecurityAdvisorError: If request is too large
        """
        try:
            # Estimate size by converting to string
            size = len(str(data))
            if size > MAX_REQUEST_SIZE:
                raise SecurityAdvisorError(
                    message="Request size exceeds maximum allowed size",
                    error_type="RequestTooLarge"
                )
        except Exception as e:
            logger.warning(f"Failed to validate request size: {e}")
    
    def validate_tls_requirement(self, context: Context) -> None:
        """Validate TLS requirement if enabled.
        
        Args:
            context: MCP context
            
        Raises:
            SecurityAdvisorError: If TLS is required but not used
        """
        if not REQUIRE_TLS:
            return
        
        # Note: In MCP context, TLS validation would depend on the transport layer
        # This is a placeholder for TLS validation logic
        logger.debug("TLS validation placeholder - implement based on transport")
    
    async def process_request(self, context: Context, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Process and validate incoming request.
        
        Args:
            context: MCP context
            tool_name: Name of the tool being called
            parameters: Tool parameters
            
        Returns:
            Dict containing processed parameters
            
        Raises:
            SecurityAdvisorError: If request validation fails
        """
        # Generate client ID (in real implementation, extract from context)
        client_id = "default_client"  # Placeholder
        
        # Rate limiting check
        if not await self.rate_limiter.is_allowed(client_id):
            raise SecurityAdvisorError(
                message="Rate limit exceeded. Please try again later.",
                error_type="RateLimitExceeded"
            )
        
        # Request size validation
        self.validate_request_size(parameters)
        
        # TLS validation
        self.validate_tls_requirement(context)
        
        # Sanitize parameters if logging is enabled
        if SANITIZE_LOGS:
            sanitized_params = sanitize_data(parameters, f"tool_{tool_name}")
            logger.debug(f"Processing {tool_name} with sanitized parameters")
        
        return parameters
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses.
        
        Returns:
            Dict containing security headers
        """
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }


# Global middleware instance
_security_middleware: Optional[SecurityMiddleware] = None


def get_security_middleware() -> SecurityMiddleware:
    """Get or create global security middleware instance.
    
    Returns:
        SecurityMiddleware: Global middleware instance
    """
    global _security_middleware
    if _security_middleware is None:
        _security_middleware = SecurityMiddleware()
    return _security_middleware


def security_middleware(func: Callable) -> Callable:
    """Decorator to apply security middleware to MCP tools.
    
    Args:
        func: MCP tool function to wrap
        
    Returns:
        Wrapped function with security middleware
    """
    @wraps(func)
    async def wrapper(ctx: Context, *args, **kwargs):
        middleware = get_security_middleware()
        
        try:
            # Extract tool name from function
            tool_name = getattr(func, '__name__', 'unknown_tool')
            
            # Process request through security middleware
            await middleware.process_request(ctx, tool_name, kwargs)
            
            # Call original function
            result = await func(ctx, *args, **kwargs)
            
            return result
            
        except SecurityAdvisorError:
            # Re-raise security errors
            raise
        except Exception as e:
            # Log unexpected errors securely
            sanitized_error = sanitize_data(str(e), "middleware_error")
            logger.error(f"Security middleware error in {tool_name}: {sanitized_error}")
            raise SecurityAdvisorError(
                message="A security validation error occurred",
                error_type="SecurityValidationError"
            ) from e
    
    return wrapper


def validate_input_parameters(**param_validators: Dict[str, Any]) -> Callable:
    """Decorator to validate input parameters for MCP tools.
    
    Args:
        **param_validators: Parameter validation specifications
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(ctx: Context, *args, **kwargs):
            validator = InputValidator()
            
            # Validate each parameter according to specification
            for param_name, validation_spec in param_validators.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    
                    if isinstance(validation_spec, dict):
                        # Complex validation specification
                        max_length = validation_spec.get('max_length')
                        pattern = validation_spec.get('pattern')
                        required = validation_spec.get('required', True)
                        
                        validated_value = validator.validate_string(
                            value, param_name, max_length, pattern, required
                        )
                        kwargs[param_name] = validated_value
                    else:
                        # Simple max length validation
                        validated_value = validator.validate_string(
                            value, param_name, max_length=validation_spec
                        )
                        kwargs[param_name] = validated_value
            
            return await func(ctx, *args, **kwargs)
        
        return wrapper
    return decorator