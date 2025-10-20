"""Production-ready rate limiting for AWS Security Posture Advisor MCP Server."""

import time
from collections import defaultdict, deque
from typing import Dict, Set, Tuple
from functools import wraps
from loguru import logger

class RateLimiter:
    """Enhanced rate limiter for production deployments."""
    
    def __init__(self, config: dict):
        self.config = config
        self.request_history: Dict[str, deque] = defaultdict(deque)
        self.blocked_clients: Set[str] = set()
        self.block_expiry: Dict[str, float] = {}
        self.warning_sent: Set[str] = set()
    
    def is_rate_limited(self, client_id: str, tool_name: str) -> Tuple[bool, str]:
        """Check if client is rate limited."""
        current_time = time.time()
        
        # Skip rate limiting for whitelisted clients
        if client_id in self.config.get("whitelisted_clients", []):
            return False, ""
        
        # Remove expired blocks
        self._cleanup_expired_blocks(current_time)
        
        # Check if client is currently blocked
        if client_id in self.blocked_clients:
            remaining = int(self.block_expiry[client_id] - current_time)
            return True, f"Rate limited. Try again in {remaining} seconds"
        
        # Check rate limits
        is_limited, reason = self._check_limits(client_id, tool_name, current_time)
        
        if is_limited:
            self._block_client(client_id, current_time)
            logger.warning(f"Rate limit exceeded for client {client_id}: {reason}")
            return True, reason
        
        # Record successful request
        self.request_history[client_id].append(current_time)
        
        # Send warning if approaching limit
        self._check_warning_threshold(client_id, current_time)
        
        return False, ""
    
    def _cleanup_expired_blocks(self, current_time: float):
        """Remove expired client blocks."""
        expired_clients = [
            client_id for client_id, expiry_time in self.block_expiry.items()
            if current_time > expiry_time
        ]
        
        for client_id in expired_clients:
            self.blocked_clients.discard(client_id)
            del self.block_expiry[client_id]
            self.warning_sent.discard(client_id)
            logger.info(f"Rate limit block expired for client {client_id}")
    
    def _check_limits(self, client_id: str, tool_name: str, current_time: float) -> Tuple[bool, str]:
        """Check various rate limit thresholds."""
        history = self.request_history[client_id]
        
        # Clean old requests (keep last hour for analysis)
        hour_ago = current_time - 3600
        while history and history[0] < hour_ago:
            history.popleft()
        
        # Check per-minute limit
        minute_ago = current_time - 60
        requests_last_minute = sum(1 for req_time in history if req_time > minute_ago)
        
        if requests_last_minute >= self.config["requests_per_minute"]:
            return True, f"Exceeded {self.config['requests_per_minute']} requests per minute"
        
        # Check per-hour limit
        requests_last_hour = len(history)
        if requests_last_hour >= self.config["requests_per_hour"]:
            return True, f"Exceeded {self.config['requests_per_hour']} requests per hour"
        
        # Check tool-specific limits
        tool_limit_key = f"{tool_name}_per_hour"
        if tool_limit_key in self.config:
            tool_requests = sum(1 for req_time in history if req_time > hour_ago)
            if tool_requests >= self.config[tool_limit_key]:
                return True, f"Exceeded {self.config[tool_limit_key]} {tool_name} requests per hour"
        
        # Check burst protection
        burst_window = current_time - self.config.get("burst_window_seconds", 60)
        burst_requests = sum(1 for req_time in history if req_time > burst_window)
        
        if burst_requests >= self.config.get("burst_limit", 10):
            return True, f"Exceeded burst limit of {self.config['burst_limit']} requests"
        
        return False, ""
    
    def _block_client(self, client_id: str, current_time: float):
        """Block client for configured duration."""
        self.blocked_clients.add(client_id)
        block_duration = self.config.get("block_duration_minutes", 15) * 60
        self.block_expiry[client_id] = current_time + block_duration
        
        logger.warning(f"Blocked client {client_id} for {block_duration/60} minutes")
    
    def _check_warning_threshold(self, client_id: str, current_time: float):
        """Send warning when approaching rate limits."""
        if client_id in self.warning_sent:
            return
        
        history = self.request_history[client_id]
        minute_ago = current_time - 60
        requests_last_minute = sum(1 for req_time in history if req_time > minute_ago)
        
        warning_threshold = self.config["requests_per_minute"] * self.config.get("warning_threshold", 0.8)
        
        if requests_last_minute >= warning_threshold:
            self.warning_sent.add(client_id)
            logger.warning(f"Client {client_id} approaching rate limit: {requests_last_minute}/{self.config['requests_per_minute']} requests per minute")
    
    def get_client_stats(self, client_id: str) -> dict:
        """Get current rate limit statistics for a client."""
        current_time = time.time()
        history = self.request_history[client_id]
        
        minute_ago = current_time - 60
        hour_ago = current_time - 3600
        
        return {
            "client_id": client_id,
            "requests_last_minute": sum(1 for req_time in history if req_time > minute_ago),
            "requests_last_hour": sum(1 for req_time in history if req_time > hour_ago),
            "is_blocked": client_id in self.blocked_clients,
            "block_expires": self.block_expiry.get(client_id, 0),
            "limits": {
                "per_minute": self.config["requests_per_minute"],
                "per_hour": self.config["requests_per_hour"]
            }
        }

def rate_limit_decorator(rate_limiter: RateLimiter):
    """Decorator for MCP tools to enforce rate limiting."""
    def decorator(func):
        @wraps(func)
        async def wrapper(ctx, *args, **kwargs):
            # Extract client identifier
            client_id = getattr(ctx, 'client_id', 'unknown')
            if hasattr(ctx, 'session') and 'client_info' in ctx.session:
                client_info = ctx.session['client_info']
                client_id = client_info.get('name', client_id)
            
            tool_name = func.__name__
            
            # Check rate limits
            is_limited, message = rate_limiter.is_rate_limited(client_id, tool_name)
            if is_limited:
                from ..errors import SecurityAdvisorError
                raise SecurityAdvisorError(
                    message=f"Rate limit exceeded: {message}",
                    error_type="RateLimitExceeded"
                )
            
            # Execute the original function
            return await func(ctx, *args, **kwargs)
        return wrapper
    return decorator

# Default production configuration
DEFAULT_RATE_LIMIT_CONFIG = {
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
    "requests_per_day": 10000,
    "assess_security_posture_per_hour": 100,
    "health_check_per_minute": 10,
    "burst_limit": 10,
    "burst_window_seconds": 60,
    "warning_threshold": 0.8,
    "block_threshold": 1.0,
    "block_duration_minutes": 15,
    "whitelisted_clients": [
        "claude-desktop",
        "cursor-ide", 
        "internal-monitoring"
    ]
}
