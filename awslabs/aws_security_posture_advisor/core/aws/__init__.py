"""AWS service integrations for Security Posture Advisor."""

from .auth import AWSSessionManager, get_session_manager, create_aws_client, get_caller_identity, validate_aws_access
from .security_hub import SecurityHubClient
from .guardduty import GuardDutyClient
from .config import ConfigClient

__all__ = [
    'AWSSessionManager',
    'get_session_manager', 
    'create_aws_client',
    'get_caller_identity',
    'validate_aws_access',
    'SecurityHubClient',
    'GuardDutyClient',
    'ConfigClient',
]