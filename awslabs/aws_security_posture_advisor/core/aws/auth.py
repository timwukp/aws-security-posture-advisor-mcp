"""AWS authentication and session management.

This module provides secure AWS credential handling, session management, and IAM
role validation following AWS Labs patterns and security best practices.
"""

import boto3
from boto3 import Session
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
    TokenRetrievalError,
)
from loguru import logger
from typing import Dict, Optional, Any
import json
from datetime import datetime, timezone

from ..common.config import AWS_REGION, get_aws_profile, is_read_only_mode
from ..common.errors import AuthenticationError, AWSServiceError


class AWSSessionManager:
    """Manages AWS sessions with secure credential handling and validation.
    
    This class provides a centralized way to create and manage AWS sessions
    with proper error handling, credential validation, and least privilege
    access patterns.
    """
    
    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize AWS session manager.
        
        Args:
            region: AWS region to use (defaults to configured region)
            profile: AWS profile name to use (defaults to configured profile)
        """
        self.region = region or AWS_REGION
        self.profile = profile or get_aws_profile()
        self._session: Optional[Session] = None
        self._identity: Optional[Dict[str, Any]] = None
        self._validated_at: Optional[datetime] = None
    
    def get_session(self) -> Session:
        """Get or create AWS session with credential validation.
        
        Returns:
            Session: Validated AWS session
            
        Raises:
            AuthenticationError: If credentials are invalid or unavailable
        """
        if self._session is None or self._needs_revalidation():
            self._session = self._create_session()
            self._validate_session()
        
        return self._session
    
    def _create_session(self) -> Session:
        """Create new AWS session with proper error handling.
        
        Returns:
            Session: New AWS session
            
        Raises:
            AuthenticationError: If session creation fails
        """
        try:
            if self.profile:
                logger.debug(f"Creating AWS session with profile: {self.profile}")
                session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                logger.debug("Creating AWS session with default credentials")
                session = boto3.Session(region_name=self.region)
            
            return session
            
        except ProfileNotFound as e:
            logger.error(f"AWS profile '{self.profile}' not found")
            raise AuthenticationError(
                message=f"AWS profile '{self.profile}' not found. Please check your AWS configuration.",
                credential_type="profile"
            ) from e
        
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.error("AWS credentials not found or incomplete")
            raise AuthenticationError(
                message="AWS credentials are not configured or incomplete. Please configure your AWS credentials.",
                credential_type="credentials"
            ) from e
        
        except Exception as e:
            logger.error(f"Failed to create AWS session: {e}")
            raise AuthenticationError(
                message=f"Failed to create AWS session: {str(e)}",
                credential_type="session"
            ) from e
    
    def _validate_session(self) -> None:
        """Validate AWS session and retrieve caller identity.
        
        Raises:
            AuthenticationError: If session validation fails
        """
        try:
            sts_client = self._session.client('sts')
            response = sts_client.get_caller_identity()
            
            self._identity = {
                'account': response.get('Account'),
                'arn': response.get('Arn'),
                'user_id': response.get('UserId')
            }
            self._validated_at = datetime.now(timezone.utc)
            
            # Log successful authentication (without sensitive data)
            logger.info(f"AWS authentication successful - Account: {self._identity['account']}, "
                       f"Region: {self.region}, ReadOnly: {is_read_only_mode()}")
            
            # Validate required permissions
            self._validate_permissions()
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"AWS session validation failed: {error_code}")
            
            if error_code in ['InvalidUserID.NotFound', 'AccessDenied']:
                raise AuthenticationError(
                    message="AWS credentials are invalid or expired. Please refresh your credentials.",
                    credential_type="credentials"
                ) from e
            else:
                raise AuthenticationError(
                    message=f"AWS session validation failed: {str(e)}",
                    credential_type="validation"
                ) from e
        
        except TokenRetrievalError as e:
            logger.error("AWS token retrieval failed")
            raise AuthenticationError(
                message="Failed to retrieve AWS security token. Please check your credentials and try again.",
                credential_type="token"
            ) from e
        
        except Exception as e:
            logger.error(f"Unexpected error during session validation: {e}")
            raise AuthenticationError(
                message=f"Unexpected error during AWS session validation: {str(e)}",
                credential_type="validation"
            ) from e
    
    def _validate_permissions(self) -> None:
        """Validate that the session has required permissions for security services.
        
        This performs a lightweight check to ensure the credentials have access
        to the AWS security services we need to query.
        """
        required_services = [
            ('securityhub', 'describe_hub'),
            ('guardduty', 'list_detectors'),
            ('config', 'describe_configuration_recorders'),
        ]
        
        missing_permissions = []
        
        for service, operation in required_services:
            try:
                client = self._session.client(service)
                
                # Perform a lightweight operation to test permissions
                if service == 'securityhub':
                    try:
                        client.describe_hub()
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') == 'InvalidAccessException':
                            # Hub not enabled is OK, we just need permission to check
                            pass
                        else:
                            raise
                
                elif service == 'guardduty':
                    client.list_detectors()
                
                elif service == 'config':
                    client.describe_configuration_recorders()
                
                logger.debug(f"Permission validated for {service}:{operation}")
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                    missing_permissions.append(f"{service}:{operation}")
                    logger.warning(f"Missing permission for {service}:{operation}")
                else:
                    # Other errors might be service-specific and not permission-related
                    logger.debug(f"Non-permission error for {service}: {error_code}")
            
            except Exception as e:
                logger.debug(f"Unexpected error checking {service} permissions: {e}")
        
        if missing_permissions:
            logger.warning(f"Some permissions may be missing: {missing_permissions}")
            logger.warning("The server will attempt to operate with available permissions")
    
    def _needs_revalidation(self) -> bool:
        """Check if session needs revalidation.
        
        Returns:
            bool: True if session needs revalidation
        """
        if self._validated_at is None:
            return True
        
        # Revalidate every hour
        age = datetime.now(timezone.utc) - self._validated_at
        return age.total_seconds() > 3600
    
    def get_caller_identity(self) -> Dict[str, Any]:
        """Get caller identity information.
        
        Returns:
            Dict[str, Any]: Caller identity information
            
        Raises:
            AuthenticationError: If identity is not available
        """
        if self._identity is None:
            # Ensure session is validated
            self.get_session()
        
        if self._identity is None:
            raise AuthenticationError(
                message="Caller identity not available",
                credential_type="identity"
            )
        
        return self._identity.copy()
    
    def create_client(self, service_name: str, **kwargs) -> Any:
        """Create AWS service client with proper configuration.
        
        Args:
            service_name: AWS service name (e.g., 'securityhub', 'guardduty')
            **kwargs: Additional client configuration
            
        Returns:
            AWS service client
            
        Raises:
            AWSServiceError: If client creation fails
        """
        try:
            session = self.get_session()
            
            # Set default configuration
            client_config = {
                'region_name': self.region,
                **kwargs
            }
            
            client = session.client(service_name, **client_config)
            logger.debug(f"Created {service_name} client for region {self.region}")
            
            return client
            
        except Exception as e:
            logger.error(f"Failed to create {service_name} client: {e}")
            raise AWSServiceError(
                service=service_name,
                operation="CreateClient",
                aws_error=e,
                message=f"Failed to create {service_name} client"
            ) from e


# Global session manager instance
_session_manager: Optional[AWSSessionManager] = None


def get_session_manager(region: Optional[str] = None, profile: Optional[str] = None) -> AWSSessionManager:
    """Get or create global AWS session manager.
    
    Args:
        region: AWS region to use (defaults to configured region)
        profile: AWS profile name to use (defaults to configured profile)
        
    Returns:
        AWSSessionManager: Global session manager instance
    """
    global _session_manager
    
    # Create new session manager if needed or if parameters changed
    if (_session_manager is None or 
        _session_manager.region != (region or AWS_REGION) or
        _session_manager.profile != (profile or get_aws_profile())):
        
        _session_manager = AWSSessionManager(region=region, profile=profile)
    
    return _session_manager


def create_aws_client(service_name: str, region: Optional[str] = None, profile: Optional[str] = None, **kwargs) -> Any:
    """Create AWS service client with global session manager.
    
    Args:
        service_name: AWS service name (e.g., 'securityhub', 'guardduty')
        region: AWS region to use (defaults to configured region)
        profile: AWS profile name to use (defaults to configured profile)
        **kwargs: Additional client configuration
        
    Returns:
        AWS service client
    """
    session_manager = get_session_manager(region=region, profile=profile)
    return session_manager.create_client(service_name, **kwargs)


def get_caller_identity(region: Optional[str] = None, profile: Optional[str] = None) -> Dict[str, Any]:
    """Get caller identity using global session manager.
    
    Args:
        region: AWS region to use (defaults to configured region)
        profile: AWS profile name to use (defaults to configured profile)
        
    Returns:
        Dict[str, Any]: Caller identity information
    """
    session_manager = get_session_manager(region=region, profile=profile)
    return session_manager.get_caller_identity()


def validate_aws_access() -> Dict[str, Any]:
    """Validate AWS access and return status information.
    
    Returns:
        Dict[str, Any]: Validation status and identity information
        
    Raises:
        AuthenticationError: If validation fails
    """
    try:
        session_manager = get_session_manager()
        identity = session_manager.get_caller_identity()
        
        return {
            "status": "valid",
            "account": identity["account"],
            "region": session_manager.region,
            "profile": session_manager.profile,
            "read_only_mode": is_read_only_mode(),
            "validated_at": session_manager._validated_at.isoformat() if session_manager._validated_at else None
        }
        
    except Exception as e:
        logger.error(f"AWS access validation failed: {e}")
        raise