"""AWS Security Hub client integration.

This module provides a comprehensive interface to AWS Security Hub, including
finding retrieval, normalization, and compliance standard mapping.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from botocore.exceptions import ClientError
from loguru import logger

from .auth import create_aws_client
from ..common.errors import (
    AWSServiceError, 
    ComplianceFrameworkError,
    exponential_backoff_with_jitter,
    handle_aws_client_error,
    GracefulDegradationMixin,
    ServiceUnavailableError,
    PartialResultError
)
from ..common.cache import cached, get_cache_manager
from ..common.models import (
    SecurityFinding,
    SeverityLevel,
    FindingStatus,
    RecordState,
    WorkflowState,
    ComplianceStatus,
    COMPLIANCE_FRAMEWORK_MAPPINGS,
    is_supported_framework,
)


class SecurityHubClient(GracefulDegradationMixin):
    """AWS Security Hub client with intelligent finding processing.
    
    This client provides high-level operations for retrieving and processing
    Security Hub findings, with built-in normalization and compliance mapping.
    Enhanced with advanced error handling, retry logic, and caching.
    """
    
    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize Security Hub client.
        
        Args:
            region: AWS region (defaults to configured region)
            profile: AWS profile (defaults to configured profile)
        """
        super().__init__()
        self.region = region
        self.profile = profile
        self._client = None
        self._hub_arn = None
        self._enabled_standards = None
    
    def _get_client(self):
        """Get or create Security Hub client."""
        if self._client is None:
            self._client = create_aws_client(
                'securityhub',
                region=self.region,
                profile=self.profile
            )
        return self._client
    
    @exponential_backoff_with_jitter(max_retries=3, base_delay=1.0)
    @handle_aws_client_error("SecurityHub", "DescribeHub")
    @cached(ttl_seconds=300)  # Cache hub status for 5 minutes
    def _ensure_hub_enabled(self) -> bool:
        """Check if Security Hub is enabled in the region.
        
        Returns:
            bool: True if Security Hub is enabled
            
        Raises:
            AWSServiceError: If unable to check hub status
        """
        try:
            client = self._get_client()
            response = client.describe_hub()
            self._hub_arn = response.get('HubArn')
            logger.debug(f"Security Hub is enabled: {self._hub_arn}")
            return True
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            
            if error_code == 'InvalidAccessException':
                logger.warning("Security Hub is not enabled in this region")
                return False
            else:
                logger.error(f"Failed to check Security Hub status: {error_code}")
                raise AWSServiceError(
                    service="SecurityHub",
                    operation="DescribeHub",
                    aws_error=e,
                    message=f"Failed to check Security Hub status: {error_code}"
                ) from e
        
        except Exception as e:
            logger.error(f"Unexpected error checking Security Hub status: {e}")
            raise AWSServiceError(
                service="SecurityHub",
                operation="DescribeHub",
                aws_error=e,
                message="Unexpected error checking Security Hub status"
            ) from e
    
    def get_findings(
        self,
        filters: Optional[Dict[str, Any]] = None,
        max_results: int = 100,
        severity_threshold: Optional[SeverityLevel] = None,
        compliance_frameworks: Optional[List[str]] = None,
        record_state: Optional[RecordState] = None,
        workflow_state: Optional[WorkflowState] = None,
        time_range_days: Optional[int] = None
    ) -> List[SecurityFinding]:
        """Retrieve Security Hub findings with intelligent filtering.
        
        Args:
            filters: Additional Security Hub filters
            max_results: Maximum number of findings to retrieve
            severity_threshold: Minimum severity level to include
            compliance_frameworks: Filter by compliance frameworks
            record_state: Filter by record state
            workflow_state: Filter by workflow state
            time_range_days: Filter findings from last N days
            
        Returns:
            List[SecurityFinding]: Normalized security findings
            
        Raises:
            AWSServiceError: If unable to retrieve findings
        """
        if not self._ensure_hub_enabled():
            logger.warning("Security Hub not enabled, returning empty findings list")
            return []
        
        try:
            client = self._get_client()
            
            # Build filters
            finding_filters = self._build_finding_filters(
                filters=filters,
                severity_threshold=severity_threshold,
                compliance_frameworks=compliance_frameworks,
                record_state=record_state,
                workflow_state=workflow_state,
                time_range_days=time_range_days
            )
            
            # Retrieve findings with pagination
            findings = []
            paginator = client.get_paginator('get_findings')
            
            page_iterator = paginator.paginate(
                Filters=finding_filters,
                MaxResults=min(max_results, 100),  # Security Hub max per page
                PaginationConfig={'MaxItems': max_results}
            )
            
            for page in page_iterator:
                raw_findings = page.get('Findings', [])
                
                # Normalize findings
                for raw_finding in raw_findings:
                    try:
                        normalized_finding = self._normalize_finding(raw_finding)
                        findings.append(normalized_finding)
                    except Exception as e:
                        logger.warning(f"Failed to normalize finding {raw_finding.get('Id', 'unknown')}: {e}")
                        continue
            
            logger.info(f"Retrieved and normalized {len(findings)} Security Hub findings")
            return findings
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"Failed to get Security Hub findings: {error_code}")
            raise AWSServiceError(
                service="SecurityHub",
                operation="GetFindings",
                aws_error=e,
                message=f"Failed to get Security Hub findings: {error_code}"
            ) from e
        
        except Exception as e:
            logger.error(f"Unexpected error getting Security Hub findings: {e}")
            raise AWSServiceError(
                service="SecurityHub",
                operation="GetFindings",
                aws_error=e,
                message="Unexpected error getting Security Hub findings"
            ) from e
    
    def _build_finding_filters(
        self,
        filters: Optional[Dict[str, Any]] = None,
        severity_threshold: Optional[SeverityLevel] = None,
        compliance_frameworks: Optional[List[str]] = None,
        record_state: Optional[RecordState] = None,
        workflow_state: Optional[WorkflowState] = None,
        time_range_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """Build Security Hub finding filters.
        
        Args:
            filters: Base filters to extend
            severity_threshold: Minimum severity level
            compliance_frameworks: Compliance frameworks to include
            record_state: Record state filter
            workflow_state: Workflow state filter
            time_range_days: Filter findings from last N days
            
        Returns:
            Dict[str, Any]: Security Hub filters
        """
        finding_filters = filters.copy() if filters else {}
        
        # Severity filter
        if severity_threshold:
            severity_values = self._get_severity_values_above_threshold(severity_threshold)
            finding_filters['SeverityLabel'] = [
                {'Value': severity, 'Comparison': 'EQUALS'}
                for severity in severity_values
            ]
        
        # Record state filter
        if record_state:
            finding_filters['RecordState'] = [
                {'Value': record_state.value, 'Comparison': 'EQUALS'}
            ]
        
        # Workflow state filter
        if workflow_state:
            finding_filters['WorkflowState'] = [
                {'Value': workflow_state.value, 'Comparison': 'EQUALS'}
            ]
        
        # Time range filter
        if time_range_days:
            from datetime import datetime, timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=time_range_days)
            finding_filters['UpdatedAt'] = [
                {
                    'Start': cutoff_date.isoformat() + 'Z',
                    'DateRange': {'Unit': 'DAYS', 'Value': time_range_days}
                }
            ]
        
        # Compliance framework filter
        if compliance_frameworks:
            # Filter by standards control ARNs that match the frameworks
            standards_arns = []
            for framework in compliance_frameworks:
                if is_supported_framework(framework):
                    framework_arns = self._get_framework_standard_arns(framework)
                    standards_arns.extend(framework_arns)
            
            if standards_arns:
                finding_filters['ComplianceSecurityControlId'] = [
                    {'Value': arn, 'Comparison': 'PREFIX'}
                    for arn in standards_arns
                ]
        
        return finding_filters
    
    def _get_severity_values_above_threshold(self, threshold: SeverityLevel) -> List[str]:
        """Get severity values at or above the threshold.
        
        Args:
            threshold: Minimum severity level
            
        Returns:
            List[str]: Severity values to include
        """
        severity_order = [
            SeverityLevel.INFORMATIONAL,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL
        ]
        
        threshold_index = severity_order.index(threshold)
        return [s.value for s in severity_order[threshold_index:]]
    
    def _normalize_finding(self, raw_finding: Dict[str, Any]) -> SecurityFinding:
        """Normalize a raw Security Hub finding to unified format.
        
        Args:
            raw_finding: Raw Security Hub finding
            
        Returns:
            SecurityFinding: Normalized finding
        """
        # Extract basic information
        finding_id = raw_finding.get('Id', '')
        product_arn = raw_finding.get('ProductArn', '')
        generator_id = raw_finding.get('GeneratorId', '')
        
        title = raw_finding.get('Title', 'Unknown Finding')
        description = raw_finding.get('Description', '')
        
        # Parse severity
        severity_info = raw_finding.get('Severity', {})
        severity_label = severity_info.get('Label', 'MEDIUM').upper()
        try:
            severity = SeverityLevel(severity_label)
        except ValueError:
            logger.warning(f"Unknown severity label: {severity_label}, defaulting to MEDIUM")
            severity = SeverityLevel.MEDIUM
        
        # Parse states
        record_state_str = raw_finding.get('RecordState', 'ACTIVE').upper()
        try:
            record_state = RecordState(record_state_str)
        except ValueError:
            record_state = RecordState.ACTIVE
        
        workflow_info = raw_finding.get('Workflow', {})
        workflow_state_str = workflow_info.get('Status', 'NEW').upper()
        try:
            workflow_state = WorkflowState(workflow_state_str)
        except ValueError:
            workflow_state = WorkflowState.NEW
        
        # Parse timestamps
        created_at = self._parse_timestamp(raw_finding.get('CreatedAt'))
        updated_at = self._parse_timestamp(raw_finding.get('UpdatedAt'))
        first_observed_at = self._parse_timestamp(raw_finding.get('FirstObservedAt'))
        last_observed_at = self._parse_timestamp(raw_finding.get('LastObservedAt'))
        
        # Extract compliance information
        compliance = {}
        standards_control_arn = None
        
        # Check for compliance information
        compliance_info = raw_finding.get('Compliance', {})
        if compliance_info:
            compliance['status'] = compliance_info.get('Status')
            compliance['status_reasons'] = compliance_info.get('StatusReasons', [])
            compliance['security_control_id'] = compliance_info.get('SecurityControlId')
            compliance['associated_standards'] = compliance_info.get('AssociatedStandards', [])
        
        # Extract standards control ARN
        if 'ComplianceSecurityControlId' in raw_finding:
            standards_control_arn = raw_finding['ComplianceSecurityControlId']
        
        # Map to compliance frameworks
        compliance_frameworks = self._extract_compliance_frameworks(raw_finding)
        if compliance_frameworks:
            compliance['frameworks'] = compliance_frameworks
        
        # Extract resources
        resources = raw_finding.get('Resources', [])
        
        # Extract additional context
        network = raw_finding.get('Network', {})
        process = raw_finding.get('Process', {})
        threat_intel_indicators = raw_finding.get('ThreatIntelIndicators', [])
        
        # Extract remediation information
        remediation = {}
        remediation_info = raw_finding.get('Remediation', {})
        if remediation_info:
            remediation['recommendation'] = remediation_info.get('Recommendation', {})
        
        # Source URL
        source_url = raw_finding.get('SourceUrl')
        
        return SecurityFinding(
            finding_id=finding_id,
            product_arn=product_arn,
            generator_id=generator_id,
            title=title,
            description=description,
            severity=severity,
            confidence=severity_info.get('Normalized'),
            record_state=record_state,
            workflow_state=workflow_state,
            created_at=created_at,
            updated_at=updated_at,
            first_observed_at=first_observed_at,
            last_observed_at=last_observed_at,
            resources=resources,
            region=raw_finding.get('Region'),
            partition=raw_finding.get('AwsAccountId'),  # Using account ID as partition
            compliance=compliance,
            standards_control_arn=standards_control_arn,
            source_url=source_url,
            remediation=remediation,
            network=network,
            process=process,
            threat_intel_indicators=threat_intel_indicators,
            raw_finding=raw_finding,
            source_service="SecurityHub"
        )
    
    def _extract_compliance_frameworks(self, raw_finding: Dict[str, Any]) -> List[str]:
        """Extract compliance frameworks from a Security Hub finding.
        
        Args:
            raw_finding: Raw Security Hub finding
            
        Returns:
            List[str]: List of compliance frameworks
        """
        frameworks = []
        
        # Check product ARN for framework indicators
        product_arn = raw_finding.get('ProductArn', '').lower()
        generator_id = raw_finding.get('GeneratorId', '').lower()
        title = raw_finding.get('Title', '').lower()
        
        # Check for framework indicators in various fields
        framework_indicators = {
            'CIS': ['cis', 'center for internet security'],
            'NIST': ['nist', 'cybersecurity framework'],
            'SOC2': ['soc2', 'soc 2'],
            'PCI-DSS': ['pci', 'payment card industry']
        }
        
        for framework, indicators in framework_indicators.items():
            for indicator in indicators:
                if (indicator in product_arn or 
                    indicator in generator_id or 
                    indicator in title):
                    frameworks.append(framework)
                    break
        
        return frameworks
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO timestamp string to datetime object.
        
        Args:
            timestamp_str: ISO timestamp string
            
        Returns:
            Optional[datetime]: Parsed datetime or None
        """
        if not timestamp_str:
            return None
        
        try:
            # Handle different timestamp formats
            if timestamp_str.endswith('Z'):
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                return datetime.fromisoformat(timestamp_str)
        except ValueError as e:
            logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return None