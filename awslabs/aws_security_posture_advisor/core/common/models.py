"""Data models for AWS Security Posture Advisor.

This module defines the core data structures used throughout the security advisor,
providing unified formats for security findings, compliance controls, and other
security-related data.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Security finding severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(str, Enum):
    """Security finding status values."""
    NEW = "NEW"
    NOTIFIED = "NOTIFIED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class ComplianceStatus(str, Enum):
    """Compliance status values."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class RecordState(str, Enum):
    """Record state values."""
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class WorkflowState(str, Enum):
    """Workflow state values."""
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    DEFERRED = "DEFERRED"
    RESOLVED = "RESOLVED"


@dataclass
class SecurityFinding:
    """Unified security finding format.
    
    This class normalizes findings from different AWS security services
    into a consistent format for processing by intelligence engines.
    """
    
    # Core identification
    finding_id: str
    product_arn: str
    generator_id: str
    
    # Basic information
    title: str
    description: str
    severity: SeverityLevel
    confidence: Optional[int] = None
    criticality: Optional[int] = None
    
    # Status and workflow
    record_state: RecordState = RecordState.ACTIVE
    workflow_state: WorkflowState = WorkflowState.NEW
    finding_status: FindingStatus = FindingStatus.NEW
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    first_observed_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None
    
    # Resources and location
    resources: List[Dict[str, Any]] = field(default_factory=list)
    region: Optional[str] = None
    partition: Optional[str] = None
    
    # Compliance and standards
    compliance: Dict[str, Any] = field(default_factory=dict)
    standards_control_arn: Optional[str] = None
    
    # Additional context
    source_url: Optional[str] = None
    remediation: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    process: Dict[str, Any] = field(default_factory=dict)
    threat_intel_indicators: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    raw_finding: Dict[str, Any] = field(default_factory=dict)
    source_service: str = "unknown"
    
    def get_resource_ids(self) -> List[str]:
        """Get list of resource IDs from the finding.
        
        Returns:
            List[str]: Resource IDs
        """
        resource_ids = []
        for resource in self.resources:
            if 'Id' in resource:
                resource_ids.append(resource['Id'])
        return resource_ids
    
    def get_resource_types(self) -> List[str]:
        """Get list of resource types from the finding.
        
        Returns:
            List[str]: Resource types
        """
        resource_types = []
        for resource in self.resources:
            if 'Type' in resource:
                resource_types.append(resource['Type'])
        return list(set(resource_types))  # Remove duplicates
    
    def is_compliance_related(self) -> bool:
        """Check if finding is related to compliance.
        
        Returns:
            bool: True if finding has compliance information
        """
        return bool(self.compliance or self.standards_control_arn)
    
    def get_compliance_frameworks(self) -> List[str]:
        """Get list of compliance frameworks this finding relates to.
        
        Returns:
            List[str]: Compliance framework names
        """
        frameworks = []
        if self.compliance:
            for key in self.compliance.keys():
                if key.upper() in ['CIS', 'NIST', 'SOC2', 'PCI-DSS', 'PCIDSS']:
                    frameworks.append(key.upper())
        return frameworks


@dataclass
class ComplianceControl:
    """Represents a security control mapped to compliance frameworks."""
    
    control_id: str
    title: str
    description: str
    framework: str
    category: str
    status: ComplianceStatus
    severity: SeverityLevel
    
    # Implementation details
    aws_config_rule: Optional[str] = None
    security_hub_control: Optional[str] = None
    remediation_url: Optional[str] = None
    
    # Assessment results
    compliant_resources: int = 0
    non_compliant_resources: int = 0
    not_applicable_resources: int = 0
    
    # Timestamps
    last_assessed: Optional[datetime] = None
    
    def get_compliance_percentage(self) -> float:
        """Calculate compliance percentage.
        
        Returns:
            float: Compliance percentage (0-100)
        """
        total = self.compliant_resources + self.non_compliant_resources
        if total == 0:
            return 0.0
        return (self.compliant_resources / total) * 100.0


# Pydantic models for API responses
class SecurityAssessmentReport(BaseModel):
    """Security assessment report response model."""
    
    assessment_id: str = Field(..., description="Unique assessment identifier")
    scope: str = Field(..., description="Assessment scope")
    target: str = Field(..., description="Assessment target")
    frameworks: List[str] = Field(..., description="Compliance frameworks assessed")
    overall_score: float = Field(..., ge=0, le=100, description="Overall security score")
    risk_level: str = Field(..., description="Overall risk level")
    
    # Summary statistics
    total_findings: int = Field(..., ge=0, description="Total number of findings")
    critical_findings: int = Field(..., ge=0, description="Number of critical findings")
    high_findings: int = Field(..., ge=0, description="Number of high severity findings")
    medium_findings: int = Field(..., ge=0, description="Number of medium severity findings")
    low_findings: int = Field(..., ge=0, description="Number of low severity findings")
    
    # Compliance status
    compliance_status: Dict[str, Any] = Field(default_factory=dict, description="Compliance status by framework")
    
    # Top findings and recommendations
    top_findings: List[Dict[str, Any]] = Field(default_factory=list, description="Top priority findings")
    recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Security recommendations")
    
    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")
    region: Optional[str] = Field(None, description="AWS region")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ThreatAnalysisReport(BaseModel):
    """Threat analysis report response model."""
    
    analysis_id: str = Field(..., description="Unique analysis identifier")
    time_range_start: datetime = Field(..., description="Analysis time range start")
    time_range_end: datetime = Field(..., description="Analysis time range end")
    
    # Threat landscape
    total_threats: int = Field(..., ge=0, description="Total number of threats detected")
    active_threats: int = Field(..., ge=0, description="Number of active threats")
    threat_categories: Dict[str, int] = Field(default_factory=dict, description="Threats by category")
    
    # Attack patterns
    attack_patterns: List[Dict[str, Any]] = Field(default_factory=list, description="Identified attack patterns")
    threat_indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Threat indicators")
    
    # High-risk findings
    high_risk_findings: List[Dict[str, Any]] = Field(default_factory=list, description="High-risk security findings")
    
    # Remediation
    remediation_plan: Dict[str, Any] = Field(default_factory=dict, description="Recommended remediation plan")
    
    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ComplianceReport(BaseModel):
    """Compliance report response model."""
    
    framework: str = Field(..., description="Compliance framework name")
    overall_compliance_score: float = Field(..., ge=0, le=100, description="Overall compliance score")
    
    # Control results
    total_controls: int = Field(..., ge=0, description="Total number of controls")
    passed_controls: int = Field(..., ge=0, description="Number of passed controls")
    failed_controls: int = Field(..., ge=0, description="Number of failed controls")
    not_applicable_controls: int = Field(..., ge=0, description="Number of not applicable controls")
    
    # Detailed results
    control_results: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed control results")
    gaps: List[Dict[str, Any]] = Field(default_factory=list, description="Compliance gaps")
    
    # Evidence and remediation
    evidence: Optional[List[Dict[str, Any]]] = Field(None, description="Compliance evidence")
    remediation_timeline: Optional[Dict[str, Any]] = Field(None, description="Remediation timeline")
    
    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SecurityReport(BaseModel):
    """Comprehensive security report response model."""
    
    report_id: str = Field(..., description="Unique report identifier")
    report_type: str = Field(..., description="Report type (executive, technical, compliance)")
    title: str = Field(..., description="Report title")
    
    # Time period and scope
    time_period_start: datetime = Field(..., description="Report time period start")
    time_period_end: datetime = Field(..., description="Report time period end")
    time_period_days: int = Field(..., ge=1, description="Time period in days")
    
    # Executive summary
    executive_summary: Dict[str, Any] = Field(default_factory=dict, description="Executive summary")
    
    # Security metrics and trends
    security_metrics: Dict[str, Any] = Field(default_factory=dict, description="Security metrics")
    trend_analysis: Dict[str, Any] = Field(default_factory=dict, description="Trend analysis")
    
    # Risk assessment
    overall_risk_score: float = Field(..., ge=0, le=100, description="Overall risk score")
    risk_level: str = Field(..., description="Overall risk level")
    risk_trends: Dict[str, Any] = Field(default_factory=dict, description="Risk trends")
    
    # Findings summary
    findings_summary: Dict[str, Any] = Field(default_factory=dict, description="Findings summary")
    top_threats: List[Dict[str, Any]] = Field(default_factory=list, description="Top security threats")
    
    # Compliance status
    compliance_overview: Dict[str, Any] = Field(default_factory=dict, description="Compliance overview")
    compliance_trends: Dict[str, Any] = Field(default_factory=dict, description="Compliance trends")
    
    # Recommendations and actions
    key_recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Key security recommendations")
    remediation_progress: Dict[str, Any] = Field(default_factory=dict, description="Remediation progress")
    
    # Performance metrics
    security_posture_score: float = Field(..., ge=0, le=100, description="Security posture score")
    improvement_areas: List[Dict[str, Any]] = Field(default_factory=list, description="Areas for improvement")
    
    # Report-specific sections
    detailed_sections: Dict[str, Any] = Field(default_factory=dict, description="Detailed report sections")
    
    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")
    generated_by: str = Field(default="AWS Security Posture Advisor", description="Report generator")
    region: Optional[str] = Field(None, description="AWS region")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SecurityValidationReport(BaseModel):
    """Security control validation report response model."""
    
    validation_id: str = Field(..., description="Unique validation identifier")
    control_ids: List[str] = Field(..., description="List of validated control IDs")
    
    # Validation summary
    total_controls: int = Field(..., ge=0, description="Total number of controls validated")
    passed_controls: int = Field(..., ge=0, description="Number of controls that passed validation")
    failed_controls: int = Field(..., ge=0, description="Number of controls that failed validation")
    error_controls: int = Field(..., ge=0, description="Number of controls with validation errors")
    
    # Validation results
    validation_results: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed validation results")
    
    # Instance summary
    total_instances: int = Field(..., ge=0, description="Total number of instances validated")
    compliant_instances: int = Field(..., ge=0, description="Number of compliant instances")
    non_compliant_instances: int = Field(..., ge=0, description="Number of non-compliant instances")
    
    # Remediation information
    auto_remediation_available: List[str] = Field(default_factory=list, description="Controls with auto-remediation available")
    remediation_recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Remediation recommendations")
    
    # Configuration drift monitoring
    drift_monitoring: Optional[Dict[str, Any]] = Field(None, description="Configuration drift monitoring results")
    
    # Execution details
    execution_time_seconds: float = Field(..., ge=0, description="Total execution time in seconds")
    validation_method: str = Field(default="systems_manager", description="Validation method used")
    
    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")
    region: Optional[str] = Field(None, description="AWS region")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Compliance framework mappings
COMPLIANCE_FRAMEWORK_MAPPINGS = {
    "CIS": {
        "name": "Center for Internet Security",
        "version": "1.4.0",
        "controls_prefix": "CIS",
        "categories": [
            "Identity and Access Management",
            "Storage",
            "Logging",
            "Monitoring",
            "Networking"
        ]
    },
    "NIST": {
        "name": "NIST Cybersecurity Framework",
        "version": "1.1",
        "controls_prefix": "NIST",
        "categories": [
            "Identify",
            "Protect", 
            "Detect",
            "Respond",
            "Recover"
        ]
    },
    "SOC2": {
        "name": "SOC 2 Type II",
        "version": "2017",
        "controls_prefix": "SOC2",
        "categories": [
            "Security",
            "Availability",
            "Processing Integrity",
            "Confidentiality",
            "Privacy"
        ]
    },
    "PCI-DSS": {
        "name": "Payment Card Industry Data Security Standard",
        "version": "3.2.1",
        "controls_prefix": "PCI",
        "categories": [
            "Build and Maintain Secure Networks",
            "Protect Cardholder Data",
            "Maintain Vulnerability Management",
            "Implement Strong Access Control",
            "Regularly Monitor and Test Networks",
            "Maintain Information Security Policy"
        ]
    }
}


def get_framework_info(framework: str) -> Optional[Dict[str, Any]]:
    """Get information about a compliance framework.
    
    Args:
        framework: Framework name (case-insensitive)
        
    Returns:
        Optional[Dict[str, Any]]: Framework information or None if not found
    """
    return COMPLIANCE_FRAMEWORK_MAPPINGS.get(framework.upper())


def is_supported_framework(framework: str) -> bool:
    """Check if a compliance framework is supported.
    
    Args:
        framework: Framework name (case-insensitive)
        
    Returns:
        bool: True if framework is supported
    """
    return framework.upper() in COMPLIANCE_FRAMEWORK_MAPPINGS


def get_severity_score(severity: SeverityLevel) -> int:
    """Convert severity level to numeric score.
    
    Args:
        severity: Severity level enum
        
    Returns:
        int: Numeric score (0-100)
    """
    severity_scores = {
        SeverityLevel.INFORMATIONAL: 10,
        SeverityLevel.LOW: 25,
        SeverityLevel.MEDIUM: 50,
        SeverityLevel.HIGH: 75,
        SeverityLevel.CRITICAL: 100
    }
    return severity_scores.get(severity, 0)


def format_timestamp(timestamp: Optional[datetime]) -> str:
    """Format timestamp for display.
    
    Args:
        timestamp: Datetime object or None
        
    Returns:
        str: Formatted timestamp string
    """
    if timestamp is None:
        return "N/A"
    
    # Ensure timezone awareness
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    
    return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def validate_aws_arn(arn: str) -> bool:
    """Validate AWS ARN format.
    
    Args:
        arn: ARN string to validate
        
    Returns:
        bool: True if valid ARN format
    """
    if not arn or not isinstance(arn, str):
        return False
    
    # Basic ARN format: arn:partition:service:region:account-id:resource
    parts = arn.split(':')
    if len(parts) < 6:
        return False
    
    if parts[0] != 'arn':
        return False
    
    # Partition should be aws, aws-cn, or aws-us-gov
    if parts[1] not in ['aws', 'aws-cn', 'aws-us-gov']:
        return False
    
    return True