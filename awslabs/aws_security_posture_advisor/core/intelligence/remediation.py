"""Remediation Advisor for AWS Security Posture Advisor.

This module provides intelligent security remediation recommendations with cost-benefit analysis,
automation identification, and step-by-step guidance for security improvements.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
from loguru import logger

from ..common.models import SecurityFinding, SeverityLevel, ComplianceControl
from ..common.errors import SecurityAdvisorError


class RemediationPriority(Enum):
    """Remediation priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RemediationComplexity(Enum):
    """Remediation implementation complexity."""
    SIMPLE = "SIMPLE"
    MODERATE = "MODERATE"
    COMPLEX = "COMPLEX"


class RemediationCategory(Enum):
    """Categories of security remediation."""
    ACCESS_CONTROL = "access_control"
    NETWORK_SECURITY = "network_security"
    DATA_PROTECTION = "data_protection"
    MONITORING = "monitoring"
    COMPLIANCE = "compliance"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    INCIDENT_RESPONSE = "incident_response"
    CONFIGURATION = "configuration"


@dataclass
class RemediationStep:
    """Individual step in a remediation process."""
    step_number: int
    title: str
    description: str
    aws_service: Optional[str] = None
    cli_command: Optional[str] = None
    console_url: Optional[str] = None
    automation_script: Optional[str] = None
    validation_method: Optional[str] = None
    estimated_time_minutes: int = 15
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'step_number': self.step_number,
            'title': self.title,
            'description': self.description,
            'aws_service': self.aws_service,
            'cli_command': self.cli_command,
            'console_url': self.console_url,
            'automation_script': self.automation_script,
            'validation_method': self.validation_method,
            'estimated_time_minutes': self.estimated_time_minutes
        }


@dataclass
class CostBenefitAnalysis:
    """Cost-benefit analysis for remediation."""
    implementation_cost: float
    operational_cost_monthly: float
    risk_reduction_percentage: float
    compliance_improvement: float
    automation_potential: float
    roi_months: Optional[int] = None
    cost_category: str = "MEDIUM"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'implementation_cost': self.implementation_cost,
            'operational_cost_monthly': self.operational_cost_monthly,
            'risk_reduction_percentage': self.risk_reduction_percentage,
            'compliance_improvement': self.compliance_improvement,
            'automation_potential': self.automation_potential,
            'roi_months': self.roi_months,
            'cost_category': self.cost_category
        }


@dataclass
class SecurityRecommendation:
    """Comprehensive security remediation recommendation."""
    recommendation_id: str
    title: str
    description: str
    category: RemediationCategory
    priority: RemediationPriority
    complexity: RemediationComplexity
    affected_findings: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    remediation_steps: List[RemediationStep] = field(default_factory=list)
    cost_benefit: Optional[CostBenefitAnalysis] = None
    automation_available: bool = False
    estimated_effort_hours: float = 2.0
    risk_score_improvement: float = 0.0
    prerequisites: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'recommendation_id': self.recommendation_id,
            'title': self.title,
            'description': self.description,
            'category': self.category.value,
            'priority': self.priority.value,
            'complexity': self.complexity.value,
            'affected_findings': self.affected_findings,
            'affected_resources': self.affected_resources,
            'compliance_frameworks': self.compliance_frameworks,
            'remediation_steps': [step.to_dict() for step in self.remediation_steps],
            'cost_benefit': self.cost_benefit.to_dict() if self.cost_benefit else None,
            'automation_available': self.automation_available,
            'estimated_effort_hours': self.estimated_effort_hours,
            'risk_score_improvement': self.risk_score_improvement,
            'prerequisites': self.prerequisites,
            'references': self.references,
            'created_at': self.created_at.isoformat()
        }


class RemediationAdvisor:
    """Advanced remediation advisor for security improvements."""
    
    def __init__(self):
        """Initialize the remediation advisor."""
        self.remediation_templates = self._load_remediation_templates()
        self.cost_models = self._load_cost_models()
        self.automation_catalog = self._load_automation_catalog()
        
    def _load_remediation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load remediation templates from knowledge base."""
        return {
            "enable_mfa": {
                "title": "Enable Multi-Factor Authentication",
                "description": "Implement MFA for all user accounts to prevent unauthorized access",
                "category": RemediationCategory.ACCESS_CONTROL,
                "complexity": RemediationComplexity.SIMPLE,
                "steps": [
                    {
                        "title": "Enable MFA for root account",
                        "description": "Enable MFA for the AWS root account using virtual or hardware MFA device",
                        "aws_service": "IAM",
                        "cli_command": "aws iam enable-mfa-device --user-name root --serial-number arn:aws:iam::123456789012:mfa/root --authentication-code1 123456 --authentication-code2 654321",
                        "console_url": "https://console.aws.amazon.com/iam/home#/security_credentials"
                    },
                    {
                        "title": "Enable MFA for IAM users",
                        "description": "Enable MFA for all IAM users with console access",
                        "aws_service": "IAM",
                        "automation_script": "enable_mfa_for_users.py"
                    }
                ],
                "automation_available": True,
                "estimated_effort_hours": 1.0,
                "risk_score_improvement": 25.0
            },
            "encrypt_ebs_volumes": {
                "title": "Enable EBS Volume Encryption",
                "description": "Encrypt all EBS volumes to protect data at rest",
                "category": RemediationCategory.DATA_PROTECTION,
                "complexity": RemediationComplexity.MODERATE,
                "steps": [
                    {
                        "title": "Enable default EBS encryption",
                        "description": "Enable default encryption for new EBS volumes",
                        "aws_service": "EC2",
                        "cli_command": "aws ec2 enable-ebs-encryption-by-default"
                    },
                    {
                        "title": "Encrypt existing volumes",
                        "description": "Create encrypted snapshots and replace unencrypted volumes",
                        "aws_service": "EC2",
                        "automation_script": "encrypt_existing_volumes.py"
                    }
                ],
                "automation_available": True,
                "estimated_effort_hours": 4.0,
                "risk_score_improvement": 20.0
            },
            "enable_cloudtrail": {
                "title": "Enable AWS CloudTrail",
                "description": "Enable CloudTrail for comprehensive audit logging",
                "category": RemediationCategory.MONITORING,
                "complexity": RemediationComplexity.SIMPLE,
                "steps": [
                    {
                        "title": "Create CloudTrail",
                        "description": "Create a new CloudTrail with S3 bucket for log storage",
                        "aws_service": "CloudTrail",
                        "cli_command": "aws cloudtrail create-trail --name security-audit-trail --s3-bucket-name security-logs-bucket"
                    },
                    {
                        "title": "Enable log file validation",
                        "description": "Enable log file integrity validation",
                        "aws_service": "CloudTrail",
                        "cli_command": "aws cloudtrail update-trail --name security-audit-trail --enable-log-file-validation"
                    }
                ],
                "automation_available": True,
                "estimated_effort_hours": 2.0,
                "risk_score_improvement": 15.0
            },
            "configure_security_groups": {
                "title": "Secure Security Group Rules",
                "description": "Remove overly permissive security group rules",
                "category": RemediationCategory.NETWORK_SECURITY,
                "complexity": RemediationComplexity.MODERATE,
                "steps": [
                    {
                        "title": "Audit security group rules",
                        "description": "Identify security groups with overly permissive rules (0.0.0.0/0)",
                        "aws_service": "EC2",
                        "automation_script": "audit_security_groups.py"
                    },
                    {
                        "title": "Restrict inbound rules",
                        "description": "Replace 0.0.0.0/0 with specific IP ranges or security groups",
                        "aws_service": "EC2",
                        "validation_method": "Verify no security groups allow 0.0.0.0/0 access"
                    }
                ],
                "automation_available": False,
                "estimated_effort_hours": 6.0,
                "risk_score_improvement": 30.0
            }
        }
    
    def _load_cost_models(self) -> Dict[str, Dict[str, float]]:
        """Load cost models for different remediation types."""
        return {
            "enable_mfa": {
                "implementation_cost": 0.0,
                "operational_cost_monthly": 0.0,
                "risk_reduction_percentage": 80.0
            },
            "encrypt_ebs_volumes": {
                "implementation_cost": 100.0,
                "operational_cost_monthly": 50.0,
                "risk_reduction_percentage": 70.0
            },
            "enable_cloudtrail": {
                "implementation_cost": 50.0,
                "operational_cost_monthly": 25.0,
                "risk_reduction_percentage": 60.0
            },
            "configure_security_groups": {
                "implementation_cost": 200.0,
                "operational_cost_monthly": 0.0,
                "risk_reduction_percentage": 85.0
            }
        }
    
    def _load_automation_catalog(self) -> Dict[str, Dict[str, Any]]:
        """Load automation catalog for remediation tasks."""
        return {
            "enable_mfa_for_users.py": {
                "description": "Automatically enable MFA for all IAM users",
                "language": "python",
                "runtime": "python3.9",
                "execution_time_minutes": 10
            },
            "encrypt_existing_volumes.py": {
                "description": "Encrypt existing EBS volumes with minimal downtime",
                "language": "python",
                "runtime": "python3.9",
                "execution_time_minutes": 30
            },
            "audit_security_groups.py": {
                "description": "Audit and report on security group configurations",
                "language": "python",
                "runtime": "python3.9",
                "execution_time_minutes": 5
            }
        }
    
    async def generate_recommendations(self, findings: List[SecurityFinding], 
                                     compliance_gaps: Optional[List[ComplianceControl]] = None,
                                     priority_filter: Optional[RemediationPriority] = None) -> List[SecurityRecommendation]:
        """Generate prioritized security recommendations.
        
        Args:
            findings: List of security findings to address
            compliance_gaps: Optional compliance control gaps
            priority_filter: Optional filter for recommendation priority
            
        Returns:
            List of prioritized security recommendations
        """
        try:
            logger.info(f"Generating remediation recommendations for {len(findings)} findings")
            
            recommendations = []
            
            # Group findings by type for more effective remediation
            finding_groups = self._group_findings_by_type(findings)
            
            # Generate recommendations for each group
            for finding_type, grouped_findings in finding_groups.items():
                recommendation = await self._create_recommendation_for_findings(
                    finding_type, grouped_findings
                )
                if recommendation:
                    recommendations.append(recommendation)
            
            # Add compliance-based recommendations
            if compliance_gaps:
                compliance_recommendations = await self._generate_compliance_recommendations(
                    compliance_gaps
                )
                recommendations.extend(compliance_recommendations)
            
            # Prioritize recommendations
            prioritized_recommendations = self._prioritize_recommendations(recommendations)
            
            # Filter by priority if specified
            if priority_filter:
                prioritized_recommendations = [
                    rec for rec in prioritized_recommendations 
                    if rec.priority == priority_filter
                ]
            
            logger.info(f"Generated {len(prioritized_recommendations)} remediation recommendations")
            return prioritized_recommendations
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}")
            raise SecurityAdvisorError(
                message=f"Failed to generate recommendations: {str(e)}",
                error_type="RemediationError"
            )