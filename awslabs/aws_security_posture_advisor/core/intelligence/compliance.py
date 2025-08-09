"""Compliance Intelligence Engine for AWS Security Posture Advisor.

This module implements intelligent compliance assessment, gap analysis, and evidence
collection for various compliance frameworks including CIS, NIST, SOC2, and PCI-DSS.
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from loguru import logger

from ..common.models import (
    SecurityFinding,
    ComplianceControl,
    SeverityLevel,
    ComplianceStatus,
    COMPLIANCE_FRAMEWORK_MAPPINGS,
    get_framework_info,
    is_supported_framework
)
from ..common.errors import IntelligenceEngineError, ComplianceFrameworkError


@dataclass
class ComplianceGap:
    """Represents a gap in compliance requirements."""
    
    gap_id: str
    control_id: str
    framework: str
    title: str
    description: str
    severity: SeverityLevel
    
    # Gap details
    current_status: ComplianceStatus
    required_status: ComplianceStatus
    gap_type: str  # MISSING, PARTIAL, MISCONFIGURED
    
    # Affected resources
    affected_resources: List[str] = field(default_factory=list)
    non_compliant_count: int = 0
    total_resources: int = 0
    
    # Remediation information
    remediation_priority: str = "MEDIUM"
    estimated_effort: str = "MEDIUM"
    remediation_steps: List[str] = field(default_factory=list)
    
    def get_compliance_percentage(self) -> float:
        """Calculate compliance percentage for this gap.
        
        Returns:
            float: Compliance percentage (0.0 to 100.0)
        """
        if self.total_resources == 0:
            return 0.0
        
        compliant_count = self.total_resources - self.non_compliant_count
        return (compliant_count / self.total_resources) * 100.0


@dataclass
class ComplianceEvidence:
    """Represents evidence for compliance validation."""
    
    evidence_id: str
    control_id: str
    evidence_type: str  # CONFIGURATION, LOG, DOCUMENT, AUTOMATED_CHECK
    description: str
    
    # Evidence details
    source: str
    collected_at: datetime
    validity_period: Optional[timedelta] = None
    
    # Evidence content
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
    
    # Validation
    is_valid: bool = True
    validation_notes: str = ""
    
    def is_expired(self) -> bool:
        """Check if evidence has expired.
        
        Returns:
            bool: True if evidence has expired
        """
        if not self.validity_period:
            return False
        
        expiry_time = self.collected_at + self.validity_period
        return datetime.utcnow() > expiry_time


@dataclass
class RemediationTimeline:
    """Represents a timeline for compliance remediation."""
    
    timeline_id: str
    framework: str
    total_gaps: int
    
    # Timeline phases
    immediate_actions: List[Dict[str, Any]] = field(default_factory=list)  # 0-30 days
    short_term_actions: List[Dict[str, Any]] = field(default_factory=list)  # 1-3 months
    medium_term_actions: List[Dict[str, Any]] = field(default_factory=list)  # 3-6 months
    long_term_actions: List[Dict[str, Any]] = field(default_factory=list)  # 6+ months
    
    # Progress tracking
    completed_actions: int = 0
    in_progress_actions: int = 0
    pending_actions: int = 0
    
    # Estimates
    estimated_completion_date: Optional[datetime] = None
    estimated_cost: Optional[float] = None
    estimated_effort_hours: Optional[int] = None
    
    def get_completion_percentage(self) -> float:
        """Calculate completion percentage.
        
        Returns:
            float: Completion percentage (0.0 to 100.0)
        """
        total_actions = (
            self.completed_actions + 
            self.in_progress_actions + 
            self.pending_actions
        )
        
        if total_actions == 0:
            return 0.0
        
        return (self.completed_actions / total_actions) * 100.0


@dataclass
class ComplianceAssessment:
    """Comprehensive compliance assessment result."""
    
    assessment_id: str
    framework: str
    scope: str
    assessment_date: datetime
    
    # Overall compliance metrics
    overall_compliance_score: float
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    not_applicable_controls: int
    
    # Detailed results
    control_results: List[ComplianceControl] = field(default_factory=list)
    compliance_gaps: List[ComplianceGap] = field(default_factory=list)
    evidence_collected: List[ComplianceEvidence] = field(default_factory=list)
    
    # Risk and priority analysis
    high_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    medium_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    low_priority_gaps: List[ComplianceGap] = field(default_factory=list)
    
    # Remediation planning
    remediation_timeline: Optional[RemediationTimeline] = None
    
    # Metadata
    assessor: str = "AWS Security Posture Advisor"
    next_assessment_due: Optional[datetime] = None
    
    def get_compliance_percentage(self) -> float:
        """Calculate overall compliance percentage.
        
        Returns:
            float: Compliance percentage (0.0 to 100.0)
        """
        if self.total_controls == 0:
            return 0.0
        
        return (self.compliant_controls / self.total_controls) * 100.0
    
    def get_risk_level(self) -> str:
        """Determine overall compliance risk level.
        
        Returns:
            str: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        compliance_percentage = self.get_compliance_percentage()
        
        if compliance_percentage >= 95.0:
            return "LOW"
        elif compliance_percentage >= 85.0:
            return "MEDIUM"
        elif compliance_percentage >= 70.0:
            return "HIGH"
        else:
            return "CRITICAL"


class ComplianceIntelligence:
    """Intelligence engine for compliance assessment and gap analysis."""
    
    def __init__(self):
        """Initialize the Compliance Intelligence Engine."""
        self.logger = logger.bind(component="ComplianceIntelligence")
        
        # Framework mappings and control definitions
        self.framework_mappings = COMPLIANCE_FRAMEWORK_MAPPINGS
        
        # Control priority weights
        self.control_priority_weights = {
            "Identity and Access Management": 1.0,
            "Data Protection": 0.9,
            "Network Security": 0.8,
            "Logging and Monitoring": 0.7,
            "Incident Response": 0.8,
            "Business Continuity": 0.6,
            "Risk Management": 0.7,
            "Vendor Management": 0.5
        }
        
        # Evidence collection rules
        self.evidence_rules = self._load_evidence_rules()
    
    def _load_evidence_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load evidence collection rules for different control types.
        
        Returns:
            Dict[str, Dict[str, Any]]: Evidence collection rules
        """
        return {
            "iam_controls": {
                "evidence_types": ["CONFIGURATION", "LOG", "AUTOMATED_CHECK"],
                "sources": ["AWS Config", "CloudTrail", "IAM"],
                "validity_days": 30,
                "required_checks": [
                    "password_policy",
                    "mfa_enabled",
                    "unused_credentials",
                    "privilege_escalation"
                ]
            },
            "data_protection": {
                "evidence_types": ["CONFIGURATION", "AUTOMATED_CHECK"],
                "sources": ["AWS Config", "S3", "RDS", "KMS"],
                "validity_days": 90,
                "required_checks": [
                    "encryption_at_rest",
                    "encryption_in_transit",
                    "backup_configuration",
                    "data_classification"
                ]
            },
            "network_security": {
                "evidence_types": ["CONFIGURATION", "LOG"],
                "sources": ["AWS Config", "VPC Flow Logs", "Security Groups"],
                "validity_days": 60,
                "required_checks": [
                    "security_group_rules",
                    "network_acls",
                    "vpc_configuration",
                    "public_access"
                ]
            },
            "logging_monitoring": {
                "evidence_types": ["CONFIGURATION", "LOG"],
                "sources": ["CloudTrail", "CloudWatch", "AWS Config"],
                "validity_days": 30,
                "required_checks": [
                    "cloudtrail_enabled",
                    "log_retention",
                    "monitoring_alarms",
                    "log_integrity"
                ]
            }
        }
    
    async def assess_compliance(
        self, 
        framework: str, 
        findings: List[SecurityFinding],
        scope: str = "full"
    ) -> ComplianceAssessment:
        """Perform comprehensive compliance assessment.
        
        Args:
            framework: Compliance framework to assess against
            findings: Security findings to analyze
            scope: Assessment scope (full, partial, specific_controls)
            
        Returns:
            ComplianceAssessment: Comprehensive assessment results
            
        Raises:
            ComplianceFrameworkError: If framework is not supported
            IntelligenceEngineError: If assessment fails
        """
        try:
            self.logger.info(f"Starting compliance assessment for {framework}")
            
            # Validate framework
            if not is_supported_framework(framework):
                raise ComplianceFrameworkError(
                    framework=framework,
                    message=f"Framework {framework} is not supported"
                )
            
            framework_info = get_framework_info(framework)
            if not framework_info:
                raise ComplianceFrameworkError(
                    framework=framework,
                    message=f"Framework information not found for {framework}"
                )
            
            # Generate assessment ID
            assessment_id = f"{framework.lower()}_assessment_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            # Map findings to controls
            control_mappings = await self._map_findings_to_controls(
                framework, findings
            )
            
            # Evaluate each control
            control_results = await self._evaluate_controls(
                framework, control_mappings
            )
            
            # Identify compliance gaps
            compliance_gaps = await self._identify_compliance_gaps(
                framework, control_results
            )
            
            # Collect evidence
            evidence_collected = await self._collect_compliance_evidence(
                framework, control_results
            )
            
            # Prioritize gaps
            prioritized_gaps = self._prioritize_compliance_gaps(compliance_gaps)
            
            # Generate remediation timeline
            remediation_timeline = await self._generate_remediation_timeline(
                framework, compliance_gaps
            )
            
            # Calculate metrics
            total_controls = len(control_results)
            compliant_controls = len([
                c for c in control_results 
                if c.status == ComplianceStatus.PASSED
            ])
            non_compliant_controls = len([
                c for c in control_results 
                if c.status == ComplianceStatus.FAILED
            ])
            not_applicable_controls = len([
                c for c in control_results 
                if c.status == ComplianceStatus.NOT_AVAILABLE
            ])
            
            # Calculate overall compliance score
            overall_score = self._calculate_compliance_score(control_results)
            
            assessment = ComplianceAssessment(
                assessment_id=assessment_id,
                framework=framework,
                scope=scope,
                assessment_date=datetime.utcnow(),
                overall_compliance_score=overall_score,
                total_controls=total_controls,
                compliant_controls=compliant_controls,
                non_compliant_controls=non_compliant_controls,
                not_applicable_controls=not_applicable_controls,
                control_results=control_results,
                compliance_gaps=compliance_gaps,
                evidence_collected=evidence_collected,
                high_priority_gaps=prioritized_gaps["high"],
                medium_priority_gaps=prioritized_gaps["medium"],
                low_priority_gaps=prioritized_gaps["low"],
                remediation_timeline=remediation_timeline,
                next_assessment_due=datetime.utcnow() + timedelta(days=90)
            )
            
            self.logger.info(
                f"Compliance assessment complete. Score: {overall_score:.1f}%, "
                f"Gaps: {len(compliance_gaps)}, Controls: {total_controls}"
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Compliance assessment failed: {str(e)}")
            raise IntelligenceEngineError(
                engine="ComplianceIntelligence",
                operation="assess_compliance",
                message=str(e)
            )
    
    # Additional methods would continue here...
    # This is a comprehensive but truncated version due to size constraints
    
    def _calculate_compliance_score(self, control_results: List[ComplianceControl]) -> float:
        """Calculate overall compliance score.
        
        Args:
            control_results: List of evaluated controls
            
        Returns:
            float: Compliance score (0.0 to 100.0)
        """
        if not control_results:
            return 0.0
        
        total_weight = 0.0
        weighted_score = 0.0
        
        for control in control_results:
            # Get weight based on control category
            weight = self.control_priority_weights.get(control.category, 0.5)
            total_weight += weight
            
            # Calculate control score
            if control.status == ComplianceStatus.PASSED:
                control_score = 100.0
            elif control.status == ComplianceStatus.FAILED:
                control_score = 0.0
            elif control.status == ComplianceStatus.WARNING:
                control_score = 50.0
            else:  # NOT_AVAILABLE
                continue  # Skip in scoring
            
            weighted_score += control_score * weight
        
        if total_weight == 0:
            return 0.0
        
        return weighted_score / total_weight
    
    async def _map_findings_to_controls(
        self, 
        framework: str, 
        findings: List[SecurityFinding]
    ) -> Dict[str, List[SecurityFinding]]:
        """Map security findings to compliance controls.
        
        Args:
            framework: Compliance framework
            findings: Security findings to map
            
        Returns:
            Dict[str, List[SecurityFinding]]: Findings mapped to control IDs
        """
        control_mappings = defaultdict(list)
        
        for finding in findings:
            # Check if finding has compliance information
            if finding.compliance:
                for compliance_key, compliance_data in finding.compliance.items():
                    if compliance_key.upper() == framework.upper():
                        if isinstance(compliance_data, dict):
                            control_id = compliance_data.get('control_id')
                            if control_id:
                                control_mappings[control_id].append(finding)
            
            # Also check standards control ARN
            if finding.standards_control_arn:
                # Extract control ID from ARN if it matches the framework
                if framework.upper() in finding.standards_control_arn.upper():
                    # Simple extraction - in practice this would be more sophisticated
                    control_id = finding.standards_control_arn.split('/')[-1]
                    control_mappings[control_id].append(finding)
        
        return dict(control_mappings)
    
    async def _evaluate_controls(
        self, 
        framework: str, 
        control_mappings: Dict[str, List[SecurityFinding]]
    ) -> List[ComplianceControl]:
        """Evaluate compliance controls based on findings.
        
        Args:
            framework: Compliance framework
            control_mappings: Findings mapped to controls
            
        Returns:
            List[ComplianceControl]: Evaluated controls
        """
        control_results = []
        framework_info = get_framework_info(framework)
        
        # For each control in the framework
        for control_id in control_mappings.keys():
            findings = control_mappings[control_id]
            
            # Determine control status based on findings
            failed_findings = [
                f for f in findings 
                if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ]
            warning_findings = [
                f for f in findings 
                if f.severity == SeverityLevel.MEDIUM
            ]
            
            if failed_findings:
                status = ComplianceStatus.FAILED
                severity = SeverityLevel.HIGH
            elif warning_findings:
                status = ComplianceStatus.WARNING
                severity = SeverityLevel.MEDIUM
            else:
                status = ComplianceStatus.PASSED
                severity = SeverityLevel.LOW
            
            # Create compliance control
            control = ComplianceControl(
                control_id=control_id,
                title=f"{framework} Control {control_id}",
                description=f"Compliance control for {framework} framework",
                framework=framework,
                category="General",  # Would be determined from control mapping
                status=status,
                severity=severity,
                compliant_resources=len([f for f in findings if f.severity == SeverityLevel.LOW]),
                non_compliant_resources=len(failed_findings + warning_findings),
                last_assessed=datetime.utcnow()
            )
            
            control_results.append(control)
        
        return control_results
    
    async def _identify_compliance_gaps(
        self, 
        framework: str, 
        control_results: List[ComplianceControl]
    ) -> List[ComplianceGap]:
        """Identify compliance gaps from control evaluation results.
        
        Args:
            framework: Compliance framework
            control_results: Evaluated controls
            
        Returns:
            List[ComplianceGap]: Identified compliance gaps
        """
        gaps = []
        
        for control in control_results:
            if control.status in [ComplianceStatus.FAILED, ComplianceStatus.WARNING]:
                # Determine gap type
                if control.status == ComplianceStatus.FAILED:
                    gap_type = "MISSING" if control.compliant_resources == 0 else "PARTIAL"
                    severity = SeverityLevel.HIGH
                else:
                    gap_type = "PARTIAL"
                    severity = SeverityLevel.MEDIUM
                
                gap = ComplianceGap(
                    gap_id=f"{framework.lower()}_{control.control_id}_gap",
                    control_id=control.control_id,
                    framework=framework,
                    title=f"Gap in {control.title}",
                    description=f"Compliance gap identified in {control.title}",
                    severity=severity,
                    current_status=control.status,
                    required_status=ComplianceStatus.PASSED,
                    gap_type=gap_type,
                    non_compliant_count=control.non_compliant_resources,
                    total_resources=control.compliant_resources + control.non_compliant_resources,
                    remediation_priority="HIGH" if severity == SeverityLevel.HIGH else "MEDIUM",
                    estimated_effort="MEDIUM"
                )
                
                gaps.append(gap)
        
        return gaps
    
    def _prioritize_compliance_gaps(
        self, 
        gaps: List[ComplianceGap]
    ) -> Dict[str, List[ComplianceGap]]:
        """Prioritize compliance gaps by severity and impact.
        
        Args:
            gaps: List of compliance gaps
            
        Returns:
            Dict[str, List[ComplianceGap]]: Gaps categorized by priority
        """
        prioritized = {
            "high": [],
            "medium": [],
            "low": []
        }
        
        for gap in gaps:
            if gap.severity == SeverityLevel.CRITICAL or gap.remediation_priority == "HIGH":
                prioritized["high"].append(gap)
            elif gap.severity == SeverityLevel.HIGH or gap.remediation_priority == "MEDIUM":
                prioritized["medium"].append(gap)
            else:
                prioritized["low"].append(gap)
        
        # Sort each priority level by compliance percentage (worst first)
        for priority_level in prioritized.values():
            priority_level.sort(key=lambda g: g.get_compliance_percentage())
        
        return prioritized
    
    async def _collect_compliance_evidence(
        self, 
        framework: str, 
        control_results: List[ComplianceControl]
    ) -> List[ComplianceEvidence]:
        """Collect evidence for compliance validation.
        
        Args:
            framework: Compliance framework
            control_results: Evaluated controls
            
        Returns:
            List[ComplianceEvidence]: Collected evidence
        """
        evidence_list = []
        
        for control in control_results:
            # Generate evidence based on control type and status
            evidence = ComplianceEvidence(
                evidence_id=f"{control.control_id}_evidence_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                control_id=control.control_id,
                evidence_type="AUTOMATED_CHECK",
                description=f"Automated compliance check for {control.title}",
                source="AWS Security Posture Advisor",
                collected_at=datetime.utcnow(),
                validity_period=timedelta(days=30),
                evidence_data={
                    "control_status": control.status.value,
                    "compliant_resources": control.compliant_resources,
                    "non_compliant_resources": control.non_compliant_resources,
                    "assessment_method": "automated"
                },
                is_valid=True
            )
            
            evidence_list.append(evidence)
        
        return evidence_list
    
    async def _generate_remediation_timeline(
        self, 
        framework: str, 
        gaps: List[ComplianceGap]
    ) -> RemediationTimeline:
        """Generate remediation timeline for compliance gaps.
        
        Args:
            framework: Compliance framework
            gaps: Identified compliance gaps
            
        Returns:
            RemediationTimeline: Generated remediation timeline
        """
        timeline = RemediationTimeline(
            timeline_id=f"{framework.lower()}_remediation_{datetime.utcnow().strftime('%Y%m%d')}",
            framework=framework,
            total_gaps=len(gaps)
        )
        
        # Categorize gaps by remediation timeline
        for gap in gaps:
            action = {
                "gap_id": gap.gap_id,
                "control_id": gap.control_id,
                "title": gap.title,
                "priority": gap.remediation_priority,
                "effort": gap.estimated_effort,
                "status": "pending"
            }
            
            # Assign to timeline phase based on priority and effort
            if gap.severity == SeverityLevel.CRITICAL:
                timeline.immediate_actions.append(action)
            elif gap.severity == SeverityLevel.HIGH:
                timeline.short_term_actions.append(action)
            elif gap.severity == SeverityLevel.MEDIUM:
                timeline.medium_term_actions.append(action)
            else:
                timeline.long_term_actions.append(action)
        
        # Calculate totals
        timeline.pending_actions = len(gaps)
        timeline.estimated_completion_date = datetime.utcnow() + timedelta(days=180)  # 6 months
        
        return timeline