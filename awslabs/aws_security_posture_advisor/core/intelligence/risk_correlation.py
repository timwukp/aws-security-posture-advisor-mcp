"""Risk Correlation Engine for AWS Security Posture Advisor.

This module provides intelligent correlation of security findings across multiple AWS services
to identify attack patterns, multi-stage attacks, and prioritize risks based on contextual analysis.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
from loguru import logger

from ..common.models import SecurityFinding, SeverityLevel
from ..common.errors import SecurityAdvisorError


class AttackStage(Enum):
    """MITRE ATT&CK framework stages."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AttackPattern:
    """Represents an identified attack pattern."""
    pattern_id: str
    name: str
    description: str
    stages: List[AttackStage]
    confidence_score: float
    related_findings: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'pattern_id': self.pattern_id,
            'name': self.name,
            'description': self.description,
            'stages': [stage.value for stage in self.stages],
            'confidence_score': self.confidence_score,
            'related_findings': self.related_findings,
            'mitre_techniques': self.mitre_techniques,
            'severity': self.severity.value,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result."""
    assessment_id: str
    overall_risk_level: RiskLevel
    risk_score: float
    total_findings: int
    correlated_findings: int
    attack_patterns: List[AttackPattern] = field(default_factory=list)
    risk_factors: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'assessment_id': self.assessment_id,
            'overall_risk_level': self.overall_risk_level.value,
            'risk_score': self.risk_score,
            'total_findings': self.total_findings,
            'correlated_findings': self.correlated_findings,
            'attack_patterns': [pattern.to_dict() for pattern in self.attack_patterns],
            'risk_factors': self.risk_factors,
            'recommendations': self.recommendations,
            'timeline': self.timeline,
            'generated_at': self.generated_at.isoformat()
        }


class RiskCorrelationEngine:
    """Advanced risk correlation engine for security findings analysis."""
    
    def __init__(self):
        """Initialize the risk correlation engine."""
        self.attack_patterns_db = self._load_attack_patterns()
        self.correlation_rules = self._load_correlation_rules()
        self.risk_weights = self._load_risk_weights()
        
    def _load_attack_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load known attack patterns from knowledge base."""
        # In a real implementation, this would load from a knowledge base
        return {
            "credential_stuffing": {
                "name": "Credential Stuffing Attack",
                "description": "Multiple failed login attempts followed by successful authentication",
                "stages": [AttackStage.INITIAL_ACCESS, AttackStage.CREDENTIAL_ACCESS],
                "mitre_techniques": ["T1110.004", "T1078"],
                "indicators": ["multiple_failed_logins", "successful_login_after_failures", "unusual_login_location"]
            },
            "privilege_escalation_chain": {
                "name": "Privilege Escalation Chain",
                "description": "Systematic privilege escalation through multiple vectors",
                "stages": [AttackStage.PRIVILEGE_ESCALATION, AttackStage.PERSISTENCE],
                "mitre_techniques": ["T1068", "T1055", "T1543"],
                "indicators": ["privilege_escalation", "persistence_mechanism", "system_modification"]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Pattern",
                "description": "Unauthorized data access and transfer patterns",
                "stages": [AttackStage.COLLECTION, AttackStage.EXFILTRATION],
                "mitre_techniques": ["T1005", "T1041", "T1048"],
                "indicators": ["unusual_data_access", "large_data_transfer", "external_communication"]
            }
        }
    
    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        """Load correlation rules for finding analysis."""
        return [
            {
                "rule_id": "temporal_correlation",
                "description": "Correlate findings within time windows",
                "time_window_minutes": 60,
                "weight": 0.8
            },
            {
                "rule_id": "resource_correlation",
                "description": "Correlate findings on same resources",
                "weight": 0.9
            },
            {
                "rule_id": "service_correlation",
                "description": "Correlate findings across related services",
                "weight": 0.7
            },
            {
                "rule_id": "severity_amplification",
                "description": "Amplify risk when multiple high-severity findings correlate",
                "weight": 1.2
            }
        ]
    
    def _load_risk_weights(self) -> Dict[str, float]:
        """Load risk weighting factors."""
        return {
            "severity_critical": 1.0,
            "severity_high": 0.8,
            "severity_medium": 0.6,
            "severity_low": 0.4,
            "correlation_bonus": 0.3,
            "attack_pattern_bonus": 0.5,
            "temporal_proximity": 0.2,
            "resource_overlap": 0.4
        }
    
    async def analyze_risk(self, findings: List[SecurityFinding]) -> RiskAssessment:
        """Perform comprehensive risk analysis on security findings.
        
        Args:
            findings: List of security findings to analyze
            
        Returns:
            RiskAssessment: Comprehensive risk assessment results
        """
        try:
            assessment_id = self._generate_assessment_id(findings)
            logger.info(f"Starting risk correlation analysis - Assessment ID: {assessment_id}")
            
            # Correlate findings
            correlated_groups = await self._correlate_findings(findings)
            
            # Identify attack patterns
            attack_patterns = await self._identify_attack_patterns(correlated_groups, findings)
            
            # Calculate risk score
            risk_score = await self._calculate_risk_score(findings, correlated_groups, attack_patterns)
            
            # Determine overall risk level
            overall_risk_level = self._determine_risk_level(risk_score)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(attack_patterns, findings)
            
            # Create timeline
            timeline = self._create_timeline(findings, attack_patterns)
            
            # Calculate risk factors
            risk_factors = self._calculate_risk_factors(findings, correlated_groups, attack_patterns)
            
            assessment = RiskAssessment(
                assessment_id=assessment_id,
                overall_risk_level=overall_risk_level,
                risk_score=risk_score,
                total_findings=len(findings),
                correlated_findings=sum(len(group) for group in correlated_groups),
                attack_patterns=attack_patterns,
                risk_factors=risk_factors,
                recommendations=recommendations,
                timeline=timeline
            )
            
            logger.info(f"Risk correlation analysis completed - Risk Level: {overall_risk_level.value}, Score: {risk_score:.2f}")
            return assessment
            
        except Exception as e:
            logger.error(f"Risk correlation analysis failed: {e}")
            raise SecurityAdvisorError(
                message=f"Risk correlation analysis failed: {str(e)}",
                error_type="RiskCorrelationError"
            )
    
    def _generate_assessment_id(self, findings: List[SecurityFinding]) -> str:
        """Generate unique assessment ID based on findings."""
        finding_ids = sorted([f.finding_id for f in findings])
        content = json.dumps(finding_ids, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    async def _correlate_findings(self, findings: List[SecurityFinding]) -> List[List[SecurityFinding]]:
        """Correlate findings based on various criteria."""
        correlated_groups = []
        processed_findings = set()
        
        for finding in findings:
            if finding.finding_id in processed_findings:
                continue
                
            # Find related findings
            related_findings = [finding]
            processed_findings.add(finding.finding_id)
            
            for other_finding in findings:
                if (other_finding.finding_id != finding.finding_id and 
                    other_finding.finding_id not in processed_findings):
                    
                    correlation_score = self._calculate_correlation_score(finding, other_finding)
                    if correlation_score > 0.5:  # Correlation threshold
                        related_findings.append(other_finding)
                        processed_findings.add(other_finding.finding_id)
            
            if len(related_findings) > 1:
                correlated_groups.append(related_findings)
        
        return correlated_groups
    
    def _calculate_correlation_score(self, finding1: SecurityFinding, finding2: SecurityFinding) -> float:
        """Calculate correlation score between two findings."""
        score = 0.0
        
        # Temporal correlation
        if finding1.created_at and finding2.created_at:
            time_diff = abs((finding1.created_at - finding2.created_at).total_seconds())
            if time_diff < 3600:  # Within 1 hour
                score += 0.3
        
        # Resource correlation
        if hasattr(finding1, 'resource_id') and hasattr(finding2, 'resource_id'):
            if finding1.resource_id == finding2.resource_id:
                score += 0.4
        
        # Service correlation
        if finding1.source_service == finding2.source_service:
            score += 0.2
        
        # Severity correlation
        if finding1.severity == finding2.severity and finding1.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            score += 0.1
        
        return min(score, 1.0)
    
    async def _identify_attack_patterns(self, correlated_groups: List[List[SecurityFinding]], 
                                      all_findings: List[SecurityFinding]) -> List[AttackPattern]:
        """Identify attack patterns from correlated findings."""
        attack_patterns = []
        
        for group in correlated_groups:
            # Extract indicators from findings
            indicators = self._extract_indicators(group)
            
            # Match against known patterns
            for pattern_id, pattern_data in self.attack_patterns_db.items():
                confidence = self._calculate_pattern_confidence(indicators, pattern_data["indicators"])
                
                if confidence > 0.6:  # Pattern confidence threshold
                    pattern = AttackPattern(
                        pattern_id=pattern_id,
                        name=pattern_data["name"],
                        description=pattern_data["description"],
                        stages=pattern_data["stages"],
                        confidence_score=confidence,
                        related_findings=[f.finding_id for f in group],
                        mitre_techniques=pattern_data["mitre_techniques"],
                        severity=self._determine_pattern_severity(group),
                        first_seen=min(f.created_at for f in group if f.created_at),
                        last_seen=max(f.created_at for f in group if f.created_at)
                    )
                    attack_patterns.append(pattern)
        
        return attack_patterns
    
    def _extract_indicators(self, findings: List[SecurityFinding]) -> Set[str]:
        """Extract security indicators from findings."""
        indicators = set()
        
        for finding in findings:
            # Extract indicators based on finding type and description
            if "login" in finding.title.lower() and "failed" in finding.description.lower():
                indicators.add("multiple_failed_logins")
            
            if "privilege" in finding.title.lower() or "escalation" in finding.description.lower():
                indicators.add("privilege_escalation")
            
            if "data" in finding.title.lower() and ("access" in finding.description.lower() or 
                                                   "transfer" in finding.description.lower()):
                indicators.add("unusual_data_access")
            
            if "external" in finding.description.lower() or "outbound" in finding.description.lower():
                indicators.add("external_communication")
            
            # Add more indicator extraction logic based on finding patterns
            
        return indicators
    
    def _calculate_pattern_confidence(self, indicators: Set[str], pattern_indicators: List[str]) -> float:
        """Calculate confidence score for pattern matching."""
        if not pattern_indicators:
            return 0.0
        
        matches = len(indicators.intersection(set(pattern_indicators)))
        return matches / len(pattern_indicators)
    
    def _determine_pattern_severity(self, findings: List[SecurityFinding]) -> SeverityLevel:
        """Determine severity level for attack pattern."""
        max_severity = SeverityLevel.LOW
        
        for finding in findings:
            if finding.severity.value > max_severity.value:
                max_severity = finding.severity
        
        return max_severity
    
    async def _calculate_risk_score(self, findings: List[SecurityFinding], 
                                  correlated_groups: List[List[SecurityFinding]],
                                  attack_patterns: List[AttackPattern]) -> float:
        """Calculate overall risk score."""
        base_score = 0.0
        
        # Base score from individual findings
        for finding in findings:
            severity_weight = self.risk_weights.get(f"severity_{finding.severity.value.lower()}", 0.4)
            base_score += severity_weight * 10  # Scale to 0-100
        
        # Correlation bonus
        correlation_bonus = len(correlated_groups) * self.risk_weights.get("correlation_bonus", 0.3) * 10
        
        # Attack pattern bonus
        pattern_bonus = len(attack_patterns) * self.risk_weights.get("attack_pattern_bonus", 0.5) * 10
        
        # Calculate final score
        total_score = base_score + correlation_bonus + pattern_bonus
        
        # Normalize to 0-100 scale
        return min(total_score, 100.0)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level based on score."""
        if risk_score >= 80:
            return RiskLevel.CRITICAL
        elif risk_score >= 60:
            return RiskLevel.HIGH
        elif risk_score >= 40:
            return RiskLevel.MEDIUM
        elif risk_score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    async def _generate_recommendations(self, attack_patterns: List[AttackPattern], 
                                      findings: List[SecurityFinding]) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Pattern-based recommendations
        for pattern in attack_patterns:
            if pattern.pattern_id == "credential_stuffing":
                recommendations.extend([
                    "Implement multi-factor authentication (MFA) for all user accounts",
                    "Enable account lockout policies after failed login attempts",
                    "Monitor and alert on unusual login patterns"
                ])
            elif pattern.pattern_id == "privilege_escalation_chain":
                recommendations.extend([
                    "Review and restrict privileged account permissions",
                    "Implement just-in-time (JIT) access controls",
                    "Enable detailed audit logging for privileged operations"
                ])
            elif pattern.pattern_id == "data_exfiltration":
                recommendations.extend([
                    "Implement data loss prevention (DLP) controls",
                    "Monitor and restrict large data transfers",
                    "Enable encryption for sensitive data at rest and in transit"
                ])
        
        # Severity-based recommendations
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        if critical_findings:
            recommendations.append("Immediately address all critical severity findings")
        
        high_findings = [f for f in findings if f.severity == SeverityLevel.HIGH]
        if len(high_findings) > 5:
            recommendations.append("Prioritize remediation of high-severity findings")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _create_timeline(self, findings: List[SecurityFinding], 
                        attack_patterns: List[AttackPattern]) -> List[Dict[str, Any]]:
        """Create timeline of security events."""
        timeline = []
        
        # Add findings to timeline
        for finding in findings:
            if finding.created_at:
                timeline.append({
                    'timestamp': finding.created_at.isoformat(),
                    'type': 'finding',
                    'event': f"Security finding detected: {finding.title}",
                    'severity': finding.severity.value,
                    'source': finding.source_service
                })
        
        # Add attack patterns to timeline
        for pattern in attack_patterns:
            if pattern.first_seen:
                timeline.append({
                    'timestamp': pattern.first_seen.isoformat(),
                    'type': 'attack_pattern',
                    'event': f"Attack pattern identified: {pattern.name}",
                    'confidence': pattern.confidence_score,
                    'techniques': pattern.mitre_techniques
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _calculate_risk_factors(self, findings: List[SecurityFinding],
                              correlated_groups: List[List[SecurityFinding]],
                              attack_patterns: List[AttackPattern]) -> Dict[str, float]:
        """Calculate detailed risk factors."""
        risk_factors = {}
        
        # Severity distribution
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
        
        total_findings = len(findings)
        if total_findings > 0:
            risk_factors['critical_ratio'] = severity_counts.get('CRITICAL', 0) / total_findings
            risk_factors['high_ratio'] = severity_counts.get('HIGH', 0) / total_findings
            risk_factors['correlation_ratio'] = len(correlated_groups) / total_findings if total_findings > 0 else 0
        
        # Attack pattern factors
        risk_factors['attack_pattern_count'] = len(attack_patterns)
        risk_factors['avg_pattern_confidence'] = (
            sum(p.confidence_score for p in attack_patterns) / len(attack_patterns)
            if attack_patterns else 0.0
        )
        
        # Temporal factors
        if findings:
            finding_times = [f.created_at for f in findings if f.created_at]
            if len(finding_times) > 1:
                time_span = (max(finding_times) - min(finding_times)).total_seconds()
                risk_factors['time_span_hours'] = time_span / 3600
                risk_factors['finding_velocity'] = len(findings) / max(time_span / 3600, 1)
        
        return risk_factors