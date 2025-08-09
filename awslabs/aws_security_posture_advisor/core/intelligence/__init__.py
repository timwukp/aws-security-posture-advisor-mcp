"""Intelligence engines for AWS Security Posture Advisor.

This module contains the core intelligence engines that provide advanced security
analysis capabilities:

- Risk Correlation Engine: Correlates findings across services to identify attack patterns
- Compliance Intelligence Engine: Provides compliance assessment and gap analysis
- Remediation Advisor Engine: Generates prioritized security recommendations

These engines work together to transform raw security findings into actionable
business intelligence.
"""

from .risk_correlation import RiskCorrelationEngine, AttackPattern, RiskAssessment
from .compliance import ComplianceIntelligence, ComplianceGap, ComplianceEvidence, RemediationTimeline, ComplianceAssessment
from .remediation import RemediationAdvisor, SecurityRecommendation, RemediationPlan, RemediationValidationResult

__all__ = [
    # Risk Correlation
    "RiskCorrelationEngine",
    "AttackPattern", 
    "RiskAssessment",
    
    # Compliance Intelligence
    "ComplianceIntelligence",
    "ComplianceGap",
    "ComplianceEvidence", 
    "RemediationTimeline",
    "ComplianceAssessment",
    
    # Remediation Advisor
    "RemediationAdvisor",
    "SecurityRecommendation",
    "RemediationPlan",
    "RemediationValidationResult"
]