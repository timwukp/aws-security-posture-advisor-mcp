"""Tests for intelligence engines (risk correlation, compliance, remediation)."""

import pytest
from datetime import datetime, timezone

from awslabs.aws_security_posture_advisor.core.common.models import (
    SecurityFinding,
    SeverityLevel,
    ComplianceControl,
    ComplianceStatus,
)
from awslabs.aws_security_posture_advisor.core.intelligence.risk_correlation import (
    RiskCorrelationEngine,
    RiskLevel,
    AttackStage,
)
from awslabs.aws_security_posture_advisor.core.intelligence.compliance import (
    ComplianceIntelligence,
    ComplianceGap,
)
from awslabs.aws_security_posture_advisor.core.intelligence.remediation import (
    RemediationAdvisor,
    RemediationPriority,
    RemediationComplexity,
    RemediationCategory,
)


class TestRiskCorrelationEngine:
    """Tests for RiskCorrelationEngine."""

    def test_initialization(self):
        engine = RiskCorrelationEngine()
        assert engine.attack_patterns_db is not None
        assert engine.correlation_rules is not None
        assert engine.risk_weights is not None

    @pytest.mark.asyncio
    async def test_analyze_risk_empty_findings(self):
        engine = RiskCorrelationEngine()
        result = await engine.analyze_risk([])
        assert result.total_findings == 0
        assert result.risk_score == 0.0
        assert result.overall_risk_level == RiskLevel.INFO

    @pytest.mark.asyncio
    async def test_analyze_risk_with_findings(self, sample_findings):
        engine = RiskCorrelationEngine()
        result = await engine.analyze_risk(sample_findings)
        assert result.total_findings == len(sample_findings)
        assert result.risk_score >= 0
        assert result.risk_score <= 100
        assert result.overall_risk_level in list(RiskLevel)

    @pytest.mark.asyncio
    async def test_risk_score_increases_with_severity(self):
        engine = RiskCorrelationEngine()

        low_findings = [
            SecurityFinding(
                finding_id=f"low-{i}",
                product_arn="arn:aws:securityhub:us-east-1::product/aws/securityhub",
                generator_id="gen",
                title="Low finding",
                description="Low severity",
                severity=SeverityLevel.LOW,
                source_service="SecurityHub",
            )
            for i in range(3)
        ]

        high_findings = [
            SecurityFinding(
                finding_id=f"high-{i}",
                product_arn="arn:aws:securityhub:us-east-1::product/aws/securityhub",
                generator_id="gen",
                title="Critical finding",
                description="Critical severity",
                severity=SeverityLevel.CRITICAL,
                source_service="SecurityHub",
            )
            for i in range(3)
        ]

        low_result = await engine.analyze_risk(low_findings)
        high_result = await engine.analyze_risk(high_findings)
        assert high_result.risk_score > low_result.risk_score

    def test_determine_risk_level(self):
        engine = RiskCorrelationEngine()
        assert engine._determine_risk_level(90) == RiskLevel.CRITICAL
        assert engine._determine_risk_level(70) == RiskLevel.HIGH
        assert engine._determine_risk_level(50) == RiskLevel.MEDIUM
        assert engine._determine_risk_level(25) == RiskLevel.LOW
        assert engine._determine_risk_level(5) == RiskLevel.INFO

    def test_determine_pattern_severity(self):
        engine = RiskCorrelationEngine()
        findings = [
            SecurityFinding(
                finding_id="1", product_arn="p", generator_id="g",
                title="t", description="d", severity=SeverityLevel.LOW,
                source_service="s",
            ),
            SecurityFinding(
                finding_id="2", product_arn="p", generator_id="g",
                title="t", description="d", severity=SeverityLevel.CRITICAL,
                source_service="s",
            ),
            SecurityFinding(
                finding_id="3", product_arn="p", generator_id="g",
                title="t", description="d", severity=SeverityLevel.MEDIUM,
                source_service="s",
            ),
        ]
        result = engine._determine_pattern_severity(findings)
        assert result == SeverityLevel.CRITICAL


class TestComplianceIntelligence:
    """Tests for ComplianceIntelligence engine."""

    def test_initialization(self):
        engine = ComplianceIntelligence()
        assert engine.framework_mappings is not None
        assert engine.evidence_rules is not None

    @pytest.mark.asyncio
    async def test_assess_compliance_unsupported_framework(self):
        engine = ComplianceIntelligence()
        from awslabs.aws_security_posture_advisor.core.common.errors import IntelligenceEngineError
        with pytest.raises(IntelligenceEngineError):
            await engine.assess_compliance("HIPAA", [])

    @pytest.mark.asyncio
    async def test_assess_compliance_empty_findings(self):
        engine = ComplianceIntelligence()
        result = await engine.assess_compliance("CIS", [])
        assert result.framework == "CIS"
        assert result.total_controls == 0
        assert result.overall_compliance_score == 0.0

    def test_calculate_compliance_score_all_passed(self):
        engine = ComplianceIntelligence()
        controls = [
            ComplianceControl(
                control_id=f"ctrl-{i}",
                title=f"Control {i}",
                description="desc",
                framework="CIS",
                category="Identity and Access Management",
                status=ComplianceStatus.PASSED,
                severity=SeverityLevel.MEDIUM,
            )
            for i in range(5)
        ]
        score = engine._calculate_compliance_score(controls)
        assert score == 100.0

    def test_calculate_compliance_score_all_failed(self):
        engine = ComplianceIntelligence()
        controls = [
            ComplianceControl(
                control_id="ctrl-1",
                title="Control 1",
                description="desc",
                framework="CIS",
                category="Identity and Access Management",
                status=ComplianceStatus.FAILED,
                severity=SeverityLevel.HIGH,
            )
        ]
        score = engine._calculate_compliance_score(controls)
        assert score == 0.0


class TestRemediationAdvisor:
    """Tests for RemediationAdvisor."""

    def test_initialization(self):
        advisor = RemediationAdvisor()
        assert advisor.remediation_templates is not None
        assert advisor.cost_models is not None
        assert advisor.automation_catalog is not None

    @pytest.mark.asyncio
    async def test_generate_recommendations_empty(self):
        advisor = RemediationAdvisor()
        recs = await advisor.generate_recommendations([])
        assert recs == []

    @pytest.mark.asyncio
    async def test_generate_recommendations_mfa_finding(self):
        advisor = RemediationAdvisor()
        findings = [
            SecurityFinding(
                finding_id="mfa-1",
                product_arn="arn:aws:securityhub:us-east-1::product/aws/securityhub",
                generator_id="cis",
                title="MFA should be enabled for root account",
                description="Multi-factor authentication is not enabled",
                severity=SeverityLevel.CRITICAL,
                source_service="SecurityHub",
            )
        ]
        recs = await advisor.generate_recommendations(findings)
        assert len(recs) >= 1
        # Should match the MFA template
        mfa_recs = [r for r in recs if "MFA" in r.title or "mfa" in r.title.lower() or "Multi-Factor" in r.title]
        assert len(mfa_recs) >= 1

    @pytest.mark.asyncio
    async def test_prioritize_recommendations_order(self):
        advisor = RemediationAdvisor()
        findings = [
            SecurityFinding(
                finding_id="enc-1",
                product_arn="p", generator_id="g",
                title="Unencrypted EBS volume detected",
                description="EBS volume is not encrypted",
                severity=SeverityLevel.HIGH,
                source_service="SecurityHub",
            ),
            SecurityFinding(
                finding_id="mfa-1",
                product_arn="p", generator_id="g",
                title="MFA not enabled for IAM users",
                description="Multi-factor authentication not enabled",
                severity=SeverityLevel.CRITICAL,
                source_service="SecurityHub",
            ),
        ]
        recs = await advisor.generate_recommendations(findings)
        # Critical priority should come first
        if len(recs) >= 2:
            priorities = [r.priority for r in recs]
            priority_order = {
                RemediationPriority.CRITICAL: 4,
                RemediationPriority.HIGH: 3,
                RemediationPriority.MEDIUM: 2,
                RemediationPriority.LOW: 1,
            }
            scores = [priority_order[p] for p in priorities]
            assert scores == sorted(scores, reverse=True)

    def test_classify_finding_type(self):
        advisor = RemediationAdvisor()
        finding = SecurityFinding(
            finding_id="test",
            product_arn="p", generator_id="g",
            title="Security group allows unrestricted access",
            description="0.0.0.0/0 inbound rule detected",
            severity=SeverityLevel.HIGH,
            source_service="SecurityHub",
        )
        result = advisor._classify_finding_type(finding)
        assert result == "configure_security_groups"
