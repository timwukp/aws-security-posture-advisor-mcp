"""Tests for core data models."""

import pytest
from datetime import datetime, timezone

from awslabs.aws_security_posture_advisor.core.common.models import (
    SecurityFinding,
    SeverityLevel,
    ComplianceControl,
    ComplianceStatus,
    get_severity_score,
    validate_aws_arn,
    is_supported_framework,
    get_framework_info,
    format_timestamp,
)


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_all_severity_levels_exist(self):
        assert SeverityLevel.INFORMATIONAL == "INFORMATIONAL"
        assert SeverityLevel.LOW == "LOW"
        assert SeverityLevel.MEDIUM == "MEDIUM"
        assert SeverityLevel.HIGH == "HIGH"
        assert SeverityLevel.CRITICAL == "CRITICAL"

    def test_severity_score_ordering(self):
        """Ensure severity scores are in correct ascending order."""
        scores = [
            get_severity_score(SeverityLevel.INFORMATIONAL),
            get_severity_score(SeverityLevel.LOW),
            get_severity_score(SeverityLevel.MEDIUM),
            get_severity_score(SeverityLevel.HIGH),
            get_severity_score(SeverityLevel.CRITICAL),
        ]
        assert scores == sorted(scores)
        assert scores[-1] == 100  # CRITICAL is highest

    def test_severity_score_values(self):
        assert get_severity_score(SeverityLevel.INFORMATIONAL) == 10
        assert get_severity_score(SeverityLevel.LOW) == 25
        assert get_severity_score(SeverityLevel.MEDIUM) == 50
        assert get_severity_score(SeverityLevel.HIGH) == 75
        assert get_severity_score(SeverityLevel.CRITICAL) == 100


class TestSecurityFinding:
    """Tests for SecurityFinding dataclass."""

    def test_get_resource_ids(self, sample_finding):
        ids = sample_finding.get_resource_ids()
        assert "AWS::::Account:123456789012" in ids

    def test_get_resource_types(self, sample_finding):
        types = sample_finding.get_resource_types()
        assert "AwsAccount" in types

    def test_is_compliance_related(self, sample_finding):
        assert sample_finding.is_compliance_related() is True

    def test_get_compliance_frameworks(self, sample_finding):
        frameworks = sample_finding.get_compliance_frameworks()
        assert "CIS" in frameworks

    def test_non_compliance_finding(self):
        finding = SecurityFinding(
            finding_id="test",
            product_arn="arn:aws:securityhub:us-east-1::product/aws/guardduty",
            generator_id="guardduty",
            title="Unusual API call",
            description="Suspicious activity detected",
            severity=SeverityLevel.HIGH,
            source_service="GuardDuty",
        )
        assert finding.is_compliance_related() is False
        assert finding.get_compliance_frameworks() == []


class TestComplianceControl:
    """Tests for ComplianceControl dataclass."""

    def test_compliance_percentage_all_compliant(self):
        control = ComplianceControl(
            control_id="test",
            title="Test",
            description="Test",
            framework="CIS",
            category="Test",
            status=ComplianceStatus.PASSED,
            severity=SeverityLevel.LOW,
            compliant_resources=10,
            non_compliant_resources=0,
        )
        assert control.get_compliance_percentage() == 100.0

    def test_compliance_percentage_partial(self):
        control = ComplianceControl(
            control_id="test",
            title="Test",
            description="Test",
            framework="CIS",
            category="Test",
            status=ComplianceStatus.FAILED,
            severity=SeverityLevel.HIGH,
            compliant_resources=7,
            non_compliant_resources=3,
        )
        assert control.get_compliance_percentage() == 70.0

    def test_compliance_percentage_zero_resources(self):
        control = ComplianceControl(
            control_id="test",
            title="Test",
            description="Test",
            framework="CIS",
            category="Test",
            status=ComplianceStatus.NOT_AVAILABLE,
            severity=SeverityLevel.LOW,
            compliant_resources=0,
            non_compliant_resources=0,
        )
        assert control.get_compliance_percentage() == 0.0


class TestValidateAwsArn:
    """Tests for ARN validation."""

    def test_valid_arn(self):
        assert validate_aws_arn("arn:aws:securityhub:us-east-1:123456789012:finding/abc") is True

    def test_valid_arn_cn(self):
        assert validate_aws_arn("arn:aws-cn:s3:::my-bucket") is True

    def test_valid_arn_govcloud(self):
        assert validate_aws_arn("arn:aws-us-gov:iam::123456789012:role/test") is True

    def test_invalid_arn_empty(self):
        assert validate_aws_arn("") is False

    def test_invalid_arn_not_string(self):
        assert validate_aws_arn(None) is False

    def test_invalid_arn_wrong_prefix(self):
        assert validate_aws_arn("notarn:aws:s3:::bucket") is False

    def test_invalid_arn_too_few_parts(self):
        assert validate_aws_arn("arn:aws:s3") is False


class TestFrameworkHelpers:
    """Tests for compliance framework helpers."""

    def test_supported_frameworks(self):
        assert is_supported_framework("CIS") is True
        assert is_supported_framework("NIST") is True
        assert is_supported_framework("SOC2") is True
        assert is_supported_framework("PCI-DSS") is True

    def test_unsupported_framework(self):
        assert is_supported_framework("HIPAA") is False
        assert is_supported_framework("") is False

    def test_case_insensitive(self):
        assert is_supported_framework("cis") is True
        assert is_supported_framework("Nist") is True

    def test_get_framework_info(self):
        info = get_framework_info("CIS")
        assert info is not None
        assert "name" in info
        assert "version" in info
        assert "categories" in info

    def test_get_framework_info_unknown(self):
        assert get_framework_info("UNKNOWN") is None


class TestFormatTimestamp:
    """Tests for timestamp formatting."""

    def test_none_timestamp(self):
        assert format_timestamp(None) == "N/A"

    def test_utc_timestamp(self):
        ts = datetime(2024, 3, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = format_timestamp(ts)
        assert "2024-03-15" in result
        assert "14:30:45" in result
        assert "UTC" in result

    def test_naive_timestamp_gets_utc(self):
        ts = datetime(2024, 3, 15, 14, 30, 45)
        result = format_timestamp(ts)
        assert "UTC" in result
