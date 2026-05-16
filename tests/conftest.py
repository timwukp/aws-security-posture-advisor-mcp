"""Shared pytest fixtures for AWS Security Posture Advisor tests."""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from awslabs.aws_security_posture_advisor.core.common.models import (
    SecurityFinding,
    SeverityLevel,
    FindingStatus,
    RecordState,
    WorkflowState,
    ComplianceControl,
    ComplianceStatus,
)


@pytest.fixture
def sample_finding():
    """Create a sample SecurityFinding for testing."""
    return SecurityFinding(
        finding_id="arn:aws:securityhub:us-east-1:123456789012:finding/test-1",
        product_arn="arn:aws:securityhub:us-east-1::product/aws/securityhub",
        generator_id="aws-foundational-security-best-practices/v/1.0.0/IAM.1",
        title="IAM root user access key should not exist",
        description="This control checks whether the root user access key is available.",
        severity=SeverityLevel.CRITICAL,
        confidence=99,
        record_state=RecordState.ACTIVE,
        workflow_state=WorkflowState.NEW,
        finding_status=FindingStatus.NEW,
        created_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        updated_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        resources=[{"Type": "AwsAccount", "Id": "AWS::::Account:123456789012"}],
        region="us-east-1",
        compliance={"CIS": {"control_id": "1.4"}},
        source_service="SecurityHub",
    )


@pytest.fixture
def sample_findings():
    """Create a list of sample findings with varying severities."""
    base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    findings = [
        SecurityFinding(
            finding_id=f"finding-{i}",
            product_arn="arn:aws:securityhub:us-east-1::product/aws/securityhub",
            generator_id=f"generator-{i}",
            title=f"Test Finding {i}",
            description=f"Description for finding {i}",
            severity=severity,
            created_at=base_time,
            resources=[{"Type": "AwsEc2Instance", "Id": f"i-{i:017d}"}],
            region="us-east-1",
            source_service="SecurityHub",
        )
        for i, severity in enumerate([
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.LOW,
            SeverityLevel.INFORMATIONAL,
        ])
    ]
    return findings


@pytest.fixture
def sample_compliance_control():
    """Create a sample ComplianceControl."""
    return ComplianceControl(
        control_id="CIS.1.4",
        title="Ensure no root account access key exists",
        description="The root account should not have access keys",
        framework="CIS",
        category="Identity and Access Management",
        status=ComplianceStatus.FAILED,
        severity=SeverityLevel.CRITICAL,
        compliant_resources=0,
        non_compliant_resources=1,
        last_assessed=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for testing without real AWS access."""
    with patch.dict("os.environ", {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_REGION": "us-east-1",
    }):
        yield
