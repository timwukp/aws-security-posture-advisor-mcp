"""Tests for error handling framework."""

import pytest
import time
from unittest.mock import patch, MagicMock

from botocore.exceptions import ClientError

from awslabs.aws_security_posture_advisor.core.common.errors import (
    SecurityAdvisorError,
    AWSServiceError,
    AuthenticationError,
    IntelligenceEngineError,
    ComplianceFrameworkError,
    RemediationError,
    ValidationError,
    SecurityAdvisorErrorResponse,
    RetryableError,
    ThrottlingError,
    ServiceUnavailableError,
    PartialResultError,
    GracefulDegradationMixin,
    exponential_backoff_with_jitter,
    _convert_client_error,
    _calculate_backoff_delay,
)


class TestSecurityAdvisorError:
    """Tests for base error class."""

    def test_basic_error(self):
        err = SecurityAdvisorError("Something went wrong")
        assert str(err) == "Something went wrong"
        assert err.message == "Something went wrong"
        assert err.error_type == "SecurityAdvisorError"
        assert err.context == {}

    def test_error_with_type_and_context(self):
        err = SecurityAdvisorError(
            message="Test error",
            error_type="CustomType",
            context={"key": "value"},
        )
        assert err.error_type == "CustomType"
        assert err.context == {"key": "value"}

    def test_as_error_data(self):
        err = SecurityAdvisorError("Test", error_type="TestType")
        error_data = err.as_error_data()
        assert error_data.code == -32000
        assert error_data.message == "Test"


class TestAWSServiceError:
    """Tests for AWS service errors."""

    def test_aws_service_error(self):
        original = Exception("Connection timeout")
        err = AWSServiceError(
            service="SecurityHub",
            operation="GetFindings",
            aws_error=original,
        )
        assert "SecurityHub" in err.message
        assert "GetFindings" in err.message
        assert err.context["service"] == "SecurityHub"
        assert err.context["operation"] == "GetFindings"

    def test_custom_message(self):
        err = AWSServiceError(
            service="GuardDuty",
            operation="ListDetectors",
            aws_error=Exception("err"),
            message="Custom message",
        )
        assert err.message == "Custom message"


class TestAuthenticationError:
    """Tests for authentication errors."""

    def test_basic_auth_error(self):
        err = AuthenticationError("Invalid credentials")
        assert "Invalid credentials" in err.message
        assert err.error_type == "AuthenticationError"

    def test_with_credential_type(self):
        err = AuthenticationError("Bad profile", credential_type="profile")
        assert err.context["credential_type"] == "profile"


class TestValidationError:
    """Tests for validation errors."""

    def test_validation_error(self):
        err = ValidationError("scope", "invalid_value", "Must be one of: account, region")
        assert "scope" in err.message
        assert err.context["parameter"] == "scope"
        assert err.context["value_type"] == "str"


class TestSecurityAdvisorErrorResponse:
    """Tests for error response model."""

    def test_from_exception(self):
        err = SecurityAdvisorError("Test error", error_type="TestType", context={"k": "v"})
        response = SecurityAdvisorErrorResponse.from_exception(err)
        assert response.detail == "Test error"
        assert response.error_type == "TestType"
        assert response.context == {"k": "v"}


class TestRetryableErrors:
    """Tests for retryable error types."""

    def test_throttling_error(self):
        err = ThrottlingError("SecurityHub", retry_after=30.0)
        assert "throttled" in err.message
        assert err.retry_after == 30.0
        assert isinstance(err, RetryableError)

    def test_service_unavailable(self):
        err = ServiceUnavailableError("GuardDuty", retry_after=60.0)
        assert "unavailable" in err.message
        assert err.retry_after == 60.0


class TestConvertClientError:
    """Tests for AWS ClientError conversion."""

    def _make_client_error(self, code: str) -> ClientError:
        return ClientError(
            {"Error": {"Code": code, "Message": "test"}},
            "TestOperation",
        )

    def test_throttling(self):
        err = _convert_client_error(
            self._make_client_error("Throttling"), "SecurityHub", "GetFindings"
        )
        assert isinstance(err, ThrottlingError)

    def test_service_unavailable(self):
        err = _convert_client_error(
            self._make_client_error("ServiceUnavailable"), "GuardDuty", "GetFindings"
        )
        assert isinstance(err, ServiceUnavailableError)

    def test_access_denied(self):
        err = _convert_client_error(
            self._make_client_error("AccessDenied"), "Config", "Describe"
        )
        assert isinstance(err, AuthenticationError)

    def test_other_error(self):
        err = _convert_client_error(
            self._make_client_error("ResourceNotFound"), "SSM", "GetDoc"
        )
        assert isinstance(err, AWSServiceError)


class TestExponentialBackoff:
    """Tests for retry decorator."""

    def test_succeeds_first_try(self):
        call_count = {"n": 0}

        @exponential_backoff_with_jitter(max_retries=3, base_delay=0.01)
        def successful_func():
            call_count["n"] += 1
            return "success"

        result = successful_func()
        assert result == "success"
        assert call_count["n"] == 1

    def test_retries_on_retryable_error(self):
        call_count = {"n": 0}

        @exponential_backoff_with_jitter(max_retries=2, base_delay=0.01)
        def flaky_func():
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise ThrottlingError("TestService")
            return "recovered"

        result = flaky_func()
        assert result == "recovered"
        assert call_count["n"] == 3

    def test_does_not_retry_non_retryable(self):
        @exponential_backoff_with_jitter(max_retries=3, base_delay=0.01)
        def always_fails():
            raise ValueError("permanent error")

        with pytest.raises(ValueError, match="permanent error"):
            always_fails()


class TestBackoffDelay:
    """Tests for backoff delay calculation."""

    def test_increases_with_attempts(self):
        d0 = _calculate_backoff_delay(0, base_delay=1.0, max_delay=60.0)
        d1 = _calculate_backoff_delay(1, base_delay=1.0, max_delay=60.0)
        d2 = _calculate_backoff_delay(2, base_delay=1.0, max_delay=60.0)
        # Each should be roughly double (with jitter)
        assert d1 > d0
        assert d2 > d1

    def test_respects_max_delay(self):
        delay = _calculate_backoff_delay(100, base_delay=1.0, max_delay=5.0)
        # With jitter up to 30%, max is 5.0 * 1.3 = 6.5
        assert delay <= 6.5


class TestGracefulDegradation:
    """Tests for graceful degradation mixin."""

    def test_mark_and_check_degraded(self):
        class TestService(GracefulDegradationMixin):
            def __init__(self):
                super().__init__()

        svc = TestService()
        assert svc.is_service_degraded("SecurityHub") is False
        svc.mark_service_degraded("SecurityHub")
        assert svc.is_service_degraded("SecurityHub") is True

    def test_clear_degradation(self):
        class TestService(GracefulDegradationMixin):
            def __init__(self):
                super().__init__()

        svc = TestService()
        svc.mark_service_degraded("GuardDuty")
        svc.clear_service_degradation("GuardDuty")
        assert svc.is_service_degraded("GuardDuty") is False
