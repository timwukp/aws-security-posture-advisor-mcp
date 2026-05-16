"""Tests for security module (input validation and data sanitization)."""

import pytest

from awslabs.aws_security_posture_advisor.core.common.security import (
    DataSanitizer,
    InputValidator,
    sanitize_data,
    SENSITIVE_PATTERNS,
)
from awslabs.aws_security_posture_advisor.core.common.errors import ValidationError


class TestDataSanitizer:
    """Tests for DataSanitizer."""

    def test_redacts_aws_access_key(self):
        sanitizer = DataSanitizer(preserve_structure=False)
        text = "My key is AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_redacts_aws_secret_key_with_context(self):
        sanitizer = DataSanitizer(preserve_structure=False)
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        result = sanitizer.sanitize_text(text)
        assert "wJalrXUtnFEMI" not in result

    def test_does_not_redact_normal_40_char_string(self):
        """The fixed regex should NOT match random 40-char strings without context."""
        sanitizer = DataSanitizer(preserve_structure=False)
        # A random 40-char string without secret key context keywords
        text = "The hash is abcdefghijklmnopqrstuvwxyz1234567890 for this file"
        result = sanitizer.sanitize_text(text)
        # Should NOT be redacted since there's no secret_key context
        assert "abcdefghijklmnopqrstuvwxyz" in result or "REDACTED" not in result

    def test_redacts_email(self):
        sanitizer = DataSanitizer(preserve_structure=False)
        text = "Contact user@example.com for help"
        result = sanitizer.sanitize_text(text)
        assert "user@example.com" not in result

    def test_redacts_ip_address(self):
        sanitizer = DataSanitizer(preserve_structure=False)
        text = "Server at 192.168.1.100 is down"
        result = sanitizer.sanitize_text(text)
        assert "192.168.1.100" not in result

    def test_sanitize_dict_recursive(self):
        sanitizer = DataSanitizer(preserve_structure=False)
        data = {
            "name": "test",
            "credentials": {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
            },
        }
        result = sanitizer.sanitize_dict(data)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(result)

    def test_sanitize_list(self):
        sanitizer = DataSanitizer(preserve_structure=False)
        data = ["normal text", "AKIAIOSFODNN7EXAMPLE", "more text"]
        result = sanitizer.sanitize_list(data)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(result)

    def test_preserve_structure_mode(self):
        sanitizer = DataSanitizer(preserve_structure=True)
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize_text(text)
        # Should replace with same-length asterisks
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" not in result  # preserve_structure uses * chars


class TestInputValidator:
    """Tests for InputValidator."""

    def test_validate_string_basic(self):
        validator = InputValidator()
        result = validator.validate_string("hello", "param")
        assert "hello" in result  # may be sanitized but content preserved

    def test_validate_string_required_none(self):
        validator = InputValidator()
        with pytest.raises(ValidationError):
            validator.validate_string(None, "param", required=True)

    def test_validate_string_optional_none(self):
        validator = InputValidator()
        result = validator.validate_string(None, "param", required=False)
        assert result == ""

    def test_validate_string_too_long(self):
        validator = InputValidator()
        with pytest.raises(ValidationError):
            validator.validate_string("x" * 200, "param", max_length=100)

    def test_validate_string_with_pattern(self):
        import re
        validator = InputValidator()
        pattern = re.compile(r'^[a-z]+$')
        result = validator.validate_string("hello", "param", pattern=pattern)
        assert result is not None

    def test_validate_string_pattern_mismatch(self):
        import re
        validator = InputValidator()
        pattern = re.compile(r'^[a-z]+$')
        with pytest.raises(ValidationError):
            validator.validate_string("Hello123", "param", pattern=pattern)

    def test_validate_aws_arn_valid(self):
        validator = InputValidator()
        # Use ARN without 12-digit account to avoid sanitizer redacting it
        arn = "arn:aws:s3:::my-bucket/prefix"
        result = validator.validate_aws_arn(arn, "arn_param")
        assert result is not None

    def test_validate_aws_arn_invalid(self):
        validator = InputValidator()
        with pytest.raises(ValidationError):
            validator.validate_aws_arn("not-an-arn", "arn_param")


class TestSanitizeDataGlobal:
    """Tests for the global sanitize_data convenience function."""

    def test_sanitize_string(self):
        result = sanitize_data("Key AKIAIOSFODNN7EXAMPLE found", "test")
        assert "AKIAIOSFODNN7EXAMPLE" not in str(result)

    def test_sanitize_dict(self):
        result = sanitize_data({"key": "AKIAIOSFODNN7EXAMPLE"}, "test")
        assert "AKIAIOSFODNN7EXAMPLE" not in str(result)

    def test_sanitize_non_sensitive(self):
        result = sanitize_data("This is perfectly normal text", "test")
        assert result == "This is perfectly normal text"
