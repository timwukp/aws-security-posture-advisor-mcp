# Contributing to AWS Security Posture Advisor MCP Server

Thank you for your interest in contributing to the AWS Security Posture Advisor MCP Server! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contributing Process](#contributing-process)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Security Guidelines](#security-guidelines)
8. [Documentation](#documentation)
9. [Submitting Changes](#submitting-changes)

## Code of Conduct

This project adheres to the AWS Open Source Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to aws-labs@amazon.com.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- AWS CLI configured with appropriate credentials
- Git for version control
- Basic understanding of AWS security services

### Development Environment

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/aws-security-posture-advisor-mcp.git
   cd aws-security-posture-advisor-mcp
   ```

3. **Set up the development environment**:
   ```bash
   # Create virtual environment
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install development dependencies
   pip install -e ".[dev,test]"
   
   # Install pre-commit hooks
   pre-commit install
   ```

4. **Verify the setup**:
   ```bash
   # Run tests
   pytest
   
   # Run linting
   ruff check .
   black --check .
   mypy .
   ```

## Development Setup

### Project Structure

```
aws-security-posture-advisor-mcp/
├── awslabs/
│   └── aws_security_posture_advisor/
│       ├── core/
│       │   ├── aws/              # AWS service integrations
│       │   ├── intelligence/     # Intelligence engines
│       │   └── common/           # Shared utilities
│       └── server.py             # Main MCP server
├── tests/                        # Test suite
├── docs/                         # Documentation
├── examples/                     # Configuration examples
├── scripts/                      # Utility scripts
└── pyproject.toml               # Project configuration
```

### Environment Variables

Set up your development environment variables:

```bash
# AWS Configuration
export AWS_REGION=us-east-1
export AWS_SECURITY_ADVISOR_PROFILE_NAME=your-profile

# Development Configuration
export FASTMCP_LOG_LEVEL=DEBUG
export AWS_SECURITY_ADVISOR_DEBUG=true
```

## Contributing Process

### 1. Choose an Issue

- Look for issues labeled `good first issue` for beginners
- Check existing issues and discussions before starting work
- Comment on the issue to indicate you're working on it

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 3. Make Changes

- Follow the coding standards outlined below
- Write tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Commit Changes

Use conventional commit messages:

```bash
git commit -m "feat: add new security assessment feature"
git commit -m "fix: resolve authentication error handling"
git commit -m "docs: update API documentation"
```

## Coding Standards

### Python Style

- **Code Formatting**: Use `black` with line length 99
- **Linting**: Use `ruff` for code quality checks
- **Type Hints**: Use `mypy` for static type checking
- **Docstrings**: Follow Google-style docstrings

### Code Quality

```bash
# Format code
black .

# Lint code
ruff check . --fix

# Type checking
mypy .

# Run all quality checks
./scripts/build.sh --skip-tests
```

### Security Guidelines

- **Input Validation**: Always validate and sanitize inputs
- **Error Handling**: Use structured error handling with proper logging
- **Secrets**: Never commit secrets or credentials
- **Dependencies**: Keep dependencies up to date and secure

### Example Code Style

```python
"""Module docstring describing the purpose."""

from typing import Dict, List, Optional
from loguru import logger

from ..common.errors import SecurityAdvisorError
from ..common.security import validate_parameter


class ExampleClass:
    """Class docstring describing the purpose.
    
    Args:
        param1: Description of parameter 1
        param2: Description of parameter 2
    """
    
    def __init__(self, param1: str, param2: Optional[int] = None):
        self.param1 = validate_parameter(param1, "param1", "string")
        self.param2 = param2
    
    async def example_method(self, data: Dict[str, Any]) -> List[str]:
        """Method docstring describing the purpose.
        
        Args:
            data: Input data dictionary
            
        Returns:
            List of processed strings
            
        Raises:
            SecurityAdvisorError: If processing fails
        """
        try:
            # Implementation here
            result = []
            logger.info(f"Processing {len(data)} items")
            return result
            
        except Exception as e:
            logger.error(f"Processing failed: {e}")
            raise SecurityAdvisorError(f"Failed to process data: {e}")
```

## Testing Guidelines

### Test Structure

- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch

from awslabs.aws_security_posture_advisor.core.aws.auth import AWSSessionManager


class TestAWSSessionManager:
    """Test suite for AWSSessionManager."""
    
    @pytest.fixture
    def session_manager(self):
        """Create a test session manager."""
        return AWSSessionManager(region="us-east-1")
    
    def test_session_creation(self, session_manager):
        """Test successful session creation."""
        with patch('boto3.Session') as mock_session:
            session = session_manager.get_session()
            assert session is not None
            mock_session.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_operation(self, session_manager):
        """Test asynchronous operations."""
        # Test implementation
        pass
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_auth.py

# Run with coverage
pytest --cov=awslabs.aws_security_posture_advisor

# Run integration tests
pytest -m integration

# Run tests with specific markers
pytest -m "not live"
```

## Security Guidelines

### Security Review Process

All contributions undergo security review:

1. **Automated Security Scanning**: Code is automatically scanned for vulnerabilities
2. **Manual Review**: Security-sensitive changes receive manual review
3. **Dependency Scanning**: Dependencies are checked for known vulnerabilities

### Security Best Practices

- **Input Validation**: Validate all inputs using the security module
- **Error Handling**: Don't expose sensitive information in error messages
- **Logging**: Sanitize sensitive data before logging
- **Authentication**: Use secure credential handling patterns

### Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead, please email security concerns to: aws-labs-security@amazon.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Documentation

### Documentation Types

- **API Documentation**: Docstrings in code
- **User Documentation**: README and docs/ directory
- **Developer Documentation**: This CONTRIBUTING.md file

### Documentation Standards

- Use clear, concise language
- Include code examples
- Keep documentation up to date with code changes
- Use proper Markdown formatting

### Building Documentation

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build documentation
mkdocs build

# Serve documentation locally
mkdocs serve
```

## Submitting Changes

### Pull Request Process

1. **Ensure tests pass**: All tests must pass before submission
2. **Update documentation**: Include relevant documentation updates
3. **Add changelog entry**: Update CHANGELOG.md with your changes
4. **Create pull request**: Use the provided template

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] Changelog updated
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and security scans
2. **Code Review**: Maintainers review code for quality and security
3. **Testing**: Changes are tested in various environments
4. **Approval**: At least one maintainer approval required
5. **Merge**: Changes are merged to main branch

## Release Process

### Version Management

- Follow [Semantic Versioning](https://semver.org/)
- Use the version management script: `python scripts/version.py`
- Update CHANGELOG.md with release notes

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Version bumped
- [ ] Changelog updated
- [ ] Security review completed
- [ ] Release notes prepared

## Getting Help

### Communication Channels

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Email**: aws-labs@amazon.com for direct contact

### Resources

- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [MCP Protocol Documentation](https://modelcontextprotocol.io/)
- [Python Development Guide](https://docs.python.org/3/tutorial/)

## Recognition

Contributors are recognized in:
- CHANGELOG.md for significant contributions
- GitHub contributors page
- Release notes for major contributions

Thank you for contributing to the AWS Security Posture Advisor MCP Server! Your contributions help make AWS environments more secure for everyone.