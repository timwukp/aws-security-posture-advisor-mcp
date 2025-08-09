# AWS Security Posture Advisor MCP Server Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY pyproject.toml README.md ./
COPY awslabs/ ./awslabs/

# Install the package
RUN pip install --no-cache-dir -e .

# Production stage
FROM python:3.11-slim as production

# Set build arguments for labels
ARG BUILD_DATE
ARG VERSION=0.1.0
ARG VCS_REF

# Add labels following OCI image spec
LABEL org.opencontainers.image.title="AWS Security Posture Advisor MCP Server" \
      org.opencontainers.image.description="MCP server for AWS security posture assessment and intelligent remediation" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="AWS Labs" \
      org.opencontainers.image.authors="AWS Labs <aws-labs@amazon.com>" \
      org.opencontainers.image.url="https://github.com/awslabs/aws-security-posture-advisor-mcp" \
      org.opencontainers.image.source="https://github.com/awslabs/aws-security-posture-advisor-mcp" \
      org.opencontainers.image.documentation="https://github.com/awslabs/aws-security-posture-advisor-mcp#readme" \
      org.opencontainers.image.licenses="Apache-2.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AWS_REGION=us-east-1 \
    FASTMCP_LOG_LEVEL=INFO \
    AWS_SECURITY_ADVISOR_READ_ONLY=true \
    AWS_SECURITY_ADVISOR_AUDIT_LOGGING=true \
    AWS_SECURITY_ADVISOR_LOG_TO_FILE=false

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r security-advisor && \
    useradd -r -g security-advisor -d /app -s /bin/bash security-advisor

# Create app directory and set permissions
WORKDIR /app
RUN mkdir -p /app/logs /app/cache && \
    chown -R security-advisor:security-advisor /app

# Copy Python environment from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=security-advisor:security-advisor awslabs/ ./awslabs/
COPY --chown=security-advisor:security-advisor pyproject.toml README.md ./

# Install the package in production mode
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER security-advisor

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import awslabs.aws_security_posture_advisor; print('OK')" || exit 1

# Expose port (if needed for HTTP interface)
EXPOSE 8000

# Set default command
CMD ["awslabs.aws-security-posture-advisor"]

# Development stage (optional)
FROM production as development

# Switch back to root for development tools
USER root

# Install development dependencies
RUN pip install --no-cache-dir pytest pytest-asyncio pytest-cov black ruff mypy

# Install additional development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*

# Switch back to non-root user
USER security-advisor

# Override command for development
CMD ["python", "-m", "awslabs.aws_security_posture_advisor.server", "--debug"]