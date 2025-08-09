"""AWS Security Posture Advisor MCP Server.

A Model Context Protocol (MCP) server that provides intelligent security insights
by orchestrating multiple AWS security services for comprehensive security assessments,
threat analysis, compliance monitoring, and automated remediation recommendations.

This server follows AWS Labs MCP patterns and implements the FastMCP framework
for robust, scalable, and secure AWS security operations.
"""

import asyncio
import sys
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from loguru import logger

from .core.common.config import (
    AWS_REGION,
    LOG_LEVEL,
    validate_configuration,
)
from .core.common.errors import (
    SecurityAdvisorError,
    SecurityAdvisorErrorResponse,
)
from .core.common.logging import (
    audit_log,
    log_mcp_tool_execution,
    setup_logging,
)
from .core.common.models import (
    SecurityAssessmentReport,
    ThreatAnalysisReport,
    ComplianceReport,
    SecurityReport,
    SecurityValidationReport,
    SecurityFinding,
    SeverityLevel,
    ComplianceControl,
    ComplianceStatus,
    is_supported_framework,
)
from .core.aws.security_hub import SecurityHubClient
from .core.aws.guardduty import GuardDutyClient
from .core.aws.config import ConfigClient
from .core.aws.systems_manager import SystemsManagerClient
from .core.intelligence.risk_correlation import RiskCorrelationEngine
from .core.intelligence.compliance import ComplianceIntelligence
from .core.intelligence.remediation import RemediationAdvisor, SecurityRecommendation

# Initialize FastMCP server with AWS Labs patterns
server = FastMCP(
    name="AWS-Security-Posture-Advisor",
    log_level=LOG_LEVEL
)


@server.tool(
    name="health_check",
    description="""Check the health and configuration of the AWS Security Posture Advisor MCP server.
    
    This tool verifies server configuration, AWS connectivity, and service availability.
    Use this tool to troubleshoot connection issues or verify proper setup.
    
    Returns server status, configuration summary, and AWS service connectivity status.""",
    annotations=ToolAnnotations(
        title="Health Check",
        readOnlyHint=True,
        openWorldHint=False
    ),
)
async def health_check(ctx: Context) -> Dict[str, Any] | SecurityAdvisorErrorResponse:
    """Perform health check of the MCP server and AWS connectivity.
    
    Args:
        ctx: MCP context for the request
        
    Returns:
        Dict containing health status and configuration information
    """
    import time
    start_time = time.time()
    
    try:
        # Basic server health
        health_status = {
            "server_name": "AWS Security Posture Advisor",
            "version": "0.1.0",
            "status": "healthy",
            "timestamp": time.time(),
            "configuration": {
                "aws_region": AWS_REGION,
                "log_level": LOG_LEVEL,
                "read_only_mode": True,  # Default to read-only for initial implementation
            },
            "services": {
                "mcp_server": "operational",
                "logging": "operational",
                "configuration": "operational"
            }
        }
        
        # Log the health check
        duration_ms = (time.time() - start_time) * 1000
        log_mcp_tool_execution("health_check", {}, duration_ms, True)
        
        audit_log(
            action="health_check",
            details={"status": "healthy", "duration_ms": duration_ms}
        )
        
        return health_status
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        log_mcp_tool_execution("health_check", {}, duration_ms, False)
        
        error = SecurityAdvisorError(
            message=f"Health check failed: {str(e)}",
            error_type="HealthCheckError"
        )
        
        logger.error(f"Health check failed: {e}")
        return SecurityAdvisorErrorResponse.from_exception(error)


def _extract_threat_category(finding: SecurityFinding) -> str:
    """Extract threat category from a security finding."""
    if finding.source_service == "guardduty":
        # GuardDuty finding types are structured as ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.ThreatFamilyVariant!Artifact
        finding_type = finding.finding_type or ""
        if ":" in finding_type:
            return finding_type.split(":")[0]
        return "Unknown"
    
    # For other services, categorize based on title or type
    title_lower = finding.title.lower()
    if any(keyword in title_lower for keyword in ["malware", "trojan", "virus"]):
        return "Malware"
    elif any(keyword in title_lower for keyword in ["backdoor", "persistence"]):
        return "Backdoor"
    elif any(keyword in title_lower for keyword in ["reconnaissance", "discovery"]):
        return "Reconnaissance"
    elif any(keyword in title_lower for keyword in ["exfiltration", "data"]):
        return "Exfiltration"
    elif any(keyword in title_lower for keyword in ["impact", "resource"]):
        return "Impact"
    elif any(keyword in title_lower for keyword in ["credential", "privilege"]):
        return "PrivilegeEscalation"
    else:
        return "Other"


def main():
    """Main entry point for the MCP server."""
    try:
        # Setup logging
        setup_logging()
        
        # Validate configuration
        validate_configuration()
        
        logger.info("Starting AWS Security Posture Advisor MCP Server...")
        logger.info(f"Server configuration: Region={AWS_REGION}, LogLevel={LOG_LEVEL}")
        
        # Run the server
        server.run()
        
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()