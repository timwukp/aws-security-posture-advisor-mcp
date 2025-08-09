# AWS Security Posture Advisor MCP Server - API Documentation

## Overview

The AWS Security Posture Advisor MCP Server provides intelligent security insights through a comprehensive set of MCP tools that orchestrate multiple AWS security services. This document provides detailed API documentation for all available tools, their parameters, and response formats.

## Tool Categories

### Core Assessment Tools
- [`assess_security_posture`](#assess_security_posture) - Comprehensive security assessment
- [`analyze_security_findings`](#analyze_security_findings) - Threat analysis and correlation
- [`check_compliance_status`](#check_compliance_status) - Compliance framework assessment

### Advanced Security Tools
- [`recommend_security_improvements`](#recommend_security_improvements) - Security recommendations
- [`investigate_security_incident`](#investigate_security_incident) - Incident investigation
- [`generate_security_report`](#generate_security_report) - Security reporting
- [`validate_security_controls`](#validate_security_controls) - Control validation

### Utility Tools
- [`health_check`](#health_check) - Server health verification
- [`get_server_info`](#get_server_info) - Server capabilities information

---

## Core Assessment Tools

### assess_security_posture

Performs comprehensive security assessment across AWS infrastructure by orchestrating multiple AWS security services.

**Description:**
This tool provides a unified view of your security posture by querying Security Hub, GuardDuty, Config, Inspector, CloudTrail, and Macie services. It performs multi-framework compliance assessment and generates prioritized findings with contextual recommendations.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `scope` | string | Yes | - | Assessment scope. Valid values: `account`, `region`, `service`, `workload` |
| `target` | string | Yes | - | Assessment target (account ID, region name, service name, or workload identifier) |
| `frameworks` | array[string] | No | `["CIS"]` | Compliance frameworks to assess against. Valid values: `CIS`, `NIST`, `SOC2`, `PCI-DSS` |
| `severity_threshold` | string | No | `"MEDIUM"` | Minimum severity level to include. Valid values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `include_recommendations` | boolean | No | `true` | Whether to include security recommendations in the response |

**Response Format:**
```json
{
  "assessment_id": "string",
  "scope": "string",
  "target": "string", 
  "frameworks": ["string"],
  "overall_score": "number (0-100)",
  "risk_level": "string (LOW|MEDIUM|HIGH|CRITICAL)",
  "total_findings": "number",
  "critical_findings": "number",
  "high_findings": "number",
  "medium_findings": "number",
  "low_findings": "number",
  "compliance_status": {
    "framework_name": {
      "overall_score": "number (0-100)",
      "status": "string (COMPLIANT|NON_COMPLIANT)",
      "passed_controls": "number",
      "failed_controls": "number",
      "total_controls": "number"
    }
  },
  "top_findings": [
    {
      "finding_id": "string",
      "title": "string",
      "severity": "string",
      "description": "string",
      "source_service": "string",
      "resource_count": "number",
      "compliance_frameworks": ["string"]
    }
  ],
  "recommendations": [
    {
      "recommendation_id": "string",
      "title": "string",
      "priority": "string",
      "description": "string",
      "affected_resources": "number",
      "compliance_impact": ["string"],
      "automation_available": "boolean"
    }
  ],
  "region": "string",
  "generated_at": "string (ISO 8601)"
}
```

**Example Usage:**
```json
{
  "scope": "account",
  "target": "123456789012",
  "frameworks": ["CIS", "NIST"],
  "severity_threshold": "HIGH",
  "include_recommendations": true
}
```

---

### analyze_security_findings

Analyzes security findings with intelligent threat correlation and remediation guidance.

**Description:**
This tool performs comprehensive threat analysis by correlating security findings from GuardDuty, Security Hub, and other AWS security services. It identifies attack patterns, behavioral anomalies, and provides prioritized remediation guidance.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `severity_threshold` | string | No | `"MEDIUM"` | Minimum severity level to include. Valid values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `time_range_days` | number | No | `30` | Number of days to look back for findings (1-365) |
| `include_remediation` | boolean | No | `true` | Whether to include remediation guidance |
| `max_findings` | number | No | `500` | Maximum number of findings to analyze (1-1000) |

**Response Format:**
```json
{
  "analysis_id": "string",
  "time_range": {
    "start_date": "string (ISO 8601)",
    "end_date": "string (ISO 8601)",
    "days": "number"
  },
  "threat_landscape": {
    "total_threats": "number",
    "active_threats": "number",
    "threat_categories": {
      "category_name": "number"
    },
    "risk_score": "number (0-100)",
    "trend": "string (INCREASING|STABLE|DECREASING)"
  },
  "attack_patterns": [
    {
      "pattern_id": "string",
      "name": "string",
      "description": "string",
      "confidence_score": "number (0-1)",
      "severity": "string",
      "kill_chain_phases": ["string"],
      "tactics": ["string"],
      "techniques": ["string"],
      "affected_resources": ["string"],
      "related_findings_count": "number",
      "risk_score": "number (0-100)"
    }
  ],
  "high_risk_findings": [
    {
      "finding_id": "string",
      "title": "string",
      "severity": "string",
      "description": "string",
      "source_service": "string",
      "attack_indicators": ["string"],
      "affected_resources": ["string"]
    }
  ],
  "remediation_plan": {
    "immediate_actions": ["string"],
    "short_term_actions": ["string"],
    "long_term_actions": ["string"],
    "estimated_effort": "string"
  },
  "generated_at": "string (ISO 8601)"
}
```

---

### check_compliance_status

Checks compliance status against industry frameworks with gap analysis and evidence collection.

**Description:**
This tool maps AWS Config rules and Security Hub standards to compliance framework requirements, providing comprehensive compliance assessment with gap analysis and audit evidence collection.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `framework` | string | Yes | - | Compliance framework to assess. Valid values: `CIS`, `NIST`, `SOC2`, `PCI-DSS` |
| `generate_report` | boolean | No | `true` | Whether to generate a detailed compliance report |
| `include_evidence` | boolean | No | `false` | Whether to collect audit evidence |
| `control_ids` | array[string] | No | `[]` | Specific control IDs to assess (empty = all controls) |

**Response Format:**
```json
{
  "framework": "string",
  "assessment_date": "string (ISO 8601)",
  "overall_compliance_score": "number (0-100)",
  "compliance_status": "string (COMPLIANT|NON_COMPLIANT|PARTIAL)",
  "control_results": [
    {
      "control_id": "string",
      "title": "string",
      "description": "string",
      "status": "string (PASSED|FAILED|NOT_APPLICABLE)",
      "severity": "string",
      "compliant_resources": "number",
      "non_compliant_resources": "number",
      "remediation_guidance": "string"
    }
  ],
  "compliance_gaps": [
    {
      "gap_id": "string",
      "control_id": "string",
      "title": "string",
      "description": "string",
      "remediation_priority": "string (HIGH|MEDIUM|LOW)",
      "estimated_effort": "string",
      "business_impact": "string"
    }
  ],
  "evidence": [
    {
      "control_id": "string",
      "evidence_type": "string",
      "source": "string",
      "timestamp": "string (ISO 8601)",
      "details": "object"
    }
  ],
  "remediation_timeline": {
    "immediate": ["string"],
    "short_term": ["string"],
    "long_term": ["string"]
  },
  "generated_at": "string (ISO 8601)"
}
```

---

## Advanced Security Tools

### recommend_security_improvements

Provides intelligent security improvement recommendations with priority-based analysis.

**Description:**
This tool analyzes current security posture and provides prioritized recommendations based on business impact, implementation complexity, and cost-effectiveness.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `priority` | string | No | `"high-impact"` | Recommendation priority strategy. Valid values: `cost-effective`, `high-impact`, `quick-wins` |
| `auto_implement_safe` | boolean | No | `false` | Whether to identify safe automated remediation options |
| `max_recommendations` | number | No | `20` | Maximum number of recommendations to return (1-50) |
| `focus_areas` | array[string] | No | `[]` | Specific security areas to focus on (empty = all areas) |

**Response Format:**
```json
{
  "analysis_id": "string",
  "priority_strategy": "string",
  "total_recommendations": "number",
  "recommendations": [
    {
      "recommendation_id": "string",
      "title": "string",
      "description": "string",
      "priority": "string (HIGH|MEDIUM|LOW)",
      "impact_score": "number (0-100)",
      "implementation_complexity": "string (LOW|MEDIUM|HIGH)",
      "cost_estimate": "string",
      "business_justification": "string",
      "affected_resources": ["string"],
      "compliance_frameworks": ["string"],
      "automation_available": "boolean",
      "remediation_steps": [
        {
          "step_number": "number",
          "title": "string",
          "description": "string",
          "estimated_time": "string",
          "prerequisites": ["string"],
          "aws_service_actions": ["string"]
        }
      ]
    }
  ],
  "summary": {
    "high_priority": "number",
    "medium_priority": "number", 
    "low_priority": "number",
    "automation_candidates": "number",
    "estimated_total_effort": "string"
  },
  "generated_at": "string (ISO 8601)"
}
```

---

## Utility Tools

### health_check

Checks the health and configuration of the MCP server.

**Description:**
This tool verifies server configuration, AWS connectivity, and service availability for troubleshooting and setup verification.

**Parameters:**
None

**Response Format:**
```json
{
  "server_name": "string",
  "version": "string",
  "status": "string (healthy|degraded|unhealthy)",
  "timestamp": "number",
  "configuration": {
    "aws_region": "string",
    "log_level": "string",
    "read_only_mode": "boolean"
  },
  "services": {
    "mcp_server": "string (operational|degraded|failed)",
    "logging": "string (operational|degraded|failed)",
    "configuration": "string (operational|degraded|failed)"
  }
}
```

---

### get_server_info

Gets detailed information about server capabilities and configuration.

**Description:**
This tool provides comprehensive information about server capabilities, supported AWS services, compliance frameworks, and available intelligence engines.

**Parameters:**
None

**Response Format:**
```json
{
  "server": {
    "name": "string",
    "version": "string",
    "description": "string",
    "author": "string",
    "mcp_version": "string"
  },
  "capabilities": {
    "security_assessment": {
      "description": "string",
      "supported_scopes": ["string"],
      "aws_services": ["string"]
    },
    "threat_analysis": {
      "description": "string",
      "features": ["string"]
    },
    "compliance_monitoring": {
      "description": "string",
      "supported_frameworks": ["string"],
      "features": ["string"]
    }
  },
  "intelligence_engines": {
    "engine_name": {
      "description": "string",
      "status": "string (available|unavailable)"
    }
  },
  "configuration": {
    "aws_region": "string",
    "read_only_mode": "boolean",
    "audit_logging": "boolean",
    "supported_auth_methods": ["string"]
  }
}
```

---

## Error Handling

All tools return standardized error responses when issues occur:

```json
{
  "detail": "string (error description)",
  "error_type": "string (error category)",
  "context": {
    "additional_info": "any"
  }
}
```

### Common Error Types

- `ValidationError`: Invalid parameters or input validation failures
- `AuthenticationError`: AWS credential or permission issues
- `ServiceError`: AWS service API errors or connectivity issues
- `IntelligenceEngineError`: Issues with security analysis engines
- `ComplianceFrameworkError`: Compliance framework processing errors
- `RemediationError`: Errors during remediation execution

### Error Handling Best Practices

1. **Graceful Degradation**: Tools continue with available services when some fail
2. **Partial Results**: Tools return partial results with clear limitation indicators
3. **Retry Logic**: Automatic retry with exponential backoff for transient errors
4. **Detailed Context**: Error messages include actionable troubleshooting information
5. **Security-First**: Error messages never expose sensitive information

---

## Rate Limits and Performance

### API Rate Limits

The server implements intelligent rate limiting based on AWS service quotas:

- **Security Hub**: 10 requests per second
- **GuardDuty**: 20 requests per second  
- **Config**: 15 requests per second
- **Inspector**: 10 requests per second

### Performance Optimization

- **Caching**: Frequently accessed data is cached to reduce API calls
- **Batching**: Requests are batched where supported by AWS APIs
- **Pagination**: Large result sets are automatically paginated
- **Concurrent Processing**: Multiple AWS services are queried concurrently

### Recommended Usage Patterns

1. **Start with health_check**: Always verify connectivity before analysis
2. **Use appropriate time ranges**: Limit time ranges to reduce processing time
3. **Filter by severity**: Use severity thresholds to focus on critical issues
4. **Batch assessments**: Group related assessments to improve efficiency
5. **Monitor rate limits**: Implement client-side rate limiting for high-volume usage

---

## Authentication and Permissions

### AWS Credentials

The server supports standard AWS credential mechanisms:

- **AWS Profiles**: Set `AWS_SECURITY_ADVISOR_PROFILE_NAME` environment variable
- **IAM Roles**: Automatic role assumption for EC2/Lambda/ECS environments
- **Environment Variables**: Standard AWS credential environment variables
- **Default Credential Chain**: Follows boto3 default credential resolution

### Required IAM Permissions

See the main README.md for the complete IAM policy with required permissions.

### Security Best Practices

1. **Least Privilege**: Use minimal required permissions
2. **Read-Only Access**: Server operates in read-only mode by default
3. **Audit Logging**: All operations are logged for security monitoring
4. **No Long-Term Credentials**: Use IAM roles instead of access keys
5. **Regional Isolation**: Limit access to specific AWS regions when possible