#!/usr/bin/env python3
"""
Example Test Questions for AWS Security Posture Advisor MCP Server
"""

def generate_test_questions():
    """Generate comprehensive test questions for the MCP server"""
    
    print("🧪 AWS Security Posture Advisor MCP Server - Test Questions")
    print("=" * 65)
    
    # Basic Functionality Tests
    print("\n📋 BASIC FUNCTIONALITY TESTS")
    print("-" * 35)
    
    basic_tests = [
        {
            "id": "T001",
            "question": "Can you check the health status of the MCP server?",
            "tool": "health_check",
            "parameters": {},
            "expected": "Server status: healthy, all services operational"
        },
        {
            "id": "T002", 
            "question": "What are the server capabilities and supported frameworks?",
            "tool": "get_server_info",
            "parameters": {},
            "expected": "Server info with supported frameworks: CIS, NIST, SOC2, PCI-DSS"
        }
    ]
    
    for test in basic_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    # Security Assessment Tests
    print("🔍 SECURITY ASSESSMENT TESTS")
    print("-" * 35)
    
    assessment_tests = [
        {
            "id": "T003",
            "question": "Assess the overall security posture of AWS account <AWS_ACCOUNT_ID> against CIS benchmarks",
            "tool": "assess_security_posture",
            "parameters": {
                "scope": "account",
                "target": "<AWS_ACCOUNT_ID>", 
                "frameworks": ["CIS"],
                "severity_threshold": "MEDIUM",
                "include_recommendations": True
            },
            "expected": "Security score, risk level, compliance status, findings count"
        },
        {
            "id": "T004",
            "question": "Perform a high-severity security assessment for the us-east-1 region only",
            "tool": "assess_security_posture", 
            "parameters": {
                "scope": "region",
                "target": "us-east-1",
                "frameworks": ["CIS"],
                "severity_threshold": "HIGH"
            },
            "expected": "Regional security assessment with high-severity findings"
        },
        {
            "id": "T005",
            "question": "Assess security posture against multiple compliance frameworks",
            "tool": "assess_security_posture",
            "parameters": {
                "scope": "account",
                "target": "<AWS_ACCOUNT_ID>",
                "frameworks": ["CIS", "NIST", "SOC2"],
                "severity_threshold": "MEDIUM"
            },
            "expected": "Multi-framework compliance assessment results"
        }
    ]
    
    for test in assessment_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    # Threat Analysis Tests
    print("🚨 THREAT ANALYSIS TESTS")
    print("-" * 30)
    
    threat_tests = [
        {
            "id": "T006",
            "question": "Analyze security findings from the last 7 days for attack patterns",
            "tool": "analyze_security_findings",
            "parameters": {
                "severity_threshold": "HIGH",
                "time_range_days": 7,
                "include_remediation": True,
                "max_findings": 100
            },
            "expected": "Attack patterns, threat landscape, remediation plan"
        },
        {
            "id": "T007",
            "question": "Find critical security threats from the past 30 days",
            "tool": "analyze_security_findings",
            "parameters": {
                "severity_threshold": "CRITICAL",
                "time_range_days": 30,
                "include_remediation": True
            },
            "expected": "Critical threats with detailed remediation guidance"
        }
    ]
    
    for test in threat_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    # Compliance Tests
    print("📊 COMPLIANCE TESTS")
    print("-" * 25)
    
    compliance_tests = [
        {
            "id": "T008",
            "question": "Check CIS compliance status with detailed report and evidence",
            "tool": "check_compliance_status",
            "parameters": {
                "framework": "CIS",
                "generate_report": True,
                "include_evidence": True
            },
            "expected": "CIS compliance report with evidence and gap analysis"
        },
        {
            "id": "T009",
            "question": "Assess NIST framework compliance for specific controls",
            "tool": "check_compliance_status",
            "parameters": {
                "framework": "NIST",
                "generate_report": True,
                "control_ids": ["AC-2", "AC-3", "SC-7"]
            },
            "expected": "NIST compliance for specified access control and security controls"
        },
        {
            "id": "T010",
            "question": "Generate SOC2 compliance report for audit purposes",
            "tool": "check_compliance_status",
            "parameters": {
                "framework": "SOC2",
                "generate_report": True,
                "include_evidence": True
            },
            "expected": "SOC2 audit-ready compliance report with evidence"
        }
    ]
    
    for test in compliance_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    # Recommendation Tests
    print("💡 RECOMMENDATION TESTS")
    print("-" * 30)
    
    recommendation_tests = [
        {
            "id": "T011",
            "question": "Get high-impact security improvement recommendations",
            "tool": "recommend_security_improvements",
            "parameters": {
                "priority": "high-impact",
                "auto_implement_safe": False,
                "max_recommendations": 10
            },
            "expected": "Prioritized high-impact security recommendations"
        },
        {
            "id": "T012",
            "question": "Find cost-effective security improvements with automation options",
            "tool": "recommend_security_improvements", 
            "parameters": {
                "priority": "cost-effective",
                "auto_implement_safe": True,
                "max_recommendations": 15,
                "focus_areas": ["IAM", "S3", "VPC"]
            },
            "expected": "Cost-effective recommendations with automation candidates"
        }
    ]
    
    for test in recommendation_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    # Error Handling Tests
    print("⚠️  ERROR HANDLING TESTS")
    print("-" * 30)
    
    error_tests = [
        {
            "id": "T013",
            "question": "Test invalid scope parameter",
            "tool": "assess_security_posture",
            "parameters": {
                "scope": "invalid_scope",
                "target": "<AWS_ACCOUNT_ID>",
                "frameworks": ["CIS"]
            },
            "expected": "ValidationError: Invalid scope parameter"
        },
        {
            "id": "T014",
            "question": "Test unsupported compliance framework",
            "tool": "check_compliance_status",
            "parameters": {
                "framework": "INVALID_FRAMEWORK"
            },
            "expected": "ValidationError: Unsupported compliance framework"
        }
    ]
    
    for test in error_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    # Performance Tests
    print("⚡ PERFORMANCE TESTS")
    print("-" * 25)
    
    performance_tests = [
        {
            "id": "T015",
            "question": "Test large-scale assessment with 1000 findings limit",
            "tool": "analyze_security_findings",
            "parameters": {
                "severity_threshold": "LOW",
                "time_range_days": 365,
                "max_findings": 1000
            },
            "expected": "Performance metrics and response time under 60 seconds"
        }
    ]
    
    for test in performance_tests:
        print(f"🔹 {test['id']}: {test['question']}")
        print(f"   Tool: {test['tool']}")
        print(f"   Parameters: {test['parameters']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    print("🎯 TEST EXECUTION GUIDE")
    print("-" * 28)
    print("1. Start MCP server: mcp run awslabs/aws_security_posture_advisor/server.py")
    print("2. Connect MCP client to server")
    print("3. Execute each test question using the specified tool and parameters")
    print("4. Verify results match expected outcomes")
    print("5. Document any failures or performance issues")
    
    print(f"\n📊 TOTAL TEST CASES: 15")
    print("   • Basic Functionality: 2 tests")
    print("   • Security Assessment: 3 tests") 
    print("   • Threat Analysis: 2 tests")
    print("   • Compliance: 3 tests")
    print("   • Recommendations: 2 tests")
    print("   • Error Handling: 2 tests")
    print("   • Performance: 1 test")

if __name__ == "__main__":
    generate_test_questions()
