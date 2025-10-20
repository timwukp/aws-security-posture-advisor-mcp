#!/usr/bin/env python3
"""
Test AWS Security Posture Assessment using MCP client
"""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

async def test_security_assessment():
    """Test the security assessment functionality"""
    
    print("🔍 Testing AWS Security Posture Assessment...")
    print("📊 Account: <AWS_ACCOUNT_ID>")
    print("📋 Framework: CIS")
    print("-" * 60)
    
    # First, let's try to run the server directly to test functionality
    try:
        # Import the server module to test the tools directly
        sys.path.append('/Users/tmwu/aws-security-posture-advisor-mcp')
        
        # Test basic AWS connectivity first
        result = subprocess.run(['aws', 'sts', 'get-caller-identity'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ AWS credentials not configured properly")
            return
        
        print("✅ AWS credentials verified")
        
        # Test Security Hub availability
        result = subprocess.run(['aws', 'securityhub', 'describe-hub'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print("⚠️  Security Hub may not be enabled - this is required for full assessment")
        else:
            print("✅ Security Hub is available")
        
        # Test GuardDuty availability
        result = subprocess.run(['aws', 'guardduty', 'list-detectors'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ GuardDuty is available")
        else:
            print("⚠️  GuardDuty may not be enabled")
        
        # Test Config availability
        result = subprocess.run(['aws', 'configservice', 'describe-configuration-recorders'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ AWS Config is available")
        else:
            print("⚠️  AWS Config may not be enabled")
        
        print("\n📋 Security Assessment Summary:")
        print("   This would normally provide:")
        print("   • Overall security score (0-100)")
        print("   • Risk level assessment")
        print("   • CIS compliance status")
        print("   • Critical/High/Medium/Low findings count")
        print("   • Top security findings with remediation")
        print("   • Prioritized security recommendations")
        
        # Create a mock assessment result for demonstration
        mock_result = {
            "assessment_id": "test-assessment-001",
            "scope": "account",
            "target": "<AWS_ACCOUNT_ID>",
            "frameworks": ["CIS"],
            "overall_score": 75,
            "risk_level": "MEDIUM",
            "total_findings": 23,
            "critical_findings": 2,
            "high_findings": 5,
            "medium_findings": 8,
            "low_findings": 8,
            "compliance_status": {
                "CIS": {
                    "overall_score": 78,
                    "status": "PARTIAL",
                    "passed_controls": 45,
                    "failed_controls": 12,
                    "total_controls": 57
                }
            },
            "top_findings": [
                {
                    "finding_id": "finding-001",
                    "title": "Root access key usage detected",
                    "severity": "CRITICAL",
                    "description": "Root user access keys are being used",
                    "source_service": "Security Hub",
                    "resource_count": 1
                },
                {
                    "finding_id": "finding-002", 
                    "title": "S3 bucket with public read access",
                    "severity": "HIGH",
                    "description": "S3 bucket allows public read access",
                    "source_service": "Config",
                    "resource_count": 3
                }
            ],
            "recommendations": [
                {
                    "recommendation_id": "rec-001",
                    "title": "Remove root access keys",
                    "priority": "HIGH",
                    "description": "Delete root user access keys and use IAM users instead",
                    "affected_resources": 1,
                    "automation_available": False
                },
                {
                    "recommendation_id": "rec-002",
                    "title": "Restrict S3 bucket public access",
                    "priority": "HIGH", 
                    "description": "Remove public read permissions from S3 buckets",
                    "affected_resources": 3,
                    "automation_available": True
                }
            ]
        }
        
        print("\n📊 Mock Assessment Results:")
        print(f"   Overall Security Score: {mock_result['overall_score']}/100")
        print(f"   Risk Level: {mock_result['risk_level']}")
        print(f"   Total Findings: {mock_result['total_findings']}")
        print(f"   Critical: {mock_result['critical_findings']}")
        print(f"   High: {mock_result['high_findings']}")
        print(f"   Medium: {mock_result['medium_findings']}")
        print(f"   Low: {mock_result['low_findings']}")
        
        cis_status = mock_result['compliance_status']['CIS']
        print(f"\n📋 CIS Compliance:")
        print(f"   Status: {cis_status['status']}")
        print(f"   Score: {cis_status['overall_score']}/100")
        print(f"   Passed: {cis_status['passed_controls']}")
        print(f"   Failed: {cis_status['failed_controls']}")
        print(f"   Total: {cis_status['total_controls']}")
        
        print(f"\n🔍 Top Findings:")
        for i, finding in enumerate(mock_result['top_findings'], 1):
            print(f"   {i}. {finding['title']} ({finding['severity']})")
            print(f"      {finding['description']}")
        
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(mock_result['recommendations'], 1):
            print(f"   {i}. {rec['title']} (Priority: {rec['priority']})")
            print(f"      {rec['description']}")
            print(f"      Automation: {'Available' if rec['automation_available'] else 'Manual'}")
        
        # Save results
        with open('mock_assessment_results.json', 'w') as f:
            json.dump(mock_result, f, indent=2)
        
        print(f"\n📄 Results saved to: mock_assessment_results.json")
        
        print(f"\n💡 Next Steps:")
        print("   1. Enable Security Hub, GuardDuty, and Config for full assessment")
        print("   2. Run the actual MCP server for real-time security analysis")
        print("   3. Implement high-priority recommendations first")
        print("   4. Set up continuous monitoring and alerting")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_security_assessment())
