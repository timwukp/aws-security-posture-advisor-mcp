#!/usr/bin/env python3
"""
AWS Security Posture Assessment Script
Assesses AWS account security posture against CIS benchmarks
"""

import asyncio
import json
from awslabs.aws_security_posture_advisor.server import SecurityPostureAdvisorServer

async def assess_security_posture():
    """Run comprehensive security assessment against CIS benchmarks"""
    
    # Initialize the MCP server
    server = SecurityPostureAdvisorServer()
    
    # Assessment parameters
    assessment_params = {
        "scope": "account",
        "target": "<AWS_ACCOUNT_ID>",
        "frameworks": ["CIS"],
        "severity_threshold": "MEDIUM",
        "include_recommendations": True
    }
    
    print("🔍 Starting AWS Security Posture Assessment...")
    print(f"📊 Account: {assessment_params['target']}")
    print(f"📋 Framework: {assessment_params['frameworks'][0]}")
    print(f"⚠️  Severity Threshold: {assessment_params['severity_threshold']}")
    print("-" * 60)
    
    try:
        # Run the assessment
        result = await server.assess_security_posture(**assessment_params)
        
        # Display results
        print("✅ Assessment Complete!")
        print(f"📈 Overall Security Score: {result.get('overall_score', 'N/A')}/100")
        print(f"🚨 Risk Level: {result.get('risk_level', 'N/A')}")
        print(f"📊 Total Findings: {result.get('total_findings', 0)}")
        print(f"🔴 Critical: {result.get('critical_findings', 0)}")
        print(f"🟠 High: {result.get('high_findings', 0)}")
        print(f"🟡 Medium: {result.get('medium_findings', 0)}")
        print(f"🟢 Low: {result.get('low_findings', 0)}")
        
        # CIS Compliance Status
        if 'compliance_status' in result and 'CIS' in result['compliance_status']:
            cis_status = result['compliance_status']['CIS']
            print("\n📋 CIS Compliance Status:")
            print(f"   Status: {cis_status.get('status', 'N/A')}")
            print(f"   Score: {cis_status.get('overall_score', 'N/A')}/100")
            print(f"   Passed Controls: {cis_status.get('passed_controls', 0)}")
            print(f"   Failed Controls: {cis_status.get('failed_controls', 0)}")
            print(f"   Total Controls: {cis_status.get('total_controls', 0)}")
        
        # Top Findings
        if 'top_findings' in result and result['top_findings']:
            print("\n🔍 Top Security Findings:")
            for i, finding in enumerate(result['top_findings'][:5], 1):
                print(f"   {i}. {finding.get('title', 'N/A')} ({finding.get('severity', 'N/A')})")
                print(f"      Source: {finding.get('source_service', 'N/A')}")
                print(f"      Resources: {finding.get('resource_count', 0)}")
        
        # Recommendations
        if 'recommendations' in result and result['recommendations']:
            print("\n💡 Top Security Recommendations:")
            for i, rec in enumerate(result['recommendations'][:3], 1):
                print(f"   {i}. {rec.get('title', 'N/A')} (Priority: {rec.get('priority', 'N/A')})")
                print(f"      Affected Resources: {rec.get('affected_resources', 0)}")
                print(f"      Automation Available: {'Yes' if rec.get('automation_available') else 'No'}")
        
        # Save detailed results
        with open('security_assessment_results.json', 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: security_assessment_results.json")
        
        return result
        
    except Exception as e:
        print(f"❌ Assessment failed: {str(e)}")
        return None

if __name__ == "__main__":
    asyncio.run(assess_security_posture())
