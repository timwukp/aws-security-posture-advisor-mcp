#!/usr/bin/env python3
"""Security review using AWS Security Posture Advisor templates."""

import asyncio
import json
import subprocess
import sys
import os
from datetime import datetime

async def run_security_review():
    """Run comprehensive security review using MCP server."""
    print("🔒 AWS Security Posture Advisor - Security Review")
    print("=" * 60)
    
    server_path = os.path.join(os.path.dirname(__file__), '.venv', 'bin', 'awslabs.aws-security-posture-advisor')
    
    process = subprocess.Popen(
        [server_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(os.environ, AWS_REGION='us-east-1')
    )
    
    try:
        # Initialize MCP
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "security-review", "version": "1.0.0"}
            }
        }
        
        process.stdin.write(json.dumps(init_request) + '\n')
        process.stdin.flush()
        process.stdout.readline()
        
        # Security review scenarios
        reviews = [
            {
                "name": "Authentication Security Review",
                "frameworks": ["CIS", "NIST"],
                "severity": "HIGH",
                "focus": "Authentication and authorization mechanisms"
            },
            {
                "name": "Database Security Review", 
                "frameworks": ["PCI-DSS"],
                "severity": "CRITICAL",
                "focus": "Database security and SQL injection prevention"
            },
            {
                "name": "API Security Review",
                "frameworks": ["CIS"],
                "severity": "MEDIUM", 
                "focus": "REST API security implementation"
            },
            {
                "name": "Secrets Management Review",
                "frameworks": ["NIST"],
                "severity": "CRITICAL",
                "focus": "Secrets and sensitive data handling"
            },
            {
                "name": "Cloud Security Review",
                "frameworks": ["CIS", "NIST"],
                "severity": "HIGH",
                "focus": "AWS deployment security configuration"
            }
        ]
        
        for i, review in enumerate(reviews, 2):
            print(f"\n🔍 {review['name']}")
            print("-" * 50)
            print(f"Focus: {review['focus']}")
            print(f"Frameworks: {', '.join(review['frameworks'])}")
            print(f"Severity Threshold: {review['severity']}")
            
            request = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {
                    "name": "assess_security_posture",
                    "arguments": {
                        "scope": "account",
                        "target": "<AWS_ACCOUNT_ID>",
                        "frameworks": review['frameworks'],
                        "severity_threshold": review['severity'],
                        "include_recommendations": True
                    }
                }
            }
            
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
            
            response = json.loads(process.stdout.readline().strip())
            
            if response.get('result'):
                content = response['result'].get('content', [])
                if content:
                    result = json.loads(content[0].get('text', '{}'))
                    
                    print(f"✅ Assessment completed")
                    print(f"   Risk Level: {result.get('risk_level', 'unknown')}")
                    print(f"   Security Score: {result.get('overall_score', 'unknown')}/100")
                    
                    # Critical findings
                    critical = result.get('critical_findings', 0)
                    high = result.get('high_findings', 0)
                    if critical > 0 or high > 0:
                        print(f"   ⚠️  Critical Issues: {critical}, High Issues: {high}")
                    
                    # Compliance status
                    compliance = result.get('compliance_status', {})
                    for framework, status in compliance.items():
                        score = status.get('overall_score', 0)
                        print(f"   {framework}: {score}% compliant")
                    
                    # Top security recommendations
                    recommendations = result.get('recommendations', [])[:3]
                    if recommendations:
                        print("   Top Security Actions:")
                        for j, rec in enumerate(recommendations, 1):
                            priority = rec.get('priority', 'unknown')
                            title = rec.get('title', 'Unknown')
                            print(f"     {j}. {title} ({priority})")
            else:
                print(f"❌ Assessment failed: {response.get('error', {}).get('message', 'Unknown')}")
        
        # Generate security summary
        print(f"\n{'='*60}")
        print("📊 Security Review Summary")
        print(f"{'='*60}")
        
        summary_request = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "assess_security_posture",
                "arguments": {
                    "scope": "account",
                    "target": "<AWS_ACCOUNT_ID>",
                    "frameworks": ["CIS", "NIST", "PCI-DSS"],
                    "severity_threshold": "LOW",
                    "include_recommendations": True
                }
            }
        }
        
        process.stdin.write(json.dumps(summary_request) + '\n')
        process.stdin.flush()
        
        response = json.loads(process.stdout.readline().strip())
        if response.get('result'):
            content = response['result'].get('content', [])
            if content:
                result = json.loads(content[0].get('text', '{}'))
                
                print(f"Overall Security Posture: {result.get('overall_score', 'unknown')}/100")
                print(f"Risk Level: {result.get('risk_level', 'unknown')}")
                print(f"Total Security Findings: {result.get('total_findings', 'unknown')}")
                
                print(f"\nSecurity Finding Breakdown:")
                print(f"  🔴 Critical: {result.get('critical_findings', 0)}")
                print(f"  🟠 High: {result.get('high_findings', 0)}")
                print(f"  🟡 Medium: {result.get('medium_findings', 0)}")
                print(f"  🟢 Low: {result.get('low_findings', 0)}")
                
                print(f"\nCompliance Framework Status:")
                compliance = result.get('compliance_status', {})
                for framework, status in compliance.items():
                    score = status.get('overall_score', 0)
                    status_text = status.get('status', 'unknown')
                    passed = status.get('passed_controls', 0)
                    failed = status.get('failed_controls', 0)
                    
                    status_icon = "✅" if score >= 80 else "⚠️" if score >= 60 else "❌"
                    print(f"  {status_icon} {framework}: {score}% ({passed} passed, {failed} failed)")
                
                print(f"\nPriority Security Recommendations:")
                recommendations = result.get('recommendations', [])[:5]
                for i, rec in enumerate(recommendations, 1):
                    priority = rec.get('priority', 'unknown')
                    title = rec.get('title', 'Unknown')
                    affected = rec.get('affected_resources', 0)
                    
                    priority_icon = "🔴" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "🟢"
                    print(f"  {priority_icon} {i}. {title}")
                    print(f"      Priority: {priority}, Affected Resources: {affected}")
        
        process.terminate()
        process.wait(timeout=5)
        
        print(f"\n{'='*60}")
        print("✅ Security Review Completed")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
    except Exception as e:
        print(f"❌ Security review failed: {e}")
        process.terminate()

if __name__ == "__main__":
    asyncio.run(run_security_review())
