#!/usr/bin/env python3
"""Usage examples for AWS Security Posture Advisor MCP Server."""

import asyncio
import json
import subprocess
import sys
import os

async def example_security_assessment():
    """Example of running a comprehensive security assessment."""
    print("🔍 Example: Comprehensive Security Assessment")
    print("=" * 50)
    
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
        # Initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "usage-example", "version": "1.0.0"}
            }
        }
        
        process.stdin.write(json.dumps(init_request) + '\n')
        process.stdin.flush()
        process.stdout.readline()  # Skip init response
        
        # Run security assessment with different parameters
        test_cases = [
            {
                "name": "Basic CIS Assessment",
                "params": {
                    "scope": "account",
                    "target": "<AWS_ACCOUNT_ID>",
                    "frameworks": ["CIS"],
                    "severity_threshold": "HIGH",
                    "include_recommendations": True
                }
            },
            {
                "name": "Multi-Framework Assessment",
                "params": {
                    "scope": "account", 
                    "target": "<AWS_ACCOUNT_ID>",
                    "frameworks": ["CIS", "NIST"],
                    "severity_threshold": "MEDIUM",
                    "include_recommendations": True
                }
            },
            {
                "name": "Critical Issues Only",
                "params": {
                    "scope": "account",
                    "target": "<AWS_ACCOUNT_ID>", 
                    "frameworks": ["CIS"],
                    "severity_threshold": "CRITICAL",
                    "include_recommendations": False
                }
            }
        ]
        
        for i, test_case in enumerate(test_cases, 2):
            print(f"\n📋 {test_case['name']}")
            print("-" * 30)
            
            request = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {
                    "name": "assess_security_posture",
                    "arguments": test_case['params']
                }
            }
            
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
            
            response = json.loads(process.stdout.readline().strip())
            
            if response.get('result'):
                content = response['result'].get('content', [])
                if content:
                    result_data = json.loads(content[0].get('text', '{}'))
                    
                    print(f"Assessment ID: {result_data.get('assessment_id', 'unknown')}")
                    print(f"Overall Score: {result_data.get('overall_score', 'unknown')}/100")
                    print(f"Risk Level: {result_data.get('risk_level', 'unknown')}")
                    print(f"Total Findings: {result_data.get('total_findings', 'unknown')}")
                    
                    # Show breakdown by severity
                    critical = result_data.get('critical_findings', 0)
                    high = result_data.get('high_findings', 0)
                    medium = result_data.get('medium_findings', 0)
                    low = result_data.get('low_findings', 0)
                    
                    print(f"Findings Breakdown:")
                    print(f"  Critical: {critical}")
                    print(f"  High: {high}")
                    print(f"  Medium: {medium}")
                    print(f"  Low: {low}")
                    
                    # Show compliance scores
                    compliance = result_data.get('compliance_status', {})
                    for framework, status in compliance.items():
                        score = status.get('overall_score', 0)
                        status_text = status.get('status', 'unknown')
                        passed = status.get('passed_controls', 0)
                        failed = status.get('failed_controls', 0)
                        total = status.get('total_controls', 0)
                        
                        print(f"{framework} Compliance:")
                        print(f"  Score: {score}% ({status_text})")
                        print(f"  Controls: {passed} passed, {failed} failed, {total} total")
                    
                    # Show recommendations if included
                    recommendations = result_data.get('recommendations', [])
                    if recommendations:
                        print(f"Top Recommendations:")
                        for j, rec in enumerate(recommendations[:3], 1):
                            priority = rec.get('priority', 'unknown')
                            title = rec.get('title', 'Unknown')
                            affected = rec.get('affected_resources', 0)
                            print(f"  {j}. {title} ({priority}) - {affected} resources")
            else:
                print(f"Assessment failed: {response.get('error', {}).get('message', 'Unknown error')}")
        
        process.terminate()
        process.wait(timeout=5)
        
    except Exception as e:
        print(f"Example failed: {e}")
        process.terminate()

def show_integration_examples():
    """Show examples of integrating with MCP clients."""
    print("\n🔧 MCP Client Integration Examples")
    print("=" * 50)
    
    print("\n1. Claude Desktop Configuration:")
    print("Add to ~/.claude_desktop_config.json:")
    print(json.dumps({
        "mcpServers": {
            "aws-security-posture-advisor": {
                "command": "/Users/tmwu/aws-security-posture-advisor-mcp/.venv/bin/awslabs.aws-security-posture-advisor",
                "env": {
                    "AWS_REGION": "us-east-1"
                }
            }
        }
    }, indent=2))
    
    print("\n2. Cursor IDE Configuration:")
    print("Add to MCP settings:")
    print(json.dumps({
        "mcpServers": {
            "aws-security-posture-advisor": {
                "command": "/Users/tmwu/aws-security-posture-advisor-mcp/.venv/bin/awslabs.aws-security-posture-advisor",
                "env": {
                    "AWS_REGION": "us-east-1",
                    "FASTMCP_LOG_LEVEL": "INFO"
                }
            }
        }
    }, indent=2))
    
    print("\n3. Example Prompts to Use:")
    prompts = [
        "Assess my AWS security posture for CIS compliance",
        "Run a comprehensive security assessment with NIST framework",
        "Check for critical security findings only",
        "Get server information and available capabilities",
        "Perform health check on the security advisor"
    ]
    
    for i, prompt in enumerate(prompts, 1):
        print(f"   {i}. \"{prompt}\"")

if __name__ == "__main__":
    print("🚀 AWS Security Posture Advisor - Usage Examples")
    
    try:
        asyncio.run(example_security_assessment())
        show_integration_examples()
        
        print("\n🎉 Usage examples completed!")
        print("\nThe server is ready for production use with MCP clients.")
        
    except KeyboardInterrupt:
        print("\n⏹️  Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Examples failed: {e}")
        sys.exit(1)
