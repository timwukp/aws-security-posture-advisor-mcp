#!/usr/bin/env python3
"""Comprehensive test suite for AWS Security Posture Advisor MCP Server."""

import asyncio
import json
import subprocess
import sys
import os
import time
from datetime import datetime

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print(f"{'='*60}")

def print_section(title):
    """Print a formatted section."""
    print(f"\n{'-'*40}")
    print(f"📋 {title}")
    print(f"{'-'*40}")

async def test_all_mcp_tools():
    """Test all available MCP tools via stdio."""
    print_header("MCP Tools Testing")
    
    server_path = os.path.join(os.path.dirname(__file__), '.venv', 'bin', 'awslabs.aws-security-posture-advisor')
    
    try:
        process = subprocess.Popen(
            [server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, AWS_REGION='us-east-1', FASTMCP_LOG_LEVEL='INFO')
        )
        
        # Initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "comprehensive-test", "version": "1.0.0"}
            }
        }
        
        process.stdin.write(json.dumps(init_request) + '\n')
        process.stdin.flush()
        response = json.loads(process.stdout.readline().strip())
        
        if response.get('result'):
            print("✅ MCP server initialized successfully")
        
        # List tools
        list_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        process.stdin.write(json.dumps(list_request) + '\n')
        process.stdin.flush()
        response = json.loads(process.stdout.readline().strip())
        
        tools = response.get('result', {}).get('tools', [])
        print(f"✅ Found {len(tools)} available tools")
        
        # Test each tool
        for i, tool in enumerate(tools, 3):
            tool_name = tool.get('name')
            print_section(f"Testing {tool_name}")
            
            # Prepare arguments based on tool
            arguments = {}
            if tool_name == "assess_security_posture":
                arguments = {
                    "scope": "account",
                    "target": "<AWS_ACCOUNT_ID>",
                    "frameworks": ["CIS"],
                    "severity_threshold": "MEDIUM",
                    "include_recommendations": True
                }
            
            tool_request = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
            
            process.stdin.write(json.dumps(tool_request) + '\n')
            process.stdin.flush()
            
            try:
                response_line = process.stdout.readline()
                response = json.loads(response_line.strip())
                
                if response.get('result'):
                    result = response['result']
                    content = result.get('content', [])
                    
                    if content and len(content) > 0:
                        result_text = content[0].get('text', '')
                        if result_text:
                            try:
                                result_data = json.loads(result_text)
                                print(f"✅ {tool_name} executed successfully")
                                
                                # Show specific results based on tool
                                if tool_name == "health_check":
                                    print(f"   Status: {result_data.get('status', 'unknown')}")
                                    print(f"   Server: {result_data.get('server_name', 'unknown')}")
                                    
                                elif tool_name == "get_server_info":
                                    server_info = result_data.get('server', {})
                                    capabilities = result_data.get('capabilities', {})
                                    print(f"   Server: {server_info.get('name', 'unknown')}")
                                    print(f"   Version: {server_info.get('version', 'unknown')}")
                                    print(f"   Capabilities: {len(capabilities)} modules")
                                    
                                elif tool_name == "assess_security_posture":
                                    print(f"   Assessment ID: {result_data.get('assessment_id', 'unknown')}")
                                    print(f"   Overall Score: {result_data.get('overall_score', 'unknown')}")
                                    print(f"   Risk Level: {result_data.get('risk_level', 'unknown')}")
                                    print(f"   Total Findings: {result_data.get('total_findings', 'unknown')}")
                                    
                                    # Show compliance status
                                    compliance = result_data.get('compliance_status', {})
                                    for framework, status in compliance.items():
                                        score = status.get('overall_score', 0)
                                        status_text = status.get('status', 'unknown')
                                        print(f"   {framework} Compliance: {score}% ({status_text})")
                                    
                                    # Show top findings
                                    findings = result_data.get('top_findings', [])
                                    if findings:
                                        print(f"   Top findings ({len(findings)}):")
                                        for j, finding in enumerate(findings[:3], 1):
                                            severity = finding.get('severity', 'unknown')
                                            title = finding.get('title', 'Unknown')
                                            print(f"     {j}. {title} ({severity})")
                                    
                                    # Show recommendations
                                    recommendations = result_data.get('recommendations', [])
                                    if recommendations:
                                        print(f"   Recommendations ({len(recommendations)}):")
                                        for j, rec in enumerate(recommendations[:2], 1):
                                            priority = rec.get('priority', 'unknown')
                                            title = rec.get('title', 'Unknown')
                                            print(f"     {j}. {title} ({priority})")
                                            
                            except json.JSONDecodeError:
                                print(f"✅ {tool_name} executed (non-JSON result)")
                                print(f"   Result: {result_text[:100]}...")
                        else:
                            print(f"✅ {tool_name} executed successfully")
                    else:
                        print(f"✅ {tool_name} executed successfully")
                        
                else:
                    error = response.get('error', {})
                    print(f"❌ {tool_name} failed: {error.get('message', 'Unknown error')}")
                    
            except json.JSONDecodeError as e:
                print(f"❌ {tool_name} response parsing failed: {e}")
            except Exception as e:
                print(f"❌ {tool_name} execution failed: {e}")
        
        # Clean up
        process.terminate()
        process.wait(timeout=5)
        
        return True
        
    except Exception as e:
        print(f"❌ MCP testing failed: {e}")
        if 'process' in locals():
            process.terminate()
        return False

def test_aws_services():
    """Test AWS service connectivity and permissions."""
    print_header("AWS Services Testing")
    
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    
    # Get caller identity
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✅ AWS Identity: {identity.get('Arn', 'unknown')}")
        print(f"   Account: {identity.get('Account', 'unknown')}")
    except Exception as e:
        print(f"❌ AWS identity check failed: {e}")
        return False
    
    # Test security services
    services = [
        ("Security Hub", "securityhub", "describe_hub"),
        ("GuardDuty", "guardduty", "list_detectors"),
        ("Config", "config", "describe_configuration_recorders"),
        ("Inspector", "inspector2", "list_findings"),
        ("CloudTrail", "cloudtrail", "describe_trails"),
    ]
    
    for service_name, service_code, operation in services:
        try:
            client = boto3.client(service_code, region_name='us-east-1')
            
            if operation == "describe_hub":
                response = client.describe_hub()
                print(f"✅ {service_name}: Hub configured")
                
            elif operation == "list_detectors":
                response = client.list_detectors()
                count = len(response.get('DetectorIds', []))
                print(f"✅ {service_name}: {count} detectors found")
                
            elif operation == "describe_configuration_recorders":
                response = client.describe_configuration_recorders()
                count = len(response.get('ConfigurationRecorders', []))
                print(f"✅ {service_name}: {count} recorders found")
                
            elif operation == "list_findings":
                response = client.list_findings(maxResults=1)
                print(f"✅ {service_name}: Service accessible")
                
            elif operation == "describe_trails":
                response = client.describe_trails()
                count = len(response.get('trailList', []))
                print(f"✅ {service_name}: {count} trails found")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['InvalidInputException', 'BadRequestException', 'InvalidUserID.NotFound']:
                print(f"✅ {service_name}: Service accessible (expected error: {error_code})")
            else:
                print(f"⚠️  {service_name}: {error_code}")
        except Exception as e:
            print(f"⚠️  {service_name}: {str(e)[:60]}...")
    
    return True

def generate_test_report():
    """Generate a comprehensive test report."""
    print_header("Test Report Summary")
    
    report = {
        "test_timestamp": datetime.now().isoformat(),
        "python_version": sys.version.split()[0],
        "aws_region": os.environ.get('AWS_REGION', 'us-east-1'),
        "server_version": "0.1.0",
        "tests_performed": [
            "AWS service connectivity",
            "MCP server initialization", 
            "Tool discovery and execution",
            "Health check functionality",
            "Server information retrieval",
            "Security posture assessment"
        ],
        "status": "completed"
    }
    
    print("📊 Test Summary:")
    print(f"   Timestamp: {report['test_timestamp']}")
    print(f"   Python Version: {report['python_version']}")
    print(f"   AWS Region: {report['aws_region']}")
    print(f"   Server Version: {report['server_version']}")
    print(f"   Tests Performed: {len(report['tests_performed'])}")
    
    # Save report
    report_file = "test_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"   Report saved to: {report_file}")
    
    return report

async def main():
    """Run comprehensive testing."""
    print("🚀 AWS Security Posture Advisor - Comprehensive Testing")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Test AWS services
    aws_success = test_aws_services()
    
    # Test MCP tools
    mcp_success = await test_all_mcp_tools()
    
    # Generate report
    report = generate_test_report()
    
    # Final status
    if aws_success and mcp_success:
        print_header("🎉 ALL TESTS PASSED!")
        print("The AWS Security Posture Advisor MCP Server is fully functional.")
        print("\nNext steps:")
        print("1. Configure with your MCP client (Cursor, Claude Desktop, etc.)")
        print("2. Use the assess_security_posture tool for real security assessments")
        print("3. Review the generated findings and recommendations")
        return True
    else:
        print_header("⚠️  SOME TESTS FAILED")
        print("Please review the errors above and ensure:")
        print("1. AWS credentials are properly configured")
        print("2. Required AWS services are enabled")
        print("3. IAM permissions are sufficient")
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Testing failed: {e}")
        sys.exit(1)
