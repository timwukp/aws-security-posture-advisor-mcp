#!/usr/bin/env python3
"""Comprehensive functionality test for AWS Security Posture Advisor MCP Server."""

import asyncio
import json
import sys
import os
from typing import Dict, Any

# Add the project to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'awslabs'))

async def test_server_tools():
    """Test all available MCP tools."""
    print("🧪 Testing AWS Security Posture Advisor MCP Server")
    print("=" * 60)
    
    try:
        # Import the server module
        from awslabs.aws_security_posture_advisor.server import server
        from mcp.server.fastmcp import Context
        
        # Create a mock context
        class MockContext:
            def __init__(self):
                self.session = {}
        
        ctx = MockContext()
        
        # Test 1: Health Check
        print("\n1️⃣ Testing health_check tool...")
        try:
            # Get the health_check function from server tools
            health_result = await test_health_check(ctx)
            print(f"✅ Health check result: {health_result.get('status', 'unknown')}")
            if isinstance(health_result, dict) and health_result.get('status') == 'healthy':
                print("   Server is healthy and operational")
            else:
                print(f"   Health check returned: {health_result}")
        except Exception as e:
            print(f"❌ Health check failed: {e}")
        
        # Test 2: Server Info
        print("\n2️⃣ Testing get_server_info tool...")
        try:
            info_result = await test_server_info(ctx)
            if isinstance(info_result, dict):
                print("✅ Server info retrieved successfully")
                print(f"   Server: {info_result.get('server', {}).get('name', 'Unknown')}")
                print(f"   Version: {info_result.get('server', {}).get('version', 'Unknown')}")
                capabilities = info_result.get('capabilities', {})
                print(f"   Available capabilities: {len(capabilities)} modules")
            else:
                print(f"   Server info returned: {info_result}")
        except Exception as e:
            print(f"❌ Server info failed: {e}")
        
        # Test 3: Security Assessment
        print("\n3️⃣ Testing assess_security_posture tool...")
        try:
            assessment_result = await test_security_assessment(ctx)
            if isinstance(assessment_result, dict):
                print("✅ Security assessment completed")
                print(f"   Assessment ID: {assessment_result.get('assessment_id', 'Unknown')}")
                print(f"   Overall Score: {assessment_result.get('overall_score', 'Unknown')}")
                print(f"   Risk Level: {assessment_result.get('risk_level', 'Unknown')}")
                print(f"   Total Findings: {assessment_result.get('total_findings', 'Unknown')}")
            else:
                print(f"   Assessment returned: {assessment_result}")
        except Exception as e:
            print(f"❌ Security assessment failed: {e}")
        
        print("\n" + "=" * 60)
        print("🎉 Functionality testing completed!")
        
    except ImportError as e:
        print(f"❌ Failed to import server module: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error during testing: {e}")
        return False
    
    return True

async def test_health_check(ctx):
    """Test the health_check tool."""
    from awslabs.aws_security_posture_advisor.server import server
    
    # Find and call the health_check tool
    for tool_name, tool_func in server._tools.items():
        if tool_name == "health_check":
            return await tool_func(ctx)
    
    # Fallback: direct import and call
    from awslabs.aws_security_posture_advisor.server import health_check
    return await health_check(ctx)

async def test_server_info(ctx):
    """Test the get_server_info tool."""
    from awslabs.aws_security_posture_advisor.server import server
    
    # Find and call the get_server_info tool
    for tool_name, tool_func in server._tools.items():
        if tool_name == "get_server_info":
            return await tool_func(ctx)
    
    # Fallback: direct import and call
    from awslabs.aws_security_posture_advisor.server import get_server_info
    return await get_server_info(ctx)

async def test_security_assessment(ctx):
    """Test the assess_security_posture tool."""
    from awslabs.aws_security_posture_advisor.server import server
    
    # Test parameters
    test_params = {
        "scope": "account",
        "target": "<AWS_ACCOUNT_ID>",  # Your AWS account ID
        "frameworks": ["CIS"],
        "severity_threshold": "MEDIUM",
        "include_recommendations": True
    }
    
    # Find and call the assess_security_posture tool
    for tool_name, tool_func in server._tools.items():
        if tool_name == "assess_security_posture":
            return await tool_func(ctx, **test_params)
    
    # Fallback: direct import and call
    from awslabs.aws_security_posture_advisor.server import assess_security_posture
    return await assess_security_posture(ctx, **test_params)

def test_aws_connectivity():
    """Test AWS service connectivity."""
    print("\n🔗 Testing AWS Service Connectivity")
    print("-" * 40)
    
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    
    services_to_test = [
        ("sts", "get_caller_identity"),
        ("securityhub", "describe_hub"),
        ("guardduty", "list_detectors"),
        ("config", "describe_configuration_recorders"),
        ("inspector2", "list_findings"),
    ]
    
    for service_name, operation in services_to_test:
        try:
            client = boto3.client(service_name, region_name='us-east-1')
            
            if operation == "get_caller_identity":
                response = client.get_caller_identity()
                print(f"✅ {service_name.upper()}: Connected (Account: {response.get('Account')})")
            elif operation == "describe_hub":
                response = client.describe_hub()
                print(f"✅ {service_name.upper()}: Hub found")
            elif operation == "list_detectors":
                response = client.list_detectors()
                detector_count = len(response.get('DetectorIds', []))
                print(f"✅ {service_name.upper()}: {detector_count} detectors found")
            elif operation == "describe_configuration_recorders":
                response = client.describe_configuration_recorders()
                recorder_count = len(response.get('ConfigurationRecorders', []))
                print(f"✅ {service_name.upper()}: {recorder_count} recorders found")
            elif operation == "list_findings":
                response = client.list_findings(MaxResults=1)
                print(f"✅ {service_name.upper()}: Service accessible")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['InvalidInputException', 'BadRequestException']:
                print(f"✅ {service_name.upper()}: Service accessible (expected error: {error_code})")
            else:
                print(f"⚠️  {service_name.upper()}: {error_code} - {e.response['Error']['Message']}")
        except NoCredentialsError:
            print(f"❌ {service_name.upper()}: No credentials configured")
        except Exception as e:
            print(f"⚠️  {service_name.upper()}: {str(e)}")

if __name__ == "__main__":
    # Test AWS connectivity first
    test_aws_connectivity()
    
    # Test MCP server functionality
    try:
        asyncio.run(test_server_tools())
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Testing failed: {e}")
        sys.exit(1)
