#!/usr/bin/env python3
"""Direct test of server functions without FastMCP wrapper."""

import asyncio
import sys
import os
from datetime import datetime

# Add the project to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'awslabs'))

class MockContext:
    """Mock MCP context for testing."""
    def __init__(self):
        self.session = {}

async def test_direct_functions():
    """Test server functions directly."""
    print("🧪 Direct Function Testing")
    print("=" * 50)
    
    ctx = MockContext()
    
    try:
        # Import server functions directly
        from awslabs.aws_security_posture_advisor.server import (
            health_check, get_server_info, assess_security_posture
        )
        
        # Test 1: Health Check
        print("\n1️⃣ Testing health_check...")
        try:
            result = await health_check(ctx)
            print(f"✅ Health check: {result.get('status', 'unknown')}")
            print(f"   Server: {result.get('server_name', 'unknown')}")
            print(f"   Version: {result.get('version', 'unknown')}")
        except Exception as e:
            print(f"❌ Health check error: {e}")
        
        # Test 2: Server Info
        print("\n2️⃣ Testing get_server_info...")
        try:
            result = await get_server_info(ctx)
            if isinstance(result, dict):
                server_info = result.get('server', {})
                print(f"✅ Server info retrieved")
                print(f"   Name: {server_info.get('name', 'unknown')}")
                print(f"   Version: {server_info.get('version', 'unknown')}")
                capabilities = result.get('capabilities', {})
                print(f"   Capabilities: {len(capabilities)} modules")
                for cap_name, cap_info in capabilities.items():
                    print(f"     - {cap_name}: {cap_info.get('description', 'No description')[:50]}...")
            else:
                print(f"   Result: {result}")
        except Exception as e:
            print(f"❌ Server info error: {e}")
        
        # Test 3: Security Assessment
        print("\n3️⃣ Testing assess_security_posture...")
        try:
            result = await assess_security_posture(
                ctx=ctx,
                scope="account",
                target="<AWS_ACCOUNT_ID>",
                frameworks=["CIS"],
                severity_threshold="MEDIUM",
                include_recommendations=True
            )
            if isinstance(result, dict):
                print(f"✅ Security assessment completed")
                print(f"   Assessment ID: {result.get('assessment_id', 'unknown')}")
                print(f"   Overall Score: {result.get('overall_score', 'unknown')}")
                print(f"   Risk Level: {result.get('risk_level', 'unknown')}")
                print(f"   Total Findings: {result.get('total_findings', 'unknown')}")
                print(f"   Critical: {result.get('critical_findings', 0)}")
                print(f"   High: {result.get('high_findings', 0)}")
                print(f"   Medium: {result.get('medium_findings', 0)}")
                print(f"   Low: {result.get('low_findings', 0)}")
                
                # Show compliance status
                compliance = result.get('compliance_status', {})
                for framework, status in compliance.items():
                    print(f"   {framework} Compliance: {status.get('overall_score', 0)}% ({status.get('status', 'unknown')})")
                
                # Show top findings
                findings = result.get('top_findings', [])
                if findings:
                    print(f"   Top {len(findings)} findings:")
                    for i, finding in enumerate(findings[:3], 1):
                        print(f"     {i}. {finding.get('title', 'Unknown')} ({finding.get('severity', 'unknown')})")
                
                # Show recommendations
                recommendations = result.get('recommendations', [])
                if recommendations:
                    print(f"   {len(recommendations)} recommendations available")
                    for i, rec in enumerate(recommendations[:2], 1):
                        print(f"     {i}. {rec.get('title', 'Unknown')} ({rec.get('priority', 'unknown')})")
            else:
                print(f"   Result: {result}")
        except Exception as e:
            print(f"❌ Security assessment error: {e}")
            import traceback
            traceback.print_exc()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 50)
    print("✅ Direct function testing completed!")
    return True

def test_core_modules():
    """Test core module imports and basic functionality."""
    print("\n🔧 Testing Core Modules")
    print("-" * 30)
    
    modules_to_test = [
        "awslabs.aws_security_posture_advisor.core.common.config",
        "awslabs.aws_security_posture_advisor.core.common.models",
        "awslabs.aws_security_posture_advisor.core.common.security",
        "awslabs.aws_security_posture_advisor.core.common.logging",
        "awslabs.aws_security_posture_advisor.core.aws.auth",
        "awslabs.aws_security_posture_advisor.core.aws.security_hub",
        "awslabs.aws_security_posture_advisor.core.intelligence.compliance",
        "awslabs.aws_security_posture_advisor.core.intelligence.remediation",
    ]
    
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            short_name = module_name.split('.')[-1]
            print(f"✅ {short_name}: Import successful")
        except ImportError as e:
            short_name = module_name.split('.')[-1]
            print(f"❌ {short_name}: Import failed - {e}")
        except Exception as e:
            short_name = module_name.split('.')[-1]
            print(f"⚠️  {short_name}: Import warning - {e}")

if __name__ == "__main__":
    print(f"🚀 AWS Security Posture Advisor - Direct Testing")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version.split()[0]}")
    
    # Test core modules first
    test_core_modules()
    
    # Test direct functions
    try:
        asyncio.run(test_direct_functions())
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Testing failed: {e}")
        sys.exit(1)
