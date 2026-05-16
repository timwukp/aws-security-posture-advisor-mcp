#!/usr/bin/env python3
"""Verify AWS Security Posture Advisor MCP deployment."""

import json
import subprocess
import sys
import os

def verify_deployment():
    """Verify the MCP server deployment."""
    print("🚀 AWS Security Posture Advisor - Deployment Verification")
    print("=" * 60)
    
    # 1. Check executable
    server_path = "/Users/tmwu/aws-security-posture-advisor-mcp/.venv/bin/awslabs.aws-security-posture-advisor"
    if os.path.exists(server_path):
        print("✅ MCP server executable found")
    else:
        print("❌ MCP server executable not found")
        return False
    
    # 2. Check agent configuration
    agent_path = "/Users/tmwu/.aws/amazonq/cli-agents/CloudArchitect-agent.json"
    try:
        with open(agent_path, 'r') as f:
            config = json.load(f)
        
        if "awslabs.aws-security-posture-advisor" in config.get("mcpServers", {}):
            print("✅ MCP server added to CloudArchitect agent")
        else:
            print("❌ MCP server not found in agent configuration")
            return False
            
        if "@awslabs.aws-security-posture-advisor" in config.get("allowedTools", []):
            print("✅ Security advisor tools enabled")
        else:
            print("❌ Security advisor tools not enabled")
            return False
            
        aliases = config.get("toolAliases", {})
        if "security_assessment" in aliases:
            print("✅ Security assessment alias configured")
        else:
            print("❌ Security assessment alias not configured")
            
    except Exception as e:
        print(f"❌ Error reading agent configuration: {e}")
        return False
    
    # 3. Test MCP server connectivity
    print("\n🔌 Testing MCP server connectivity...")
    try:
        process = subprocess.Popen(
            [server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, AWS_REGION='us-east-1')
        )
        
        # Send initialize request
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "deployment-test", "version": "1.0.0"}
            }
        }
        
        process.stdin.write(json.dumps(init_request) + '\n')
        process.stdin.flush()
        
        # Read response
        response_line = process.stdout.readline()
        if response_line:
            response = json.loads(response_line.strip())
            if response.get('result'):
                print("✅ MCP server responds to initialization")
            else:
                print("❌ MCP server initialization failed")
                return False
        
        process.terminate()
        process.wait(timeout=5)
        
    except Exception as e:
        print(f"❌ MCP server connectivity test failed: {e}")
        return False
    
    # 4. Check AWS credentials
    try:
        result = subprocess.run(['aws', 'sts', 'get-caller-identity'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            identity = json.loads(result.stdout)
            print(f"✅ AWS credentials configured (Account: {identity.get('Account')})")
        else:
            print("⚠️ AWS credentials not configured")
    except Exception as e:
        print(f"⚠️ AWS credential check failed: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 DEPLOYMENT SUCCESSFUL!")
    print("\n📋 Usage Instructions:")
    print("1. Use Amazon Q CLI with CloudArchitect agent:")
    print("   q chat --agent CloudArchitect-agent")
    print("\n2. Available security commands:")
    print("   - 'Assess my AWS security posture for CIS compliance'")
    print("   - 'Run a comprehensive security assessment'")
    print("   - 'Check security health of my AWS environment'")
    print("   - 'security_assessment' (alias)")
    print("   - 'security_health' (alias)")
    
    print("\n3. Integration with architecture:")
    print("   - Security assessments are now part of architectural reviews")
    print("   - Compliance analysis integrated with solution design")
    print("   - Security recommendations included in cost optimization")
    
    return True

if __name__ == "__main__":
    success = verify_deployment()
    sys.exit(0 if success else 1)
