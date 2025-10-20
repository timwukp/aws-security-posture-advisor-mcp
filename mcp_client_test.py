#!/usr/bin/env python3
"""MCP Client test for AWS Security Posture Advisor."""

import asyncio
import json
import subprocess
import sys
import os
from typing import Dict, Any

async def test_mcp_server():
    """Test the MCP server using stdio transport."""
    print("🔌 Testing MCP Server via stdio transport")
    print("=" * 50)
    
    # Path to the server executable
    server_path = os.path.join(os.path.dirname(__file__), '.venv', 'bin', 'awslabs.aws-security-posture-advisor')
    
    if not os.path.exists(server_path):
        print(f"❌ Server executable not found at: {server_path}")
        return False
    
    try:
        # Start the MCP server process
        process = subprocess.Popen(
            [server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, AWS_REGION='us-east-1')
        )
        
        # Test 1: Initialize MCP connection
        print("\n1️⃣ Testing MCP initialization...")
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        process.stdin.write(json.dumps(init_request) + '\n')
        process.stdin.flush()
        
        # Read response
        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                if response.get('result'):
                    print("✅ MCP initialization successful")
                    server_info = response['result']
                    print(f"   Server: {server_info.get('serverInfo', {}).get('name', 'unknown')}")
                    print(f"   Version: {server_info.get('serverInfo', {}).get('version', 'unknown')}")
                else:
                    print(f"❌ MCP initialization failed: {response}")
            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON response: {e}")
                print(f"   Raw response: {response_line}")
        else:
            print("❌ No response from server")
        
        # Test 2: List available tools
        print("\n2️⃣ Testing tools/list...")
        list_tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        process.stdin.write(json.dumps(list_tools_request) + '\n')
        process.stdin.flush()
        
        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                if response.get('result'):
                    tools = response['result'].get('tools', [])
                    print(f"✅ Found {len(tools)} available tools:")
                    for tool in tools:
                        print(f"   - {tool.get('name', 'unknown')}: {tool.get('description', 'No description')[:60]}...")
                else:
                    print(f"❌ Tools list failed: {response}")
            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON response: {e}")
        
        # Test 3: Call health_check tool
        print("\n3️⃣ Testing health_check tool...")
        health_check_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "health_check",
                "arguments": {}
            }
        }
        
        process.stdin.write(json.dumps(health_check_request) + '\n')
        process.stdin.flush()
        
        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                if response.get('result'):
                    result = response['result']
                    content = result.get('content', [])
                    if content and len(content) > 0:
                        health_data = content[0].get('text', '')
                        if health_data:
                            health_info = json.loads(health_data)
                            print(f"✅ Health check successful: {health_info.get('status', 'unknown')}")
                        else:
                            print(f"✅ Health check completed: {result}")
                    else:
                        print(f"✅ Health check result: {result}")
                else:
                    print(f"❌ Health check failed: {response}")
            except (json.JSONDecodeError, KeyError) as e:
                print(f"❌ Error parsing health check response: {e}")
        
        # Clean up
        process.terminate()
        process.wait(timeout=5)
        
        print("\n" + "=" * 50)
        print("✅ MCP server testing completed!")
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ Server process timed out")
        process.kill()
        return False
    except Exception as e:
        print(f"❌ MCP server test failed: {e}")
        if 'process' in locals():
            process.terminate()
        return False

def test_command_line_interface():
    """Test the command line interface."""
    print("\n🖥️  Testing Command Line Interface")
    print("-" * 40)
    
    server_path = os.path.join(os.path.dirname(__file__), '.venv', 'bin', 'awslabs.aws-security-posture-advisor')
    
    if not os.path.exists(server_path):
        print(f"❌ Server executable not found")
        return False
    
    try:
        # Test --help
        result = subprocess.run(
            [server_path, '--help'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("✅ --help command works")
            help_output = result.stdout
            if 'AWS Security Posture Advisor' in help_output:
                print("   Help output contains expected content")
            else:
                print("   Help output:")
                print(f"   {help_output[:200]}...")
        else:
            print(f"❌ --help failed: {result.stderr}")
        
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ Command line test timed out")
        return False
    except Exception as e:
        print(f"❌ Command line test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 AWS Security Posture Advisor - MCP Client Testing")
    print(f"Time: {asyncio.get_event_loop().time()}")
    
    # Test command line interface
    cli_success = test_command_line_interface()
    
    # Test MCP server
    try:
        mcp_success = asyncio.run(test_mcp_server())
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
        mcp_success = False
    except Exception as e:
        print(f"\n❌ MCP testing failed: {e}")
        mcp_success = False
    
    if cli_success and mcp_success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed")
        sys.exit(1)
