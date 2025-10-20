#!/usr/bin/env python3
"""Simple test script to verify MCP server functionality."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'awslabs'))

try:
    from mcp import server
    print("✅ MCP library imported successfully")
    
    # Test basic MCP server creation
    app = server.Server("test-server")
    print("✅ MCP server instance created successfully")
    
    # Test AWS SDK
    import boto3
    print("✅ Boto3 imported successfully")
    
    # Test basic AWS client creation (without credentials)
    try:
        client = boto3.client('sts', region_name='us-east-1')
        print("✅ AWS client created successfully")
    except Exception as e:
        print(f"⚠️  AWS client creation warning: {e}")
    
    print("\n🎉 Basic MCP server components are working!")
    print("The server should be able to start with proper AWS credentials.")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)
