#!/usr/bin/env python3
"""Minimal AWS Security MCP Server for testing."""

import asyncio
from mcp.server import Server
from mcp.types import Tool
import boto3

app = Server("aws-security-advisor")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="test_aws_connection",
            description="Test AWS connection and credentials",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "test_aws_connection":
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            return {
                "success": True,
                "account": identity.get('Account'),
                "user_arn": identity.get('Arn')
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

if __name__ == "__main__":
    import mcp.server.stdio
    mcp.server.stdio.run_server(app)
