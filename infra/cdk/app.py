#!/usr/bin/env python3
"""AWS CDK app for deploying the AWS Security Posture Advisor MCP Server on ECS Fargate."""

import aws_cdk as cdk

from stack import SecurityAdvisorStack

app = cdk.App()

SecurityAdvisorStack(
    app,
    "SecurityAdvisorMcpStack",
    env=cdk.Environment(
        account=app.node.try_get_context("account") or None,
        region=app.node.try_get_context("region") or "us-east-1",
    ),
    description="AWS Security Posture Advisor MCP Server on ECS Fargate",
)

app.synth()
