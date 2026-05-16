# Infrastructure Deployment

Three deployment options are provided for deploying the AWS Security Posture Advisor MCP Server on **ECS Fargate**:

| Option | Directory | Best For |
|--------|-----------|----------|
| **CDK** | `cdk/` | Teams already using CDK; most Pythonic |
| **CloudFormation** | `cloudformation/` | Teams preferring native AWS templates; no extra tooling |
| **Terraform** | `terraform/` | Multi-cloud teams; state management built-in |

## Architecture

All three options deploy the same architecture:

```
┌─────────────┐       ┌─────────────┐       ┌──────────────────────┐
│   Client    │──────▶│     ALB     │──────▶│  ECS Fargate Task    │
│ (Kiro/IDE)  │  :80  │  (optional) │ :8000 │  ┌────────────────┐  │
└─────────────┘       └─────────────┘       │  │  MCP Server    │  │
                                            │  │  (Docker)       │  │
                                            │  └────────────────┘  │
                                            │  IAM Task Role ──────┼──▶ Security Hub
                                            │  (read-only)         │──▶ GuardDuty
                                            └──────────────────────┘──▶ Config
```

## What Gets Created

- **VPC** with public/private subnets, NAT gateway
- **ECR Repository** for Docker images
- **ECS Cluster** with Container Insights
- **Fargate Service** running the MCP server
- **IAM Task Role** with least-privilege read-only access to security services
- **CloudWatch Log Group** (30-day retention)
- **ALB** (optional) for HTTP/SSE access

## Security

- Task runs in **private subnets** (no public IP)
- IAM role has **read-only** permissions only
- Container runs as **non-root user**
- **No credentials stored** in code or environment variables
- ECR images scanned on push
- Container Insights enabled for monitoring

## Quick Start (any option)

1. Choose your preferred tool (CDK/CloudFormation/Terraform)
2. Deploy the infrastructure
3. Build & push Docker image to ECR
4. Service starts automatically

See each subdirectory's README for detailed instructions.
