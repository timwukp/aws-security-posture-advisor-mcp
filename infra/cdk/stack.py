"""CDK Stack for AWS Security Posture Advisor MCP Server on ECS Fargate."""

from constructs import Construct
import aws_cdk as cdk
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_ecr as ecr,
    aws_iam as iam,
    aws_logs as logs,
    aws_elasticloadbalancingv2 as elbv2,
    CfnOutput,
)


class SecurityAdvisorStack(Stack):
    """ECS Fargate stack for the Security Posture Advisor MCP Server."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Context parameters (override via cdk.json or --context) ---
        cpu = int(self.node.try_get_context("cpu") or 512)
        memory = int(self.node.try_get_context("memory") or 1024)
        desired_count = int(self.node.try_get_context("desired_count") or 1)
        enable_alb = self.node.try_get_context("enable_alb") == "true"

        # --- VPC ---
        vpc = ec2.Vpc(
            self,
            "Vpc",
            max_azs=2,
            nat_gateways=1,
        )

        # --- ECR Repository ---
        ecr_repo = ecr.Repository(
            self,
            "EcrRepo",
            repository_name="aws-security-posture-advisor",
            removal_policy=RemovalPolicy.RETAIN,
            image_scan_on_push=True,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    max_image_count=10,
                    description="Keep only 10 most recent images",
                )
            ],
        )

        # --- ECS Cluster ---
        cluster = ecs.Cluster(
            self,
            "Cluster",
            vpc=vpc,
            cluster_name="security-advisor-cluster",
            container_insights=True,
        )

        # --- CloudWatch Log Group ---
        log_group = logs.LogGroup(
            self,
            "LogGroup",
            log_group_name="/ecs/security-advisor-mcp",
            retention=logs.RetentionDays.THIRTY_DAYS,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Task Execution Role (for pulling images and writing logs) ---
        execution_role = iam.Role(
            self,
            "TaskExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                )
            ],
        )

        # --- Task Role (for the application to access AWS security services) ---
        task_role = iam.Role(
            self,
            "TaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="Role for Security Advisor MCP Server to access AWS security services",
        )

        # Least-privilege policy for security services (read-only)
        task_role.add_to_policy(
            iam.PolicyStatement(
                sid="SecurityHubReadOnly",
                effect=iam.Effect.ALLOW,
                actions=[
                    "securityhub:GetFindings",
                    "securityhub:DescribeHub",
                    "securityhub:DescribeStandards",
                    "securityhub:GetInsights",
                    "securityhub:ListMembers",
                ],
                resources=["*"],
            )
        )

        task_role.add_to_policy(
            iam.PolicyStatement(
                sid="GuardDutyReadOnly",
                effect=iam.Effect.ALLOW,
                actions=[
                    "guardduty:GetFindings",
                    "guardduty:ListDetectors",
                    "guardduty:GetDetector",
                    "guardduty:ListFindings",
                ],
                resources=["*"],
            )
        )

        task_role.add_to_policy(
            iam.PolicyStatement(
                sid="ConfigReadOnly",
                effect=iam.Effect.ALLOW,
                actions=[
                    "config:GetComplianceDetailsByConfigRule",
                    "config:DescribeConfigRules",
                    "config:DescribeConfigurationRecorders",
                    "config:GetResourceConfigHistory",
                ],
                resources=["*"],
            )
        )

        task_role.add_to_policy(
            iam.PolicyStatement(
                sid="STSIdentity",
                effect=iam.Effect.ALLOW,
                actions=["sts:GetCallerIdentity"],
                resources=["*"],
            )
        )

        # --- Task Definition ---
        task_definition = ecs.FargateTaskDefinition(
            self,
            "TaskDef",
            cpu=cpu,
            memory_limit_mib=memory,
            execution_role=execution_role,
            task_role=task_role,
        )

        container = task_definition.add_container(
            "McpServer",
            image=ecs.ContainerImage.from_ecr_repository(ecr_repo, tag="latest"),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="mcp-server",
                log_group=log_group,
            ),
            environment={
                "AWS_REGION": self.region,
                "FASTMCP_LOG_LEVEL": "INFO",
                "AWS_SECURITY_ADVISOR_READ_ONLY": "true",
                "AWS_SECURITY_ADVISOR_AUDIT_LOGGING": "true",
                "AWS_SECURITY_ADVISOR_LOG_TO_FILE": "false",
            },
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "python -c 'from awslabs.aws_security_posture_advisor.core.common.config import validate_configuration; validate_configuration(); print(\"OK\")' || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(10),
                retries=3,
                start_period=Duration.seconds(15),
            ),
        )

        # Port mapping for HTTP/SSE mode
        container.add_port_mappings(
            ecs.PortMapping(container_port=8000, protocol=ecs.Protocol.TCP)
        )

        # --- Fargate Service ---
        if enable_alb:
            # Deploy with Application Load Balancer for HTTP/SSE access
            fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
                self,
                "FargateService",
                cluster=cluster,
                task_definition=task_definition,
                desired_count=desired_count,
                public_load_balancer=True,
                listener_port=80,
                health_check_grace_period=Duration.seconds(60),
            )

            # Configure health check on ALB target group
            fargate_service.target_group.configure_health_check(
                path="/",
                healthy_http_codes="200",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(10),
            )

            CfnOutput(
                self,
                "LoadBalancerDNS",
                value=fargate_service.load_balancer.load_balancer_dns_name,
                description="ALB DNS name for the MCP server",
            )
        else:
            # Deploy without ALB (for stdio/private access)
            fargate_service = ecs.FargateService(
                self,
                "FargateService",
                cluster=cluster,
                task_definition=task_definition,
                desired_count=desired_count,
                assign_public_ip=False,
            )

        # --- Outputs ---
        CfnOutput(
            self,
            "EcrRepositoryUri",
            value=ecr_repo.repository_uri,
            description="ECR repository URI for pushing Docker images",
        )

        CfnOutput(
            self,
            "ClusterName",
            value=cluster.cluster_name,
            description="ECS cluster name",
        )

        CfnOutput(
            self,
            "TaskRoleArn",
            value=task_role.role_arn,
            description="Task Role ARN (for verifying permissions)",
        )
