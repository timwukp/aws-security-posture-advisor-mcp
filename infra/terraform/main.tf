######################################################################
# AWS Security Posture Advisor MCP Server - ECS Fargate (Terraform)
######################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------
# Variables
# -----------------------------------------------------------
variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "security-advisor"
}

variable "container_cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 512
}

variable "container_memory" {
  description = "Fargate task memory (MiB)"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of Fargate tasks"
  type        = number
  default     = 1
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "enable_alb" {
  description = "Whether to create an ALB"
  type        = bool
  default     = true
}

# -----------------------------------------------------------
# Data
# -----------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

# -----------------------------------------------------------
# VPC
# -----------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.environment_name}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${var.environment_name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 3}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${var.environment_name}-private-${count.index + 1}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.environment_name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.environment_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.environment_name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${var.environment_name}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.environment_name}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# -----------------------------------------------------------
# ECR
# -----------------------------------------------------------
resource "aws_ecr_repository" "main" {
  name                 = "${var.environment_name}-mcp"
  image_tag_mutability = "MUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "${var.environment_name}-ecr" }
}

resource "aws_ecr_lifecycle_policy" "main" {
  repository = aws_ecr_repository.main.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep only 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# -----------------------------------------------------------
# ECS Cluster
# -----------------------------------------------------------
resource "aws_ecs_cluster" "main" {
  name = "${var.environment_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${var.environment_name}-cluster" }
}

# -----------------------------------------------------------
# CloudWatch
# -----------------------------------------------------------
resource "aws_cloudwatch_log_group" "main" {
  name              = "/ecs/${var.environment_name}"
  retention_in_days = 30
  tags              = { Name = "${var.environment_name}-logs" }
}

# -----------------------------------------------------------
# IAM
# -----------------------------------------------------------
resource "aws_iam_role" "execution" {
  name = "${var.environment_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.environment_name}-execution-role" }
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name = "${var.environment_name}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.environment_name}-task-role" }
}

resource "aws_iam_role_policy" "task_security" {
  name = "security-services-readonly"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityHubReadOnly"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:DescribeHub",
          "securityhub:DescribeStandards",
          "securityhub:GetInsights",
          "securityhub:ListMembers"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyReadOnly"
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListDetectors",
          "guardduty:GetDetector",
          "guardduty:ListFindings"
        ]
        Resource = "*"
      },
      {
        Sid    = "ConfigReadOnly"
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:DescribeConfigRules",
          "config:DescribeConfigurationRecorders",
          "config:GetResourceConfigHistory"
        ]
        Resource = "*"
      },
      {
        Sid      = "STSIdentity"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------
# Security Groups
# -----------------------------------------------------------
resource "aws_security_group" "alb" {
  count       = var.enable_alb ? 1 : 0
  name        = "${var.environment_name}-alb-sg"
  description = "ALB security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.environment_name}-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name        = "${var.environment_name}-ecs-sg"
  description = "ECS task security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = var.enable_alb ? [aws_security_group.alb[0].id] : []
    cidr_blocks     = var.enable_alb ? [] : ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.environment_name}-ecs-sg" }
}

# -----------------------------------------------------------
# ALB (conditional)
# -----------------------------------------------------------
resource "aws_lb" "main" {
  count              = var.enable_alb ? 1 : 0
  name               = "${var.environment_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${var.environment_name}-alb" }
}

resource "aws_lb_target_group" "main" {
  count       = var.enable_alb ? 1 : 0
  name        = "${var.environment_name}-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = { Name = "${var.environment_name}-tg" }
}

resource "aws_lb_listener" "main" {
  count             = var.enable_alb ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main[0].arn
  }
}

# -----------------------------------------------------------
# ECS Task Definition
# -----------------------------------------------------------
resource "aws_ecs_task_definition" "main" {
  family                   = "${var.environment_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name  = "mcp-server"
    image = "${aws_ecr_repository.main.repository_url}:${var.image_tag}"

    portMappings = [{
      containerPort = 8000
      protocol      = "tcp"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.main.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "mcp"
      }
    }

    environment = [
      { name = "AWS_REGION", value = var.aws_region },
      { name = "FASTMCP_LOG_LEVEL", value = "INFO" },
      { name = "AWS_SECURITY_ADVISOR_READ_ONLY", value = "true" },
      { name = "AWS_SECURITY_ADVISOR_AUDIT_LOGGING", value = "true" },
      { name = "AWS_SECURITY_ADVISOR_LOG_TO_FILE", value = "false" },
    ]

    healthCheck = {
      command     = ["CMD-SHELL", "python -c 'from awslabs.aws_security_posture_advisor.core.common.config import validate_configuration; validate_configuration(); print(\"OK\")' || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 3
      startPeriod = 15
    }
  }])

  tags = { Name = "${var.environment_name}-task" }
}

# -----------------------------------------------------------
# ECS Service
# -----------------------------------------------------------
resource "aws_ecs_service" "main" {
  name            = "${var.environment_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = var.enable_alb ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.main[0].arn
      container_name   = "mcp-server"
      container_port   = 8000
    }
  }

  depends_on = [aws_lb_listener.main]

  tags = { Name = "${var.environment_name}-service" }
}

# -----------------------------------------------------------
# Outputs
# -----------------------------------------------------------
output "ecr_repository_url" {
  description = "ECR repository URL for pushing Docker images"
  value       = aws_ecr_repository.main.repository_url
}

output "cluster_name" {
  description = "ECS Cluster name"
  value       = aws_ecs_cluster.main.name
}

output "task_role_arn" {
  description = "IAM Task Role ARN"
  value       = aws_iam_role.task.arn
}

output "alb_dns_name" {
  description = "ALB DNS name (if enabled)"
  value       = var.enable_alb ? aws_lb.main[0].dns_name : "ALB not enabled"
}

output "push_commands" {
  description = "Commands to build and push Docker image"
  value       = <<-EOT
    aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${aws_ecr_repository.main.repository_url}
    docker build -t ${var.environment_name} ../../
    docker tag ${var.environment_name}:latest ${aws_ecr_repository.main.repository_url}:latest
    docker push ${aws_ecr_repository.main.repository_url}:latest
  EOT
}
