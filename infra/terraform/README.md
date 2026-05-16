# Terraform Deployment

## Prerequisites
- Terraform >= 1.5.0
- AWS credentials configured

## Deploy

```bash
cd infra/terraform
terraform init
terraform plan
terraform apply
```

## Push Docker Image

```bash
# Get ECR URL from terraform output
ECR_URL=$(terraform output -raw ecr_repository_url)

# Login, build, push
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $ECR_URL
docker build -t security-advisor ../../
docker tag security-advisor:latest $ECR_URL:latest
docker push $ECR_URL:latest

# Force new deployment
aws ecs update-service \
  --cluster $(terraform output -raw cluster_name) \
  --service security-advisor-service \
  --force-new-deployment
```

## Customise

Create a `terraform.tfvars` file:

```hcl
aws_region       = "us-east-1"
environment_name = "security-advisor"
container_cpu    = 512
container_memory = 1024
desired_count    = 1
enable_alb       = true
```

## Destroy

```bash
terraform destroy
```
