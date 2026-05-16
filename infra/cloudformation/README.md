# CloudFormation Deployment

## Deploy

```bash
cd infra/cloudformation

aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-advisor \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    EnvironmentName=security-advisor \
    ContainerCpu=512 \
    ContainerMemory=1024 \
    DesiredCount=1 \
    EnableALB=true
```

## Push Docker Image

```bash
# Get ECR URI from stack outputs
ECR_URI=$(aws cloudformation describe-stacks --stack-name security-advisor --query 'Stacks[0].Outputs[?OutputKey==`ECRRepositoryUri`].OutputValue' --output text)

# Login, build, push
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $ECR_URI
docker build -t security-advisor ../../
docker tag security-advisor:latest $ECR_URI:latest
docker push $ECR_URI:latest

# Force new deployment
aws ecs update-service --cluster security-advisor-cluster --service security-advisor-service --force-new-deployment
```

## Delete

```bash
aws cloudformation delete-stack --stack-name security-advisor
```
