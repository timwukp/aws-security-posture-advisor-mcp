# CDK Deployment

## Prerequisites
- AWS CDK CLI: `npm install -g aws-cdk`
- Python 3.10+
- AWS credentials configured

## Deploy

```bash
cd infra/cdk
pip install -r requirements.txt
cdk bootstrap   # first time only
cdk deploy
```

## Push Docker Image

```bash
# Get ECR login
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

# Build and push
docker build -t aws-security-posture-advisor ../../
docker tag aws-security-posture-advisor:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/aws-security-posture-advisor:latest
docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/aws-security-posture-advisor:latest
```

## Configuration

Edit `cdk.json` context values or pass via CLI:

```bash
cdk deploy --context cpu=1024 --context memory=2048 --context enable_alb=true
```
