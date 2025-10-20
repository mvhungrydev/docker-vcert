# Terraform variables for VCert Lambda deployment

# Project name
project_name = "terraform-cicd"

# Environment
environment = "dev"

# Lambda function name
function_name = "vcert-docker-lambda"

# AWS region
aws_region = "us-east-1"

# ECR repository name (optional - will default to {project_name}/vcert-lambda)
# ecr_repository = "custom/repository-name"

# EventBridge schedule expression
# EventBridge schedule expression (examples)
# schedule_expression = "rate(30 minutes)"   # Every 30 minutes
# schedule_expression = "rate(6 hours)"      # Every 6 hours
# schedule_expression = "cron(0 9 * * ? *)"  # Daily at 9 AM UTC
schedule_expression = "rate(5 minutes)"
