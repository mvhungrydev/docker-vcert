# VCert Lambda Infrastructure

Terraform configuration for deploying a **Venafi VCert Lambda function** with automated certificate management capabilities. This infrastructure automatically manages SSL/TLS certificates using Venafi's VCert tool in a serverless AWS environment.

## 🏗️ Architecture Overview

This project deploys:

- **AWS Lambda Function** (Container-based) running VCert
- **EventBridge Rule** for hourly certificate checks
- **IAM Role** with permissions for ACM and Secrets Manager
- **Automated Certificate Management** workflows

## 📁 Project Structure

```
├── main.tf              # Main Terraform configuration
├── variables.tf         # Variable definitions
├── terraform.tfvars    # Variable values (local state)
├── examples.tfvars     # Example configuration
├── buildspec.yml       # AWS CodeBuild configuration
└── README.md           # This file
```

## 🚀 Prerequisites

- **Terraform** (>= 1.0) with AWS Provider ~> 6.0
- **AWS CLI** configured with appropriate credentials
- **ECR Repository** with VCert container image
- **IAM Permissions** for Lambda, ACM, Secrets Manager, and EventBridge

## ⚙️ Configuration Variables

| Variable              | Description                      | Default                              | Required |
| --------------------- | -------------------------------- | ------------------------------------ | -------- |
| `account_id`          | AWS account ID for ECR image     | -                                    | ✅       |
| `image_tag`           | ECR image tag to deploy          | -                                    | ✅       |
| `project_name`        | Project name for resource naming | `terraform-cicd`                     | ❌       |
| `environment`         | Environment (dev/staging/prod)   | `dev`                                | ❌       |
| `function_name`       | Lambda function name             | `vcert-docker`                       | ❌       |
| `aws_region`          | AWS region for deployment        | `us-east-1`                          | ❌       |
| `ecr_repository`      | ECR repository name              | `{project_name}/{environment}-vcert` | ❌       |
| `schedule_expression` | EventBridge schedule expression  | `rate(1 hour)`                       | ❌       |

## 🔧 Getting Started

### 1. Configure Variables

Copy and customize the example configuration:

```bash
cp examples.tfvars terraform.tfvars
# Edit terraform.tfvars with your values
```

**Required Variables:**

```hcl
# terraform.tfvars
account_id = "123456789012"  # Your AWS account ID
image_tag = "latest"
```

### 2. Initialize and Deploy

```bash
# Initialize Terraform
terraform init

# Review deployment plan
terraform plan

# Deploy infrastructure
terraform apply
```

### 3. Verify Deployment

```bash
# Check Lambda function
aws lambda get-function --function-name vcert-docker-lambda

# Check EventBridge rule
aws events describe-rule --name terraform-cicd-dev-time-rule
```

## 🏷️ Resource Naming Convention

Resources follow the pattern: `{project_name}-{environment}-{resource_type}`

**Examples:**

- IAM Role: `terraform-cicd-dev-lambda-exec-role`
- Lambda Function: `vcert-docker-lambda` (configurable)
- EventBridge Rule: `terraform-cicd-dev-time-rule`

## 🔐 Security & Permissions

### IAM Permissions Included:

- **AWS Certificate Manager (ACM)**:
  - Import, describe, list, delete certificates
  - Certificate tagging operations
- **AWS Secrets Manager**:
  - Create, update, retrieve, delete secrets
- **CloudWatch Logs**:
  - Basic Lambda execution logging

### Security Best Practices:

- ✅ Least privilege IAM policies
- ✅ Resource-level tagging
- ✅ ECR image versioning
- ✅ Environment separation

## 📅 Automation Schedule

- **Default Frequency**: Every hour (`rate(1 hour)`)
- **Configurable**: Use `schedule_expression` variable
- **Trigger**: EventBridge (CloudWatch Events)
- **Function**: Certificate lifecycle management
- **Timeout**: 30 seconds

### Schedule Expression Examples:

```hcl
# Rate expressions
schedule_expression = "rate(30 minutes)"   # Every 30 minutes
schedule_expression = "rate(6 hours)"      # Every 6 hours
schedule_expression = "rate(1 day)"        # Daily

# Cron expressions
schedule_expression = "cron(0 9 * * ? *)"    # Daily at 9 AM UTC
schedule_expression = "cron(0 18 ? * FRI *)" # Every Friday at 6 PM UTC
schedule_expression = "cron(0 0 1 * ? *)"    # First day of month at midnight
```

## 🐳 Container Configuration

**ECR Repository Structure:**

```
{account_id}.dkr.ecr.{region}.amazonaws.com/{project_name}/{environment}-vcert:{image_tag}
```

**Example:**

```
123456789012.dkr.ecr.us-east-1.amazonaws.com/terraform-cicd/dev-vcert:latest
```

## 🌍 Multi-Environment Deployment

Deploy to different environments by overriding variables:

```bash
# Different schedule frequencies
terraform apply -var="schedule_expression=rate(30 minutes)"

# Daily at specific time
terraform apply -var="schedule_expression=cron(0 9 * * ? *)"

# Different environments
terraform apply -var="environment=staging" -var="image_tag=staging"
```

## 🚢 CI/CD Integration

**AWS CodeBuild** configuration included (`buildspec.yml`):

- Installs Terraform
- Destroys existing infrastructure
- Deploys fresh infrastructure
- Uses environment variables for dynamic configuration

**Environment Variables:**

- `ACCOUNT_ID` - AWS account ID
- `IMAGE_TAG` - Container image tag
- `TFVER` - Terraform download URL

## 🔄 State Management

Currently configured for **local state**. For production environments, consider using remote state:

```hcl
terraform {
  backend "s3" {
    bucket = "your-terraform-state-bucket"
    key    = "vcert-lambda/terraform.tfstate"
    region = "us-east-1"
  }
}
```

## 🧹 Cleanup

Remove all infrastructure:

```bash
terraform destroy
```

## 📚 Additional Resources

- [Venafi VCert Documentation](https://github.com/Venafi/vcert)
- [AWS Lambda Container Images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html)
- [AWS Certificate Manager](https://docs.aws.amazon.com/acm/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/)

## 🆘 Support & Troubleshooting

**Common Issues:**

- **ECR Authentication**: Ensure AWS CLI is configured with ECR permissions
- **Lambda Timeout**: Increase timeout if certificate operations take longer
- **IAM Permissions**: Verify Lambda role has required ACM/Secrets Manager permissions

**Logs:**

```bash
# View Lambda logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/vcert-docker-lambda
```
