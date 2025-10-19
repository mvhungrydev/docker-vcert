# Terraform configuration for VCert-Lambda ECR repository and CodeBuild project

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configuration for Terraform state
  # Uncomment and configure as needed for your environment

  # Example S3 backend configuration
  # backend "s3" {
  #   bucket  = "your-terraform-state-bucket"
  #   key     = "docker-vcert/terraform.tfstate"
  #   region  = "us-east-1"
  #   encrypt = true
  #   
  # }

  # Example local backend (default)
  # backend "local" {
  #   path = "terraform.tfstate"
  # }
}

provider "aws" {
  region = var.aws_region
}

# Data source for existing IAM role - dynamically find role containing project_name and environment
data "aws_iam_roles" "codebuild_roles" {
  name_regex = ".*${var.project_name}.*${var.environment}.*codebuild.*"
}

# Use the first matching role that contains project_name and environment
locals {
  selected_role_name = length(data.aws_iam_roles.codebuild_roles.names) > 0 ? tolist(data.aws_iam_roles.codebuild_roles.names)[0] : null
}

data "aws_iam_role" "existing_codebuild_role" {
  name = local.selected_role_name
}

# ECR Repository for the VCert Lambda container
resource "aws_ecr_repository" "vcert_lambda" {
  name                 = "${var.project_name}/${var.environment}-vcert"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-vcert"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Attach your existing ECR policy to the CodeBuild role
resource "aws_iam_role_policy_attachment" "codebuild_ecr_policy" {
  role       = data.aws_iam_role.existing_codebuild_role.name
  policy_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.project_name}-${var.environment}-codebuild-ecr-policy"
}

# ECR Lifecycle Policy to manage image retention
resource "aws_ecr_lifecycle_policy" "vcert_lambda_lifecycle" {
  repository = aws_ecr_repository.vcert_lambda.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "release"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Delete untagged images older than 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# CodeBuild Project for building and pushing the Docker image
resource "aws_codebuild_project" "vcert_lambda_build" {
  name         = "${var.project_name}-${var.environment}-build"
  description  = "CodeBuild project for ${var.project_name} ${var.environment} container"
  service_role = data.aws_iam_role.existing_codebuild_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode            = true # Required for Docker builds

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.aws_region
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = aws_ecr_repository.vcert_lambda.name
    }

    environment_variable {
      name  = "IMAGE_TAG"
      value = var.image_tag
    }
  }

  source {
    type            = "GITHUB"
    location        = var.github_repo_url
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = false
    }
  }

  source_version = "refs/heads/main"

  tags = {
    Name        = "${var.project_name}-${var.environment}-build"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# CodeBuild Webhook for GitHub integration
resource "aws_codebuild_webhook" "vcert_lambda_webhook" {
  project_name = aws_codebuild_project.vcert_lambda_build.name
  build_type   = "BUILD"

  filter_group {
    filter {
      type    = "EVENT"
      pattern = "PUSH"
    }
    filter {
      type    = "HEAD_REF"
      pattern = "^refs/heads/main$"
    }
  }
}

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# CloudWatch Log Group for CodeBuild logs
resource "aws_cloudwatch_log_group" "codebuild_logs" {
  name              = "/aws/codebuild/${var.project_name}-${var.environment}-build"
  retention_in_days = 7

  tags = {
    Name        = "${var.project_name}-${var.environment}-build-logs"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}


##### Lambda Deployment ######

# Local values for computed configurations
locals {
  ecr_repository = var.ecr_repository != "" ? var.ecr_repository : "${var.project_name}/${var.environment}-vcert"
}

# Lambda Execution Role
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-${var.environment}-lambda-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-lambda-exec-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Inline policy for Secrets Manager access
resource "aws_iam_role_policy" "lambda_secrets_acm" {
  name = "${var.project_name}-${var.environment}-secrets-acm-policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DeleteSecret",
          "acm:ImportCertificate",
          "acm:DescribeCertificate",
          "acm:ListCertificates",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:RemoveTagsFromCertificate"
        ]
        Resource = "*"
      }
    ]
  })
}

# Basic logging permissions
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



# lambda function
resource "aws_lambda_function" "lambda_function" {
  function_name = var.function_name
  package_type  = "Image"
  image_uri     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${local.ecr_repository}:${var.image_tag}"
  role          = aws_iam_role.lambda_exec.arn
  timeout       = 30

  tags = {
    Name        = var.function_name
    Project     = var.project_name
    Environment = var.environment
  }
}


# EventBridge Rule
resource "aws_cloudwatch_event_rule" "time" {
  name                = "${var.project_name}-${var.environment}-time-rule"
  description         = "Run ${var.function_name} lambda on schedule: ${var.schedule_expression}"
  schedule_expression = var.schedule_expression

  tags = {
    Name        = "${var.project_name}-${var.environment}-time-rule"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.time.arn
}

# Attach Lambda to the EventBridge rule
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.time.name
  target_id = "${var.project_name}-${var.environment}-lambda-target"
  arn       = aws_lambda_function.lambda_function.arn
}
