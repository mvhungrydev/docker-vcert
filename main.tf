# Terraform configuration for VCert-Lambda ECR repository and CodeBuild project

terraform {
  required_version = ">= 1.0"
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

# Data source for existing IAM role
data "aws_iam_role" "existing_codebuild_role" {
  name = var.existing_codebuild_role_name
}

# ECR Repository for the VCert Lambda container
resource "aws_ecr_repository" "vcert_lambda" {
  name                 = "${var.project_name}/${var.environment}-vcert"
  image_tag_mutability = "MUTABLE"

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

# ECR Repository Policy to allow CodeBuild to push images
resource "aws_ecr_repository_policy" "vcert_lambda_policy" {
  repository = aws_ecr_repository.vcert_lambda.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCodeBuildPush"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_iam_role.existing_codebuild_role.arn
        }
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
      }
    ]
  })
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

  tags = {
    Name        = "${var.project_name}-${var.environment}-build"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
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