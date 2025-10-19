# Variables for VCert-Lambda Terraform configuration

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}


variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "terraform-cicd"
}

variable "image_tag" {
  description = "Starting Docker image tag to use"
  type        = string
  default     = ""
}

variable "github_repo_url" {
  description = "GitHub repository URL for CodeBuild source"
  type        = string
  validation {
    condition     = can(regex("^https://github\\.com/.+/.+\\.git$", var.github_repo_url))
    error_message = "The github_repo_url must be a valid GitHub repository URL ending with .git"
  }
}

### Lambda Deployment Vars ###
variable "ecr_repository" {
  type        = string
  description = "ECR repository name (if empty, will use project_name/vcert-lambda)"
  default     = ""
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression for Lambda execution"
  default     = "rate(1 hour)"
}

variable "function_name" {
  type        = string
  description = "Name of the Lambda function"
  default     = "vcert-docker"
}
