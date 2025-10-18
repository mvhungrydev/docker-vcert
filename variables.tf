# Variables for VCert-Lambda Terraform configuration

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}

variable "existing_codebuild_role_name" {
  description = "Name of the existing IAM role to use for CodeBuild"
  type        = string
  validation {
    condition     = length(var.existing_codebuild_role_name) > 0
    error_message = "The existing_codebuild_role_name must not be empty."
  }
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
  description = "Docker image tag to use"
  type        = string
  default     = "5.11.1"
}

variable "github_repo_url" {
  description = "GitHub repository URL for CodeBuild source"
  type        = string
  validation {
    condition     = can(regex("^https://github\\.com/.+/.+\\.git$", var.github_repo_url))
    error_message = "The github_repo_url must be a valid GitHub repository URL ending with .git"
  }
}