

variable "image_tag" {
  type        = string
  description = "Tag of the ECR image to deploy"
}

variable "project_name" {
  type        = string
  description = "Name of the project"
  default     = "terraform-cicd"
}

variable "environment" {
  type        = string
  description = "Environment (dev, staging, prod)"
  default     = "dev"
}

variable "function_name" {
  type        = string
  description = "Name of the Lambda function"
  default     = "vcert-docker"
}

variable "aws_region" {
  type        = string
  description = "AWS region for resources"
  default     = "us-east-1"
}

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

