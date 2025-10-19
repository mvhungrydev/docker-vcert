# Example Terraform variables file
# Copy this file to terraform.tfvars and update the values

# AWS region where resources will be created
aws_region = "us-east-1"

# Environment (dev, staging, prod)
environment = "dev"

# Project name - should match your existing IAM role naming pattern
project_name = "terraform-cicd"

# Starting Docker image tag (optional - defaults to 5.11.1)
image_tag = "10-19.3"

# GitHub repository URL for CodeBuild source (required)
github_repo_url = "https://github.com/mvhungrydev/docker-vcert.git"