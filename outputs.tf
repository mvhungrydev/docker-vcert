# Outputs for VCert-Lambda Terraform configuration

output "ecr_repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.vcert_lambda.repository_url
}

output "ecr_repository_name" {
  description = "Name of the ECR repository"
  value       = aws_ecr_repository.vcert_lambda.name
}

output "ecr_repository_arn" {
  description = "ARN of the ECR repository"
  value       = aws_ecr_repository.vcert_lambda.arn
}



output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "docker_build_command" {
  description = "Command to manually build and push Docker image"
  value       = "aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com && docker build -t ${aws_ecr_repository.vcert_lambda.repository_url}:${var.image_tag} . && docker push ${aws_ecr_repository.vcert_lambda.repository_url}:${var.image_tag}"
}