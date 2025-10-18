# Backend configuration for Terraform state
# Uncomment and configure as needed for your environment

# Example S3 backend configuration
# terraform {
#   backend "s3" {
#     bucket  = "your-terraform-state-bucket"
#     key     = "docker-vcert/terraform.tfstate"
#     region  = "us-east-1"
#     encrypt = true
#     
#     # Optional: DynamoDB table for state locking
#     # dynamodb_table = "your-terraform-locks-table"
#   }
# }

# Example local backend (default)
# terraform {
#   backend "local" {
#     path = "terraform.tfstate"
#   }
# }