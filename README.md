# VCert-Lambda

A containerized AWS Lambda function for automated certificate management using Venafi's VCert tool. This solution automates the process of downloading certificates from Venafi, importing them into AWS Certificate Manager (ACM), and storing them in AWS Secrets Manager.

## Project Structure

```
docker-vcert/
├── app.py              # Lambda handler function
├── Dockerfile          # Container configuration for Lambda
├── requirements.txt    # Python dependencies
├── buildspec.yml       # AWS CodeBuild configuration
├── vcert              # Venafi VCert binary (Linux x86-64)
└── README.md          # This file

Infra/ (separate)
├── main.tf            # Terraform infrastructure
├── backend.tf         # Terraform backend configuration
└── policy/            # IAM policies
```

## Description

This project deploys a containerized AWS Lambda function that:

- **Integrates with Venafi**: Uses the VCert binary to interact with Venafi certificate management platform
- **Certificate Management**: Downloads certificates from Venafi API based on application names/tags
- **AWS Integration**:
  - Imports certificates into AWS Certificate Manager (ACM)
  - Stores certificate data in AWS Secrets Manager
  - Supports cross-account secret management
- **Automation**: Runs as a scheduled Lambda function for certificate lifecycle management

## Features

- ✅ Containerized Lambda deployment using AWS Lambda Python 3.13 runtime
- ✅ VCert binary integration for Venafi operations
- ✅ AWS ACM certificate import functionality
- ✅ AWS Secrets Manager integration for secure storage
- ✅ Self-signed certificate generation (for testing)
- ✅ AWS CodeBuild pipeline for Docker image builds
- 🚧 Venafi API integration (in development)
- 🚧 Certificate filtering by application/tags (planned)

## Prerequisites

- AWS CLI configured
- Docker installed
- AWS ECR repository: `<account-id>.dkr.ecr.<region>.amazonaws.com/venafi/vcert-lambda`
- VCert binary (included as `vcert` file)
- Terraform (for infrastructure deployment)

## Usage

### 1. Build and Deploy

```bash
# Build and push Docker image using CodeBuild
aws codebuild start-build --project-name vcert-lambda-build

# OR build manually
docker build -t vcert-lambda .
docker tag vcert-lambda:latest <account-id>.dkr.ecr.<region>.amazonaws.com/venafi/vcert-lambda:5.11.1
docker push <account-id>.dkr.ecr.<region>.amazonaws.com/venafi/vcert-lambda:5.11.1
```

### 2. Deploy Infrastructure

```bash
cd Infra/
terraform init
terraform plan
terraform apply
```

### 3. Lambda Function Capabilities

The Lambda handler (`app.handler`) supports:

- **VCert Operations**: Execute VCert binary commands
- **Secret Management**:
  - Retrieve secrets from AWS Secrets Manager
  - Create/update secrets across regions
- **Certificate Operations**:
  - Generate self-signed certificates (testing)
  - Import certificates to ACM
  - Download certificates from Venafi (planned)
- **API Integration**: HTTP requests to external APIs

## Environment Variables

| Variable             | Description              | Required            |
| -------------------- | ------------------------ | ------------------- |
| `AWS_DEFAULT_REGION` | AWS region for resources | Yes                 |
| `AWS_ACCOUNT_ID`     | AWS account ID           | Yes (for CodeBuild) |

## Dependencies

- **Python Packages**:

  - `requests` - HTTP client for API calls
  - `cryptography` - Certificate operations and cryptographic functions
  - `boto3` - AWS SDK (included in Lambda runtime)

- **System Dependencies**:
  - VCert binary (Venafi certificate management tool)

## Development Status

### Completed

- [x] Basic Lambda function structure
- [x] Docker containerization
- [x] AWS service integrations (ACM, Secrets Manager)
- [x] CodeBuild pipeline configuration
- [x] Self-signed certificate generation for testing

### In Progress

- [ ] Venafi API integration for certificate retrieval
- [ ] Certificate filtering logic by application name/tags
- [ ] Cross-account secret management implementation
- [ ] Error handling and logging improvements

### TODO

- [ ] Complete Venafi API integration
- [ ] Implement certificate filtering by application/tags
- [ ] Add comprehensive error handling
- [ ] Set up monitoring and alerting
- [ ] Add unit tests
- [ ] Create deployment documentation
- [ ] Implement certificate renewal automation

## Configuration

The Lambda function uses AWS Secrets Manager to store configuration. Create secrets with the following structure:

```json
{
  "venafi_api_key": "your-venafi-api-key",
  "venafi_endpoint": "https://your-venafi-instance.com",
  "target_applications": ["app1", "app2"]
}
```

## Security

- Lambda execution role requires permissions for:
  - ECR image pulls
  - Secrets Manager read/write
  - ACM certificate import
  - CloudWatch Logs
- Secrets are encrypted at rest in Secrets Manager
- Certificate private keys are securely handled

## License

[Add your license information here]
