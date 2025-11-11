# PKI Certificate Fetch and Upload Script

This script automates the process of fetching recently issued certificates from Venafi Cloud, mapping them to AWS applications, and securely uploading them to AWS Secrets Manager in multiple accounts and regions.

## Features

- Fetches certificates issued in the last N minutes from Venafi Cloud, or processes a user-specified list of certificate IDs
- Maps certificates to AWS applications using Venafi API
- Assumes cross-account IAM roles for secure access
- Uploads certificate chains and private keys to AWS Secrets Manager
- Handles error logging and robust failure scenarios

## Prerequisites

- Python 3.7+
- AWS credentials with permission to assume target roles and manage secrets
- Venafi Cloud API key stored in AWS Secrets Manager
- vcert CLI binary (for certificate pickup)
- Required Python packages: boto3, requests

## Usage

1. Configure your AWS credentials and Venafi API key.
2. Set the required variables in the script (regions, role name, vcert path, etc).
3. To process all certificates issued in the last N minutes (default bulk mode):
   ```bash
   python _fetch_certs.py
   ```
4. To process only specific certificates, set the `certificate_ids_to_process` list in the script to the desired certificate IDs:
   ```python
   certificate_ids_to_process = [
       "280b8710-be84-11f0-8a92-1152c3883671",
       "20868760-bdd0-11f0-afd7-b326dadc92bf",
   ]
   ```
   Then run the script as usual:
   ```bash
   python _fetch_certs.py
   ```

## Main Steps

1. **Fetch Venafi API Key**: Retrieve the API key from AWS Secrets Manager.
2. **Fetch Applications**: Get all AWS applications from Venafi Cloud.
3. **Fetch Certificates**: Get all certificates issued in the last N minutes, or fetch only those specified in the `certificate_ids_to_process` list.
4. **Map Certificates to Applications**: Build a mapping of app IDs to certificates.
5. **Assume Roles**: For each app/account, assume the cross-account role in each region.
6. **Download Certificate Chain**: Use vcert CLI to download the certificate chain and private key.
7. **Upload to Secrets Manager**: Store the certificate chain and private key in AWS Secrets Manager.
8. **Error Handling**: Log and skip any failures (missing keys, role assumption errors, etc).

## Process Diagram

```
┌─────────────────────────────┐
│ Start                      │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Fetch Venafi API Key        │
│ - Retrieve API key from     │
│   AWS Secrets Manager.      │
│ - Used for authenticating   │
│   with Venafi Cloud.        │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Fetch Applications          │
│ - Query Venafi Cloud for    │
│   all registered apps.      │
│ - Filter for AWS apps by    │
│   name prefix ("aws_").     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Fetch Certificates          │
│ - If `certificate_ids_to_process` is empty, query Venafi Cloud for certificates issued in the last N minutes. │
│ - If `certificate_ids_to_process` contains IDs, fetch only those certificates. │
│ - Only ACTIVE and CURRENT certificates are fetched. │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Map Certs to Applications   │
│ - Build mapping of app IDs  │
│   to relevant certificates. │
│ - Extract cert details      │
│   (serial, CN, validity).   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│ For each App/Account/Region:                │
│   - Parse AWS account number from app name. │
│   - Assume cross-account IAM role in each   │
│     target region.                          │
│   - Download certificate chain and private  │
│     key using vcert CLI.                    │
│   - Validate certificate/key presence.      │
│   - Upload certificate chain and key to     │
│     AWS Secrets Manager as a new or updated │
│     secret.                                │
│   - Log success or error for each upload.   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ End                         │
└─────────────────────────────┘
```

## Troubleshooting

- Ensure your AWS credentials are valid and have the necessary permissions.
- Check that the Venafi API key is correctly stored in AWS Secrets Manager.
- Make sure the vcert binary is executable and in the correct path.
- If you provide certificate IDs, ensure they are valid and exist in Venafi Cloud.
- Review logs for error messages and skipped certificates.

## License

MIT
