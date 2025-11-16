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
│ - Function: fetch_aws_secret│
│   - Returns: dict (secret) or │
│     None on failure.          │
│   - Error: logs and exits if  │
│     secret missing/invalid.   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Fetch Applications          │
│ - Query Venafi Cloud for    │
│   all registered apps.      │
│ - Filter for AWS apps by    │
│   name prefix ("aws_").     │
│ - Function: fetch_aws_applications_data   │
│   - Returns: list of {app,id}│
│     dicts or [] on failure.   │
│   - Error: logs and returns    │
│     empty list on failure.     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Fetch Certificates          │
│ - If `certificate_ids_to_process` is empty, query Venafi Cloud for certificates issued in the last N minutes. │
│ - If `certificate_ids_to_process` contains IDs, fetch only those certificates. │
│ - Function: fetch_certificates_data        │
│   - Only ACTIVE and CURRENT certificates are fetched. │
│   - Returns: list of cert     │
│     objects (partial or empty)│
│   - Error: logs and returns partial results  │
│     on API error; if none found, exits.      │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Map Certs to Applications   │
│ - Build mapping of app IDs  │
│   to relevant certificates. │
│ - Extract cert details      │
│   (serial, CN, validity).   │
│ - Function: inline mapping logic in script │
│ - Error: skips malformed data;             │
│   unmapped apps show as "UNKNOWN".         │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│ For each App/Account/Region:                │
│   - Parse AWS account number from app name. │
│   - Assume cross-account IAM role in each   │
│     target region.                          │
│   - Function: fetch_cross_account_role_assume_creds │
│     • Returns: dict creds    │
│       (AKID/SAK/Token) or None. │
│     • Error: log and skip region/account on  │
│       failure.                                │
│   - Download certificate chain and private  │
│     key using vcert CLI.                    │
│   - Function: fetch_cert_key_chain           │
│     • Returns: {leaf_cert,  │
│       issuing_cert, root_cert,│
│       private_key, pem} or None. │
│     • Error: log; skip if missing chain/key. │
│   - Validate certificate/key presence.      │
│   - Upload certificate chain and key to     │
│     AWS Secrets Manager as a new or updated │
│     secret.                                │
│   - Function: create_update_cert_secret      │
│     • Returns: None (side-  │
│       effect: create/update).│
│     • Error: log on create/update failure.   │
│   - Log success or error for each upload.   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ End                         │
└─────────────────────────────┘
```

## Function reference

- fetch_aws_secret(secret_name, region_name="us-east-2")

  - Inputs: secret_name (str), region_name (str, default "us-east-2")
  - Returns: dict (parsed secret) or None
  - Errors/Notes: Logs detailed Secrets Manager errors; caller exits if API key secret is None

- fetch_aws_applications_data(api_base_url, headers)

  - Inputs: api_base_url (str), headers (dict)
  - Returns: list[dict] of {"app", "id"} (filtered to names starting with "aws\_") or []
  - Errors/Notes: Logs on HTTP/parse failures and returns empty list

- fetch_certificates_data(api_base_url, headers, minutes=15, certificate_ids_to_process=None)

  - Inputs: api_base_url (str), headers (dict), minutes (int, default 15), certificate_ids_to_process (list[str] | None)
  - Returns: list[dict] of certificate objects (bulk mode) or targeted certificates; may be partial/empty on errors
  - Errors/Notes: Logs on HTTP errors and returns what has been collected so far; script logs and exits if overall result is empty in bulk mode

- fetch_cross_account_role_assume_creds(target_role_arn, aws_region)

  - Inputs: target_role_arn (str), aws_region (str)
  - Returns: dict Credentials {AccessKeyId, SecretAccessKey, SessionToken, ...} or None
  - Errors/Notes: Logs assume-role failures; caller skips that account/region on None

- fetch_cert_key_chain(api_token, token_switch, vcert_bin_path, cert_request_id)

  - Inputs: api_token (str), token_switch (str), vcert_bin_path (str), cert_request_id (str)
  - Returns: dict {leaf_cert, issuing_cert, root_cert, private_key, pem} or None
  - Errors/Notes: Runs vcert CLI; logs stderr on failure; caller skips certificate if any required piece is missing

- create_update_cert_secret(creds, secret_name, region, aws_account_number, cert_data)
  - Inputs: creds (dict from STS), secret_name (str), region (str), aws_account_number (str), cert_data (dict)
  - Returns: None (side effect: creates or updates the secret)
  - Errors/Notes: Logs on create/update errors; safe to call repeatedly (update path handles exists)

## Troubleshooting

- Ensure your AWS credentials are valid and have the necessary permissions.
- Check that the Venafi API key is correctly stored in AWS Secrets Manager.
- Make sure the vcert binary is executable and in the correct path.
- If you provide certificate IDs, ensure they are valid and exist in Venafi Cloud.
- Review logs for error messages and skipped certificates.

## License

MIT
