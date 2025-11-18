# PKI Certificate Fetch and Upload Script

This script automates the process of fetching recently issued certificates from Venafi Cloud, mapping them to AWS applications, and securely uploading them to AWS Secrets Manager in multiple accounts and regions.

## Features

- Fetches certificates issued in the last N minutes from Venafi Cloud, or processes a user-specified list of certificate IDs
- Maps certificates to AWS applications using Venafi API
- Assumes cross-account IAM roles for secure access
- Uploads certificate chains and private keys to AWS Secrets Manager
- Uploads certificates and chains to AWS ACM (Certificate Manager) when appropriate (if app name contains `_acm_`)
- Handles error logging and robust failure scenarios

## Prerequisites

- Python 3.7+
- AWS credentials with permission to assume target roles and manage secrets
- Venafi Cloud API key stored in AWS Secrets Manager
- vcert CLI binary (for certificate pickup)
- Required Python packages: boto3, requests, cryptography

## Usage

1. Configure your AWS credentials and Venafi API key.
2. Set the required variables in the script (regions, role name, vcert path, etc).
3. To process all certificates issued in the last N minutes (default bulk mode):

4. To process only specific certificates, set the `certificate_ids_to_process` list in the script to the desired certificate IDs:

   certificate_ids_to_process = [
   "280b8710-be84-11f0-8a92-1152c3883671",
   "20868760-bdd0-11f0-afd7-b326dadc92bf",
   ]

## Lambda event payload examples

Below are example event payloads you can use when invoking the Lambda handler in `app.py`.

- The first example is annotated (with comments) to explain each field. Note: JSON does not support comments—remove them before using in the Lambda console.
- The second example is a minimal payload; all omitted fields fall back to sane defaults in the handler.

### Full payload (annotated)

```jsonc
{
  // Venafi Cloud base URL; defaults to "https://api.venafi.cloud"
  "apiBaseUrl": "https://api.venafi.cloud",

  // Look-back window in minutes for bulk fetch; defaults to 15
  // Ignored if certificateIds is provided
  "minutes": 14,

  // Path to vcert binary in the Lambda image; defaults to "/usr/local/bin/vcert"
  // Change if your image places vcert elsewhere (e.g., "/opt/bin/vcert")
  "vcertBinPath": "/usr/local/bin/vcert",

  // Optional list of specific certificate IDs to process; when present, bulk search by minutes is skipped
  "certificateIds": [
    "280b8710-be84-11f0-8a92-1152c3883671",
    "20868760-bdd0-11f0-afd7-b326dadc92bf"
  ],

  // Auth switch for vcert pickup: "-k" for API key (default), "-t" for OAuth access token
  "tokenSwitch": "-k",

  // AWS regions to upload to; defaults to ["us-east-1", "us-west-2"]
  "awsRegions": ["us-east-1", "us-west-2"],

  // Name of the cross-account IAM role to assume in each target account
  // The handler constructs: arn:aws:iam::<account-id>:role/<this-name>
  "crossAccountRoleName": "CrossAccountSecretsAndACMRole"
}
```

### Minimal payload

If you only want to adjust the look-back window and use all other defaults:

```json
{ "minutes": 10 }
```

Handler defaults (when keys are omitted):

- apiBaseUrl: https://api.venafi.cloud
- minutes: 15
- vcertBinPath: /usr/local/bin/vcert
- certificateIds: [] (empty list means bulk mode by minutes)
- tokenSwitch: -k
- awsRegions: ["us-east-1", "us-west-2"]
- crossAccountRoleName: CrossAccountSecretsAndACMRole

## Data Structures

Several key mappings and data structures are used throughout the script. Example data is shown for clarity:

- **app_id_to_app_name**: `dict[str, str]`

  - Maps application IDs (UUID strings) to application names.
  - Example:
    ```python
    {
      '01e74a50-b115-11f0-8d72-5db6f6714f7d': 'aws_55555_8524855123412_lle',
      '13a61880-b114-11f0-9ded-f9c8726fae77': 'aws_55555_8524855123412_lle',
      ...
    }
    ```

- **unique_app_ids_from_certs_list**: `set[str]`

  - Set of application IDs found in the certificate data.
  - Example:
    ```python
    {
      '07160950-bdcf-11f0-8d6a-51911d7ee646',
      '659e5430-b115-11f0-8d72-5db6f6714f7d',
      ...
    }
    ```

- **app_id_to_certs**: `defaultdict(list)`

  - Maps application IDs to lists of certificate dicts.
  - Each certificate dict contains: `id`, `certificateRequestId`, `serialNumber`, `subjectCN`, `validityStart`, `validityEnd`, `app_name`.
  - Example:
    ```python
    {
      '07160950-bdcf-11f0-8d6a-51911d7ee646': [
        {
          'id': '92f30750-c2c2-11f0-8cd1-415078a52a2f',
          'certificateRequestId': '92ea06a0-c2c2-11f0-8d8a-a91e6abe086d',
          'serialNumber': '497CE118EE20CA41F7977EFACCA2153F6BA0C988',
          'subjectCN': ['cert-f0b8869b.mydomain.com'],
          'validityStart': '2025-11-16T08:01:49.000+00:00',
          'validityEnd': '2026-02-14T08:02:19.000+00:00',
          'app_name': 'aws_12345_123456499234_lle'
        },
        ...
      ],
      ...
    }
    ```

- **aws_account_number_to_app_ids**: `dict[str, list[dict]]`

  - Maps AWS account numbers to lists of app dicts (`app_name`, `app_id`).
  - Example:
    ```python
    {
      '123456499234': [
        {'app_name': 'aws_12345_123456499234_lle', 'app_id': '07160950-bdcf-11f0-8d6a-51911d7ee646'}
      ],
      '730335123456': [
        {'app_name': 'aws_12345_730335123456_ACM_lle', 'app_id': '699d24a0-c333-11f0-a91f-6bf9605e2a86'},
        {'app_name': 'aws_12345_730335123456_lle', 'app_id': '7dec5490-a7fd-11f0-a03f-91f52b49ac04'}
      ],
      ...
    }
    ```

- **aws_account_number_to_credentials**: `dict[str, dict]`
  - Maps AWS account numbers to credential dicts (with `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`).
  - Example:
    ```python
    {
      '123456499234': {
        'credentials': {
          'AccessKeyId': 'AS123123123123W',
          'SecretAccessKey': '1234124123123124',
          'SessionToken': 'I1231231231231237//////////wEaCXVzLWVhc3QtMSJIMEYCIQCFaxTa51bwXL8XygXe6vuI3GTnVk7ywwfIXbX2M1BVHwIhANCg11W3J3tK10ZlsqgNmQE+yE3aiUYuuulWLwDDsXCNKrwCCKf//////////wEQABoMMTU0NjQ1NDk5MjM0Igyrh7jr7f1/RvEsxnQqkAIgY3ExLDArcZn2M2XxHL/6GHdpauMqcAjJviPG/7PkzorTrw7AZclLFBlOM4p7Mh/v0YWkpQCaCGsFOsap4kxwzcoE/mACCovxuYHdUNMU7SmLcMcVgIugLexc3fdEesrjwiXOv84yUFIoTWXstqxQjoWF2sTAtPhMGBVIhRxl0Pu1uypBsKlmM+TM/hgPpu/YeunQgIBqXRLb3UEcvV/GviS4NohXEJ42lAOkghFRgIGVJ4eZHICB7e6u1smpYWFte2uitLsXt++W+cw1BYvVkGX11kgOvDoxOELZtMheiULaVympSTJln1xLYPlq3RnOxnIUMOXMPYR1Oc7QWzXwSkdCXfjEX3uCbeQXKa+7ejD25erIBjqcAWVQxvQzOp+OSB/RXn4NfFmc39140c506ptNKMVT1mVFKAJPPRwFfqbQTKYp53BCnGJfWfqhvz4UMWpvWF7xMDG35aTW6tbYh1q42Ew4spB7pdKwWmzhYhy+vWFLYVTsrV5WDkF3qzba7uBKRwwGaKsSmzxYEZ4cnKdKcAoIhsruaZB7dt8QR2SxE1k+CzAiYwrA+YoAe8BsSKG6xQ==',
          'Expiration': datetime.datetime(2025, 11, 17, 6, 30, 30, tzinfo=tzutc())
        },
        'aws_account_number': '123456499234'
      },
      ...
    }
    ```

These mappings are built and used in the main workflow to ensure correct certificate-to-account associations and secure uploads.

1. **Fetch Venafi API Key**: Retrieve the API key from AWS Secrets Manager.
2. **Fetch Applications**: Get all AWS applications from Venafi Cloud.
3. **Fetch Certificates**: Get all certificates issued in the last N minutes, or fetch only those specified in the `certificate_ids_to_process` list.
4. **Map Certificates to Applications**: Build a mapping of app IDs to certificates.
5. **Assume Roles**: For each app/account, assume the cross-account role in each region.
6. **Download Certificate Chain**: Use vcert CLI to download the certificate chain and private key.
7. **Upload to Secrets Manager or ACM**:

- If the application name contains `_acm_`, upload the certificate and chain to AWS ACM in the target region/account.
- Otherwise, store the certificate chain and private key in AWS Secrets Manager.

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
  ...existing code...

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
