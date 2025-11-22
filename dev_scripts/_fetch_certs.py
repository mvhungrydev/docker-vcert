import json
import requests
import logging
import datetime
import subprocess
import boto3
import re
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


def sanitize_secret_name(text: str, max_len: int = 240) -> str:
    if not isinstance(text, str):
        text = str(text)

    # Common normalization
    sanitized = text.strip()
    sanitized = sanitized.replace("*", "")

    # Convert whitespace to '-'
    sanitized = re.sub(r"\s+", "-", sanitized)

    # Convert / to '-'
    sanitized = sanitized.replace("/", "-")

    # Replace disallowed chars with ''
    sanitized = re.sub(r"[^A-Za-z0-9_+=.@-]", "", sanitized)

    # Collapse multiple '-' into one
    sanitized = re.sub(r"-{2,}", "-", sanitized)

    # Trim to a conservative length (Secrets Manager allows up to 512)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len]

    return sanitized or "UNKNOWN_CN"


def fetch_aws_secret(secret_name, region_name="us-east-2"):
    logger.info(
        f"Fetching secret '{secret_name}' from AWS Secrets Manager in region '{region_name}'"
    )
    try:
        client = boto3.client("secretsmanager", region_name=region_name)
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret_string = get_secret_value_response.get("SecretString")
        if not secret_string:
            logger.error(f"Secret '{secret_name}' has no SecretString value.")
            return None
        try:
            secret_dict = json.loads(secret_string)
            logger.info(
                f"Successfully fetched and parsed secret '{secret_name}'. Keys: {list(secret_dict.keys())}"
            )
            return secret_dict
        except json.JSONDecodeError as e:
            logger.error(f"Secret '{secret_name}' is not valid JSON: {e}")
            return None
    except client.exceptions.ResourceNotFoundException:
        logger.error(f"Secret '{secret_name}' not found in region '{region_name}'.")
    except client.exceptions.DecryptionFailure:
        logger.error(f"Decryption failure for secret '{secret_name}'.")
    except client.exceptions.InvalidRequestException as e:
        logger.error(f"Invalid request for secret '{secret_name}': {e}")
    except client.exceptions.InvalidParameterException as e:
        logger.error(f"Invalid parameter for secret '{secret_name}': {e}")
    except Exception as e:
        logger.error(f"Unexpected error fetching secret '{secret_name}': {e}")
    return None


def fetch_aws_applications_data(api_base_url, headers):
    """Fetch all applications and filter those starting with 'aws_'"""
    try:
        app_url = f"{api_base_url}/outagedetection/v1/applications"
        logger.info(f"Requesting applications from {app_url}")
        response = requests.get(app_url, headers=headers)
        response.raise_for_status()
        applications = response.json().get("applications", [])
        logger.info(f"Fetched {len(applications)} applications from API.")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch applications: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error fetching applications: {e}")
        return []

    app_name_id_list = [
        {"app": app["name"], "id": app["id"]}
        for app in applications
        if app["name"].startswith("aws_")
    ]
    logger.info(f"Found {len(app_name_id_list)} applications starting with 'aws_'")
    return app_name_id_list


def fetch_cert_key_chain(api_token, token_switch, vcert_bin_path, cert_request_id):
    logger.info(f"Fetching cert pem for certificate request ID: {cert_request_id}")
    logger.info(
        f"Returning in the order of leaf_cert, issuing_cert, root_cert, private_key, pem"
    )
    try:
        fetch_cert_chain = subprocess.run(
            [
                vcert_bin_path,
                "pickup",
                "-p",
                "vcp",
                token_switch,
                api_token,
                "--pickup-id",
                cert_request_id,
                "--format",
                "json",
                "--no-prompt",
                "--timeout",
                "60",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        json_data = json.loads(fetch_cert_chain.stdout)
        private_key = json_data["PrivateKey"]
        leaf_cert = json_data["Certificate"]
        root_cert = json_data["Chain"][-1]
        issuing_cert = json_data["Chain"][0]
        pem_data = leaf_cert + issuing_cert + root_cert + private_key
        return {
            "leaf_cert": leaf_cert,
            "issuing_cert": issuing_cert,
            "root_cert": root_cert,
            "private_key": private_key,
            "pem": pem_data,
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"vcert failed: {e}")
        logger.error(f"stderr: {e.stderr}")
    except Exception as e:
        logger.error(f"Error fetching or parsing cert: {e}")
    return None


def get_cross_account_role_assume_creds(target_role_arn):
    try:
        sts = boto3.client("sts")
        now = datetime.datetime.now(datetime.timezone.utc)
        session_name = f"pki_cert_upload_session_{now.strftime('%Y%m%d%H%M%S')}"
        assumed = sts.assume_role(RoleArn=target_role_arn, RoleSessionName=session_name)
        return assumed["Credentials"]
    except Exception as e:
        logger.error(f"Error assuming role {target_role_arn}: {e}")
        return None


def create_update_cert_secret(
    creds,
    secret_name,
    region,
    aws_account_number,
    cert_data,
):
    sm = boto3.client(
        "secretsmanager",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    logger.info(
        f"Attempting to create a secret with name: {secret_name} in AWS region: {region} under account {aws_account_number}"
    )
    try:
        secret_payload = {
            "private_key": cert_data.get("private_key"),
            "leaf_cert": cert_data.get("leaf_cert"),
            "issuing_cert": cert_data.get("issuing_cert"),
            "root_cert": cert_data.get("root_cert"),
            "pem": cert_data.get("pem"),
        }
    except Exception as e:
        logger.error(
            f"Error preparing secret payload for secret {secret_name} in AWS region {region} under account {aws_account_number}: {e}"
        )
        return
    try:
        sm.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_payload),
        )
        logger.info(
            f"Successfully created secret {secret_name} in AWS region {region} under account {aws_account_number}"
        )
    except sm.exceptions.ResourceExistsException:
        logger.info(
            f"Secret {secret_name} in AWS region {region} under account {aws_account_number}already exists, updating..."
        )
        try:
            sm.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_payload),
            )
            logger.info(
                f"Successfully updated secret {secret_name} in AWS region {region} under account {aws_account_number}"
            )
        except Exception as e:
            logger.error(
                f"Error updating secret {secret_name} in AWS region {region} under account {aws_account_number}: {e}"
            )
    except Exception as e:
        logger.error(
            f"Error creating secret {secret_name} in AWS region {region} under account {aws_account_number}: {e}"
        )


def import_cert_to_acm(
    creds,
    region,
    aws_account_number,
    cert_data,
    subject_cn,
):
    acm = boto3.client(
        "acm",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    logger.info(
        f"Attempting to import certificate with Subject CN: {subject_cn} into ACM in AWS region: {region} under account {aws_account_number}"
    )
    leaf_cert = cert_data.get("leaf_cert")
    private_key = cert_data.get("private_key").replace(" RSA", "")
    issuing_cert = cert_data.get("issuing_cert")
    root_cert = cert_data.get("root_cert")
    # Combine certificate chain
    certificate_chain = issuing_cert + root_cert
    try:
        # Import to ACM - use the binary data read from files
        response = acm.import_certificate(
            Certificate=leaf_cert,
            PrivateKey=private_key,
            CertificateChain=certificate_chain,
        )
        certificate_arn = response.get("CertificateArn")
        logger.info(
            f"Successfully imported certificate with Subject CN: {subject_cn} into ACM in AWS region: {region} under account {aws_account_number}. Certificate ARN: {certificate_arn}"
        )
        return response
    except Exception as e:
        logger.error(
            f"Error importing certificate with Subject CN: {subject_cn} into ACM in AWS region: {region} under account {aws_account_number}: {e}"
        )
        return None


def fetch_certificates_data(
    api_base_url, headers, minutes=15, certificate_ids_to_process=None
):
    """Fetch all certificates issued in the last 'minutes' minutes or specific IDs."""
    all_certificates = []
    if certificate_ids_to_process is not None:
        # Process only those IDs
        logger.info(
            f"Processing only provided certificateIds: {certificate_ids_to_process}"
        )
        for cert_id in certificate_ids_to_process:
            url = f"{api_base_url}/outagedetection/v1/certificates/{cert_id}?ownershipTree=false&excludeSupersededInstances=false"
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                cert_data = response.json()
                all_certificates.append(cert_data)
            except requests.RequestException as e:
                logger.error(f"Failed to fetch certificate ID {cert_id}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching certificate ID {cert_id}: {e}")
        return all_certificates
    else:
        # Process all certs
        now = datetime.datetime.now(datetime.timezone.utc)
        validityStart = now - datetime.timedelta(minutes=minutes)
        validityStart_ISO = validityStart.strftime("%Y-%m-%dT%H:%M")
        logger.info(
            f"Fetching certificates with validity start after {validityStart_ISO}"
        )
        page_number = 0
        page_size = 100
        while True:
            payload = {
                "ordering": {
                    "orders": [{"direction": "DESC", "field": "validityStart"}]
                },
                "paging": {"pageNumber": page_number, "pageSize": page_size},
                "expression": {
                    "operator": "AND",
                    "operands": [
                        {
                            "field": "validityStart",
                            "operator": "GTE",
                            "value": validityStart_ISO,
                        },
                        {
                            "field": "certificateStatus",
                            "operator": "EQ",
                            "value": "ACTIVE",
                        },
                        {"field": "versionType", "operator": "EQ", "value": "CURRENT"},
                    ],
                },
            }

            search_url = f"{api_base_url}/outagedetection/v1/certificatesearch?ownershipTree=false&excludeSupersededInstances=true"
            logger.info(
                f"Retrieving certificate data.. page: {page_number} size: {page_size} from {search_url} with payload: {payload}"
            )
            try:
                response = requests.post(search_url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                certificates = data.get("certificates", [])
                all_certificates.extend(certificates)
                paging = data.get("paging", {})
                total_pages = paging.get("totalPages")
                if total_pages is not None and page_number + 1 >= total_pages:
                    break
                if not certificates:
                    break
                page_number += 1
            except requests.RequestException as e:
                logger.error(f"Failed to fetch certificates: {e}")
                return all_certificates
            except Exception as e:
                logger.error(f"Unexpected error fetching certificates: {e}")
                return all_certificates

        logger.info(
            f"Data retrieved for {len(all_certificates)} certificates from API (page {page_number})."
        )
        return all_certificates


# Get api secret from secrets manager
api_secrets = fetch_aws_secret("pki-tppl-api-key", region_name="us-east-1")
if not api_secrets:
    logger.error("Failed to retrieve API secrets. Exiting.")
    exit(1)

# lambda handler would pass these as parameters in production
api_token = api_secrets["tppl-api-key"]
headers = {"tppl-api-key": f"{api_token}", "accept": "application/json"}
api_base_url = "https://api.venafi.cloud"
minutes = 1440  # last 24 hours
vcert_bin_path = "./vcert_mac"  # Update with actual path to vcert binary
token_switch = "-k"
aws_regions = ["us-west-1", "us-east-2"]  # List of AWS regions to use
standard_cross_account_role_name = "CrossAccountSecretsAndACMRole"
# certificate_ids_to_process = [
#    "280b8710-be84-11f0-8a92-1152c3883671",
#    "20868760-bdd0-11f0-afd7-b326dadc92bf",
# ]
certificate_ids_to_process = []  # Empty list means process all
# If certificate_ids_to_process is populated, filter certs_list
if certificate_ids_to_process:
    logger.info(f"Processing specific certificate IDs: {certificate_ids_to_process}")
    certs_list = fetch_certificates_data(
        api_base_url, headers, minutes, certificate_ids_to_process
    )
else:
    logger.info("Processing all certificates.")
    certs_list = fetch_certificates_data(api_base_url, headers, minutes)


# Fetch data and build mappings start here
# Fetch certs
# Exit if no certificates found
if not certs_list:
    logger.info(
        f"No new certificates found within the last {minutes} minutes. Exiting script."
    )
    exit(1)

# Fetch apps
logger.info("Fetching AWS applications data...")
app_id_to_app_name = {
    app["id"]: app["app"] for app in fetch_aws_applications_data(api_base_url, headers)
}


# Collect unique application IDs and their names from fetch cert data
logger.info("Collecting unique application IDs from certificates data...")
unique_app_ids_from_certs_list = set(
    app_id for cert in certs_list for app_id in cert.get("applicationIds", [])
)
# This line filters out any app IDs not present in app_id_to_app_name
unique_app_ids_from_certs_list = {
    app_id for app_id in unique_app_ids_from_certs_list if app_id in app_id_to_app_name
}
logger.info(
    f"Collected {len(unique_app_ids_from_certs_list)} unique application IDs from certificates data: {unique_app_ids_from_certs_list}"
)
# For each unique app id, find matching certs, extract relevant data such as cert id and request id, serialNumber, subjectCN.
# Build mapping: app_id -> list of certs with relevant data
logger.info("Building application ID to certificates mapping...")
app_id_to_certs = defaultdict(list)
for cert in certs_list:
    for app_id in cert.get("applicationIds", []):
        app_id_to_certs[app_id].append(
            {
                "id": cert["id"],
                "certificateRequestId": cert["certificateRequestId"],
                "serialNumber": cert.get("serialNumber"),
                "subjectCN": cert.get("subjectCN"),
                "validityStart": cert.get("validityStart"),
                "validityEnd": cert.get("validityEnd"),
                "app_name": app_id_to_app_name.get(app_id, "UNKNOWN"),
            }
        )
logger.info(
    f"Built mapping for {len(app_id_to_certs)} application IDs. {list(app_id_to_certs.keys())}"
)
for app_id, certs in app_id_to_certs.items():
    count = len(certs)
    logger.info(f"App ID: {app_id} has {count} certificates")
# Build mapping: aws_account_number -> list of app ids, app names
logger.info(f"Building aws account number to app ids mapping...")
aws_account_number_to_app_ids = {}
for app_id in unique_app_ids_from_certs_list:
    app_name = app_id_to_app_name.get(app_id, "UNKNOWN")

    try:
        aws_account_number = app_name.split("_")[2]
        if aws_account_number not in aws_account_number_to_app_ids:
            aws_account_number_to_app_ids[aws_account_number] = []
        aws_account_number_to_app_ids[aws_account_number].append(
            {
                "app_name": app_name,
                "app_id": app_id,
            }
        )
    except (IndexError, AttributeError) as e:
        logger.error(
            f"Failed to parse AWS account number from app name '{app_name}' for app ID {app_id}: {e}"
        )
        continue
logger.info(
    f"Collected {len(aws_account_number_to_app_ids)} AWS account numbers: {list(aws_account_number_to_app_ids.keys())}"
)

# Obtain assume role credentials for each unique app id, per AWS region.
logger.info("Obtaining cross-account role assume credentials...")
aws_account_number_to_credentials = {}
for aws_account_number in aws_account_number_to_app_ids:
    try:
        target_role_arn = (
            f"arn:aws:iam::{aws_account_number}:role/{standard_cross_account_role_name}"
        )
        logger.info(
            f"Using role ARN {target_role_arn} to assume role into target AWS account."
        )
        credentials = get_cross_account_role_assume_creds(target_role_arn)
        if credentials:
            if aws_account_number in aws_account_number_to_credentials:
                continue
            aws_account_number_to_credentials[aws_account_number] = {
                "credentials": credentials,
                "aws_account_number": aws_account_number,
            }
            logger.info(
                f"Successfully obtained credentials for AWS Account {aws_account_number}."
            )
        else:
            logger.error(
                f"Failed to obtain credentials for AWS Account {aws_account_number}."
            )
    except Exception as e:
        logger.error(
            f"Exception while assuming role for AWS Account {aws_account_number}: {e}"
        )
logger.info(
    f"Obtained a total of {len(aws_account_number_to_credentials)} AWS account credentials for AWS accounts: {list(aws_account_number_to_credentials.keys())}."
)
# log AWS account numbers that we have obtained credentials for and their expiry
if not aws_account_number_to_credentials:
    logger.error("No AWS account credentials obtained. Exiting.")
    exit(1)

logger.info("Data mappings/fetching complete.")
#
# For each unique app id, get certs and credentials, download cert and upload to aws accounts
logger.info("Begin cert download and upload process...")
for unique_app_id in unique_app_ids_from_certs_list:
    account_number = None
    account_number = next(
        (
            acct
            for acct, apps in aws_account_number_to_app_ids.items()
            if any(a.get("app_id") == unique_app_id for a in apps)
        ),
        None,
    )
    logger.info(
        f"Processing certs under app ID: {unique_app_id} for AWS account number: {account_number}"
    )
    # Get credentials for this app id
    logger.info(
        f"Fetch credentials for AWS account number: {account_number} from mapping"
    )
    creds_obj = aws_account_number_to_credentials.get(account_number, {})
    if not creds_obj:
        logger.error(
            f"No AWS credentials were found for AWS account number {account_number} needed to process certs under the app ID {unique_app_id}. Skipping cert upload for certs under this app ID."
        )
        continue
    creds = creds_obj["credentials"]
    certs_in_app_ids = app_id_to_certs.get(unique_app_id, [])
    logger.info(
        f"Found {len(certs_in_app_ids)} certificates to process for app ID: {unique_app_id}"
    )
    # process each cert for this app id
    for cert_in_app in certs_in_app_ids:
        id = cert_in_app["id"]
        cert_request_id = cert_in_app["certificateRequestId"]
        logger.info(
            f"Processing Certificate Request ID: {cert_request_id} for app ID: {unique_app_id}"
        )
        logger.info(f"Certificate  ID: {id}")
        logger.info(f"With Subject CN: {cert_in_app['subjectCN'][0]}")
        logger.info(f"With Serial Number: {cert_in_app['serialNumber']}")
        logger.info(
            f"With Validity: {cert_in_app['validityStart']} - {cert_in_app['validityEnd']}"
        )
        logger.info(
            f"Downloading certificate key and chain for certificate request ID {cert_request_id}"
        )
        cert_data = fetch_cert_key_chain(
            api_token, token_switch, vcert_bin_path, cert_request_id
        )
        try:
            if (
                not cert_data.get("leaf_cert")
                or not cert_data.get("issuing_cert")
                or not cert_data.get("root_cert")
            ):
                logger.error(
                    f"Failed to retrieve Leaf or issuing or root certificate for certificate request ID: {cert_request_id}, certificate ID:{id} SubjectName: {cert_in_app['subjectCN'][0]}. No need to process this cert, skipping."
                )
                continue
            if not cert_data.get("private_key"):
                logger.error(
                    f"Private key was not present for certificate request ID {cert_request_id}, certificate ID:{id} SubjectName: {cert_in_app['subjectCN'][0]}. no need to process this cert, skipping."
                )
                continue
        except Exception as e:
            logger.error(
                f"Exception while processing certificate data for certificate request ID {cert_request_id}: {e}"
            )
            continue

        # for each region/credentials for this app id
        # upload cert to each region
        for region in aws_regions:
            if "_acm_" in cert_in_app["app_name"].lower():
                logger.info(
                    f"Proceeding to upload to ACM in region {region} under account {account_number}. app name {cert_in_app['app_name']}  (app name contains _acm_)"
                )
                import_cert_to_acm(
                    creds,
                    region,
                    account_number,
                    cert_data,
                    cert_in_app["subjectCN"][0],
                )
            else:
                logger.info(
                    f"Proceeding to upload to Secrets Manager in region {region} under account {account_number}. app name {cert_in_app['app_name']}"
                )
                try:
                    secret_name = (
                        f"pki-{sanitize_secret_name(cert_in_app['subjectCN'][0])}"
                    )
                except Exception as e:
                    logger.error(
                        f"Error sanitizing secret name for certificate request ID {cert_request_id}: {e}"
                    )
                    logger.error("attempting to use CN as secret name")
                    secret_name = f"pki-{cert_in_app['subjectCN'][0]}"
                create_update_cert_secret(
                    creds,
                    secret_name,
                    region,
                    account_number,
                    cert_data,
                )


# %%
print("Script execution complete.")
# %%
