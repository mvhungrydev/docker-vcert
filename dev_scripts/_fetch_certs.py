import json
import requests
import logging
import datetime
import subprocess
import boto3
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


def fetch_aws_secret(secret_name, region_name="us-east-1"):
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


def fetch_certificates_data(api_base_url, headers, minutes):
    """Fetch all certificates issued in the last 'minutes' minutes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    validityStart = now - datetime.timedelta(minutes=minutes)
    validityStart_ISO = validityStart.strftime("%Y-%m-%dT%H:%M")
    logger.info(f"Fetching certificates with validity start after {validityStart_ISO}")

    all_certificates = []
    page_number = 0
    page_size = 100

    while True:
        payload = {
            "ordering": {"orders": [{"direction": "DESC", "field": "validityStart"}]},
            "paging": {"pageNumber": page_number, "pageSize": page_size},
            "expression": {
                "operator": "AND",
                "operands": [
                    {
                        "field": "validityStart",
                        "operator": "GTE",
                        "value": validityStart_ISO,
                    },
                    {"field": "certificateStatus", "operator": "EQ", "value": "ACTIVE"},
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


def fetch_cert_key_chain(api_token, token_switch, vcert_bin_path, cert_request_id):
    logger.info(f"Fetching cert pem for certificate request ID: {cert_request_id}")
    logger.info(
        f"Returning in the order of leaf_cert, issuing_cert, root_cert, private_key"
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
        return leaf_cert, issuing_cert, root_cert, private_key
    except subprocess.CalledProcessError as e:
        logger.error(f"vcert failed: {e}")
        logger.error(f"stderr: {e.stderr}")
    except Exception as e:
        logger.error(f"Error fetching or parsing cert: {e}")
    return None, None, None, None


def get_cross_account_role_assume_creds(target_role_arn, aws_region):
    try:
        sts = boto3.client("sts", region_name=aws_region)
        now = datetime.datetime.now(datetime.timezone.utc)
        session_name = f"pki_cert_upload_session_{now.strftime('%Y%m%d%H%M%S')}"
        assumed = sts.assume_role(RoleArn=target_role_arn, RoleSessionName=session_name)
        return assumed["Credentials"]
    except Exception as e:
        logger.error(f"Error assuming role {target_role_arn}: {e}")
        return None


# Get api secret from secrets manager
api_secrets = fetch_aws_secret("pki-tppl-api-key", region_name="us-east-1")
if not api_secrets:
    logger.error("Failed to retrieve API secrets. Exiting.")
    exit(1)

# lambda handler would pass these as parameters in production
api_token = api_secrets["tppl-api-key"]
headers = {"tppl-api-key": f"{api_token}", "accept": "application/json"}
api_base_url = "https://api.venafi.cloud"
minutes = 600
vcert_bin_path = "./vcert_mac"  # Update with actual path to vcert binary
token_switch = "-k"
aws_regions = ["us-west-1", "us-east-2"]  # List of AWS regions to use
standard_cross_account_role_name = "CrossAccountSecretsAndACMRole"

# Fetch data and build mappings start here
# fetch certs
certs_list = fetch_certificates_data(api_base_url, headers, minutes)
# Exit if no certificates found
if not certs_list:
    logger.info(
        f"No new certificates found within the last {minutes} minutes. Exiting script."
    )
    exit(1)

# fetch apps
# Build a mapping from app id to app name for fast lookup
app_id_to_name = {
    app["id"]: app["app"] for app in fetch_aws_applications_data(api_base_url, headers)
}
# Collect unique application IDs and their names from fetch cert data
unique_app_ids_from_certs_list = set(
    app_id for cert in certs_list for app_id in cert.get("applicationIds", [])
)
# Build a mapping from app id to app name for fast lookup
unique_apps_with_names = [
    {"appId": app_id, "name": app_id_to_name.get(app_id, "UNKNOWN")}
    for app_id in unique_app_ids_from_certs_list
]

# For each unique app id, find matching certs, extract relevant data such as cert id and request id, serialNumber, subjectCN.
# Build mapping: app_id -> list of certs with relevant data
app_id_to_certs = defaultdict(list)
for cert in certs_list:
    for app_id in cert.get("applicationIds", []):
        app_id_to_certs[app_id].append(
            {
                "cert_id": cert["id"],
                "certificateRequestId": cert["certificateRequestId"],
                "serialNumber": cert.get("serialNumber"),
                "subjectCN": cert.get("subjectCN"),
                "validityStart": cert.get("validityStart"),
                "validityEnd": cert.get("validityEnd"),
            }
        )

# Fetch data and build mappings end here
#
# Obtain assume role credentials for each unique app id, per AWS region.
app_id_to_credentials = {}
for app in unique_apps_with_names:
    try:
        aws_account_number = app["name"].split("_")[2]
    except (IndexError, AttributeError) as e:
        logger.error(
            f"Failed to parse AWS account number from app name '{app['name']}' for app ID {app['appId']}: {e}"
        )
        continue
    logger.info(
        f"Obtaining assume role into AWS Account Number {aws_account_number} for app name: {app['name']} app ID {app['appId']}"
    )
    for aws_region in aws_regions:
        try:
            target_role_arn = f"arn:aws:iam::{aws_account_number}:role/{standard_cross_account_role_name}"
            logger.info(
                f"Using role ARN {target_role_arn} to assume role into target AWS account in region {aws_region}."
            )
            credentials = get_cross_account_role_assume_creds(
                target_role_arn, aws_region
            )
            if credentials:
                if app["appId"] not in app_id_to_credentials:
                    app_id_to_credentials[app["appId"]] = []
                app_id_to_credentials[app["appId"]].append(
                    {
                        "region": aws_region,
                        "credentials": credentials,
                        "aws_account_number": aws_account_number,
                        "app_name": app["name"],
                    }
                )
                logger.info(
                    f"Successfully obtained credentials for app ID {app['appId']} in region {aws_region}."
                )
            else:
                logger.error(
                    f"Failed to obtain credentials for app ID {app['appId']} in region {aws_region}."
                )
        except Exception as e:
            logger.error(
                f"Exception while assuming role for app ID {app['appId']} in region {aws_region}: {e}"
            )
#
# For each unique app id, get certs and credentials, download cert and upload to aws accounts
for unique_app_id in unique_app_ids_from_certs_list:
    unique_app_certs = app_id_to_certs.get(unique_app_id, [])
    # process each cert for this app id
    for cert_in_app in unique_app_certs:
        cert_id = cert_in_app["cert_id"]
        cert_request_id = cert_in_app["certificateRequestId"]
        logger.info(
            f"Processing Certificate Request ID: {cert_request_id} for app ID: {unique_app_id}"
        )
        logger.info(f"Certificate  ID: {cert_id}")
        logger.info(f"With Subject CN: {cert_in_app['subjectCN'][0]}")
        logger.info(f"With Serial Number: {cert_in_app['serialNumber']}")
        logger.info(
            f"Downloading certificate key and chain for certificate request ID {cert_request_id}"
        )
        leaf_cert, issuing_cert, root_cert, private_key = fetch_cert_key_chain(
            api_token, token_switch, vcert_bin_path, cert_request_id
        )

        if not leaf_cert or not issuing_cert or not root_cert:
            logger.error(
                f"Failed to retrieve Leaf, issuing, root certificate for certificate request ID {cert_request_id}. No need to process this cert, skipping."
            )
            continue

        if not private_key:
            logger.warning(
                f"Private key was not present for certificate ID {cert_id}. no need to process this cert, skipping."
            )
            continue

        # Logging cert details to demonstrate retrieval
        logger.info(f"private_key: {private_key}")
        logger.info(f"leaf_cert: {leaf_cert}")
        logger.info(f"issuing_cert: {issuing_cert}")
        logger.info(f"root_cert: {root_cert}")

        unique_app_credentials = app_id_to_credentials.get(unique_app_id, {})
        # for each region/credentials for this app id
        # upload cert to each region
        for app_credential in unique_app_credentials:
            region = app_credential["region"]
            creds = app_credential["credentials"]
            aws_account_number = app_credential["aws_account_number"]
            app_name = app_credential["app_name"]

            sm = boto3.client(
                "secretsmanager",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
            secret_name = f"pki-{cert_in_app['subjectCN'][0]}"
            logger.info(
                f"Creating secret with name: {secret_name} in AWS region: {region}"
            )
            try:
                sm.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(
                        {
                            "private_key": private_key,
                            "leaf_cert": leaf_cert,
                            "issuing_cert": issuing_cert,
                            "root_cert": root_cert,
                        }
                    ),
                )
                logger.info(
                    f"Successfully created secret in account {aws_account_number}"
                )
            except sm.exceptions.ResourceExistsException:
                logger.info(f"Secret {secret_name} already exists, updating...")
                try:
                    sm.update_secret(
                        SecretId=secret_name,
                        SecretString=json.dumps(
                            {
                                "private_key": private_key,
                                "leaf_cert": leaf_cert,
                                "issuing_cert": issuing_cert,
                                "root_cert": root_cert,
                            }
                        ),
                    )
                    logger.info(
                        f"Successfully updated secret in account {aws_account_number} in region {region}"
                    )
                except Exception as e:
                    logger.error(
                        f"Error updating secret {secret_name} in account {aws_account_number} in region {region}: {e}"
                    )
                    continue
            except Exception as e:
                logger.error(
                    f"Error creating secret {secret_name} in account {aws_account_number} in region {region}: {e}"
                )
                continue

        # Here you would add the code to upload the cert to the specified AWS account
        # ...existing code...


# Process each certificate
# download certs
# upload to aws accounts
## OLD CODE FROM HERE

# %%
