import subprocess
import requests
import logging
import boto3
from botocore.exceptions import ClientError
import json
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

def handler(event, context):
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # call venafi api to get all certs
    # loop each cert and call vcert to download each key
    # there should be some logic to determine where the certs will go
    # consider checking application name or tag to determine which certs to download
    # upload a cert to ACM
    # create a secret in secrets manager on another account

    logging.info("Lambda function has started")
    logging.info("hello world")
    # Function to pull a secret from AWS Secrets Manager.
    def get_secret(secret_name, region_name="us-east-1"):
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            raise e
        secret = get_secret_value_response['SecretString']
        logging.info(f"Secret type: {type(secret)}")
        logging.info(f"Secret length: {len(secret) if secret else 0}")

        # Check if secret is empty or None
        if not secret:
            raise ValueError("Secret is empty or None - "
                             "no value found in Secrets Manager")

        # Check if it looks like JSON (starts with { or [)
        secret_stripped = secret.strip()
        if secret_stripped.startswith(('{', '[')):
            logging.info("Secret appears to be JSON format")
            try:
                return json.loads(secret)
            except json.JSONDecodeError:
                # JSON parsing failed, just return as string
                return secret
        else:
            logging.info("Secret appears to be plain text")
            return secret
    
    # Function to put a secret into AWS Secrets Manager
    def put_secret(secret_name, key, value, region_name="us-east-1"):
        session = boto3.session.Session()
        client = session.client("secretsmanager", region_name=region_name)
        secret_dict = {key: value}
        secret_string = json.dumps(secret_dict)
        try:
            newSecret = client.put_secret_value(SecretId=secret_name, SecretString=secret_string)
        except client.exceptions.ResourceNotFoundException:
            newSecret = client.create_secret(Name=secret_name, SecretString=secret_string)
        except Exception as e:
            raise e
        print("Secret created/updated in Secrets Manager:", newSecret)
        return newSecret

    # Function to import a certificate into AWS ACM
    def import_cert_to_acm(cert_pem, key_pem, region_name="us-east-1"):
        session = boto3.session.Session()
        client = session.client("acm", region_name=region_name)
        try:
            response = client.import_certificate(
                Certificate=cert_pem.encode(),
                PrivateKey=key_pem.encode()
            )
        except ClientError as e:
            raise e
        print("Certificate imported in ACM:", response)
        return response["CertificateArn"]
    
    # TO BE REMOVED LATER
    # Function to generate a self-signed certificate
    def generate_self_signed_cert(common_name="example.com"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
            .public_key(key.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.datetime.utcnow())\
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
            .sign(key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return cert_pem.decode(), key_pem.decode()
    # TO BE REMOVED LATER
    # generate a self-signed cert and import it into ACM for testing purposes
    cert_pem, key_pem = generate_self_signed_cert(common_name=f"{str(int(time.time()))}mydomain.com")
    cert_arn = import_cert_to_acm(cert_pem, key_pem, region_name="us-east-1")
    # generate a self-signed cert and import it into secrets manager for testing purposes
    put_secret("lle/_mydomain.com_cert", "pub_cert", cert_pem, "us-east-1")
    put_secret("lle/_mydomain.com_key", "key", key_pem, "us-east-1")
    #

    try:
        # Run the vcert binary with --version
        result = subprocess.run(
            ["/usr/local/bin/vcert", "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        print("vcert command executed:", result.stdout.strip())

        # Sample GET request to a public API
        api_response = requests.get("https://api.github.com/")
        api_body = api_response.text
        print("API response received:", api_body[:100])  # Print first 100 characters of the response

        response = {
            "statusCode": 200,
            "body": {
                "secret_data": get_secret("pki-tppl-api-key","us-east-1"),
            }
        }
        return response
    except subprocess.CalledProcessError as e:
        return {
            "statusCode": 500,
            "error": e.stderr.strip()
        }
