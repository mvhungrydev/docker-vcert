import json
import boto3
from botocore.exceptions import ClientError


def get_secret(secret_name, region_name="us-east-1"):
    """
    Function to pull a secret from AWS Secrets Manager.
    This is a copy of the function from standalone.py for testing purposes.
    """
    # Create a Secrets Manager client
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
    print(f"Secret type: {type(secret)}")
    print(f"Secret length: {len(secret) if secret else 0}")
    
    # Check if secret is empty or None
    if not secret:
        raise ValueError("Secret is empty or None - "
                         "no value found in Secrets Manager")
    
    # Check if it looks like JSON (starts with { or [)
    secret_stripped = secret.strip()
    if secret_stripped.startswith(('{', '[')):
        print("Secret appears to be JSON format")
        try:
            return json.loads(secret)
        except json.JSONDecodeError:
            # JSON parsing failed, just return as string
            return secret
    else:
        print("Secret appears to be plain text")
        return secret


if __name__ == "__main__":
    # Test the function with a sample secret name
    try:
        result = get_secret("sample/secret")
        print("Success! Retrieved secret:", result)
    except ValueError as e:
        print(f"Secret value error: {e}")
    except ClientError as e:
        print(f"AWS error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        print("This might be due to missing AWS credentials or other issues")