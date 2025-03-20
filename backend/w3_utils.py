import boto3
import os

FILEBASE_ACCESS_KEY = os.getenv("FILEBASE_ACCESS_KEY")
FILEBASE_SECRET_KEY = os.getenv("FILEBASE_SECRET_KEY")
BUCKET_NAME = "pii-authenticator-test"
ENDPOINT_URL = "https://s3.filebase.com"

# Initialize Filebase S3 client
s3 = boto3.client(
    "s3",
    aws_access_key_id=FILEBASE_ACCESS_KEY,
    aws_secret_access_key=FILEBASE_SECRET_KEY,
    endpoint_url=ENDPOINT_URL,
)

def upload_to_filebase(file_name, file_data):
    """Uploads encrypted data to Filebase and returns the file URL."""
    try:
        s3.put_object(Bucket=BUCKET_NAME, Key=file_name, Body=file_data)
        file_url = f"{ENDPOINT_URL}/{BUCKET_NAME}/{file_name}"
        return file_url
    except Exception as e:
        print(f"❌ File upload failed: {e}")
        return None


def retrieve_from_filebase(file_name):
    """Retrieves a file from Filebase."""
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=file_name)
        file_data = response["Body"].read()
        return file_data
    except Exception as e:
        print(f"❌ File retrieval failed: {e}")
        return None