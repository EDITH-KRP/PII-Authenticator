import os
import requests
import logging

# ✅ Use the new Web3.Storage REST API
WEB3_STORAGE_API_KEY = os.getenv("WEB3_STORAGE_TOKEN")  # Ensure this is set

def upload_to_filecoin(file_name, data):
    """Upload data to Web3.Storage and return CID using the new REST API."""
    if not WEB3_STORAGE_API_KEY:
        raise EnvironmentError(
            "WEB3_STORAGE_TOKEN environment variable is not set. "
            "Please set it in your .env file or environment variables. "
            "See .env.example for reference."
        )
        
    url = "https://api.web3.storage/upload"
    headers = {
        "Authorization": f"Bearer {WEB3_STORAGE_API_KEY}",
        "Content-Type": "application/octet-stream"
    }
    
    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200 or response.status_code == 201:
        return response.json()["cid"]
    else:
        raise Exception(f"❌ Failed to upload to Web3.Storage: {response.text}")
