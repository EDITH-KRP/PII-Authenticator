import os
import json
from dotenv import load_dotenv, set_key
from web3_storage import Web3Storage

# Load API key
load_dotenv()
WEB3_STORAGE_TOKEN = os.getenv("WEB3_STORAGE_TOKEN")
storage = Web3Storage(WEB3_STORAGE_TOKEN)

def update_env_file(key, value):
    env_path = ".env"
    env_data = {}

    # Read existing env file
    if os.path.exists(env_path):
        with open(env_path, "r") as file:
            for line in file.readlines():
                k, v = line.strip().split("=", 1)
                env_data[k] = v

    # Update or add new key-value pair
    env_data[key] = value

    # Write updated data back
    with open(env_path, "w") as file:
        for k, v in env_data.items():
            file.write(f"{k}={v}\n")

def encrypt_and_store_id(id_number):
    # Encrypt ID (your existing encryption code here)
    
    # Upload encrypted file to Filecoin
    file_path = f"encrypted_{id_number}.txt"
    cid = storage.upload(file_path)
    
    # Update Filecoin CID in .env
    update_env_file("FILECOIN_CID", cid)

    return cid
