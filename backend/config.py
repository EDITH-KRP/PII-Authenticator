import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Configure Logging
LOG_FILE = "retrieval_logs.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Load environment variables for storage and keys
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ENCRYPTED_AES_KEY = os.getenv("ENCRYPTED_AES_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
WEB3_STORAGE_TOKEN = os.getenv("WEB3_STORAGE_TOKEN")
FILECOIN_CID = os.getenv("FILECOIN_CID")

# Optionally, print environment variables for debugging (avoid in production)
print("INFURA_PROJECT_ID:", INFURA_PROJECT_ID)
print("PRIVATE_KEY:", PRIVATE_KEY)
print("CONTRACT_ADDRESS:", CONTRACT_ADDRESS)
print("ENCRYPTED_AES_KEY:", ENCRYPTED_AES_KEY)
