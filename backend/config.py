import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Logging
LOG_FILE = "retrieval_logs.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Load environment variables for storage and keys
WEB3_STORAGE_TOKEN = os.getenv("WEB3_STORAGE_TOKEN")
FILECOIN_CID = os.getenv("FILECOIN_CID")
JWT_SECRET = os.getenv("JWT_SECRET", "your_default_secret_key_here")

# Optionally, you can print the environment variables for debugging
print("Web3 Storage Token:", WEB3_STORAGE_TOKEN)
print("Filecoin CID:", FILECOIN_CID)
