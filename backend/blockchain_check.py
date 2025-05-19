import os
import json
import time
from web3 import Web3
from dotenv import load_dotenv
from w3_utils import check_blockchain_connection

# Load environment variables
load_dotenv()

# Run the check
print("Checking blockchain connection...")
result = check_blockchain_connection()
print(json.dumps(result, indent=2))

# Print environment variables (redacted for security)
print("\nEnvironment variables:")
alchemy_key = os.getenv('ALCHEMY_API_KEY', '')
if alchemy_key:
    masked_key = alchemy_key[:4] + '*' * (len(alchemy_key) - 8) + alchemy_key[-4:]
    print(f"ALCHEMY_API_KEY: {masked_key}")
else:
    print("ALCHEMY_API_KEY: Not set")

contract_address = os.getenv('CONTRACT_ADDRESS', '')
if contract_address:
    print(f"CONTRACT_ADDRESS: {contract_address}")
else:
    print("CONTRACT_ADDRESS: Not set")

# Check if we're in development mode
dev_mode = os.getenv('BLOCKCHAIN_DEV_MODE', 'false').lower() == 'true'
print(f"BLOCKCHAIN_DEV_MODE: {dev_mode}")