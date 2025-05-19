import os
import time
from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key
ALCHEMY_API_KEY = os.getenv('ALCHEMY_API_KEY')
SEPOLIA_RPC_URL = os.getenv('SEPOLIA_RPC_URL', f"https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}")

print(f"Using Sepolia RPC URL: {SEPOLIA_RPC_URL}")

# Try to connect
try:
    print("Connecting to Ethereum network...")
    start_time = time.time()
    
    web3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
    
    if web3.is_connected():
        elapsed_time = time.time() - start_time
        print(f"SUCCESS: Connected to Ethereum network in {elapsed_time:.4f} seconds")
        print(f"Latest block number: {web3.eth.block_number}")
    else:
        print("ERROR: Could not connect to Ethereum network")
        
except Exception as e:
    print(f"ERROR: {str(e)}")
    import traceback
    traceback.print_exc()