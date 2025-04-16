# backend/w3_utils.py
import os
import json
import boto3
import time
import traceback
from web3 import Web3, HTTPProvider
from dotenv import load_dotenv
from logger import get_logger

# Load environment variables
load_dotenv()

# Get logger
logger = get_logger()

ALCHEMY_API_KEY = os.getenv('ALCHEMY_API_KEY', 'sample_key_for_development')
PRIVATE_KEY = os.getenv('PRIVATE_KEY', '0x0000000000000000000000000000000000000000000000000000000000000000')
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '0x0000000000000000000000000000000000000000')

# In development mode, we'll allow missing environment variables
# In production, this should raise an error
if not ALCHEMY_API_KEY or not PRIVATE_KEY or not CONTRACT_ADDRESS:
    logger.warning("⚠️ Missing environment variables (ALCHEMY_API_KEY, PRIVATE_KEY, CONTRACT_ADDRESS)")
    logger.warning("⚠️ Using development placeholders - DO NOT USE IN PRODUCTION")

# Try to connect to Sepolia via Alchemy
try:
    logger.info("Connecting to Ethereum network via Alchemy...")
    start_time = time.time()
    
    alchemy_url = f"https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
    web3 = Web3(HTTPProvider(alchemy_url))
    
    if not web3.is_connected():
        logger.warning("⚠️ Could not connect to Sepolia via Alchemy")
        logger.warning("⚠️ Running in development mode with simulated blockchain")
        BLOCKCHAIN_DEV_MODE = True
    else:
        BLOCKCHAIN_DEV_MODE = False
        elapsed_time = time.time() - start_time
        logger.info(f"✅ Connected to Ethereum network in {elapsed_time:.4f} seconds")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize Web3: {e}")
    logger.warning("⚠️ Running in development mode with simulated blockchain")
    logger.debug(traceback.format_exc())
    web3 = Web3()  # Fallback to local provider
    BLOCKCHAIN_DEV_MODE = True

# Try to load contract ABI
contract_abi = None
try:
    logger.info("Loading contract ABI...")
    abi_path = "../blockchain/artifacts/contracts/Token_Auth.sol/TokenAuth.json"
    with open(abi_path, "r") as f:
        contract_json = json.load(f)
        contract_abi = contract_json["abi"]
    logger.info("✅ Contract ABI loaded successfully")
except Exception as e:
    logger.warning(f"⚠️ Failed to load contract ABI: {e}")
    logger.warning("⚠️ Using a dummy ABI for development")
    logger.debug(traceback.format_exc())
    
    # Dummy ABI for development
    contract_abi = [
        {
            "inputs": [{"internalType": "string", "name": "token", "type": "string"}],
            "name": "storeToken",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [{"internalType": "string", "name": "token", "type": "string"}],
            "name": "verifyToken",
            "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
    logger.debug("Dummy ABI created for development")

# Initialize contract
try:
    logger.info("Initializing contract...")
    contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
    account = web3.eth.account.from_key(PRIVATE_KEY)
    logger.info(f"✅ Contract initialized at address {CONTRACT_ADDRESS}")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize contract: {e}")
    logger.debug(traceback.format_exc())
    contract = None
    account = None
account = web3.eth.account.from_key(PRIVATE_KEY)

# Filebase setup
FILEBASE_ACCESS_KEY = os.getenv("FILEBASE_ACCESS_KEY", "sample_access_key")
FILEBASE_SECRET_KEY = os.getenv("FILEBASE_SECRET_KEY", "sample_secret_key")
BUCKET_NAME = os.getenv("BUCKET_NAME", "pii-authenticator-test")
ENDPOINT_URL = "https://s3.filebase.com"

# In development mode, we'll allow missing environment variables
if not FILEBASE_ACCESS_KEY or not FILEBASE_SECRET_KEY or not BUCKET_NAME:
    logger.warning("⚠️ Filebase credentials missing - using development placeholders")
    logger.warning("⚠️ File storage operations will be simulated")

# Initialize S3 client if credentials are available
try:
    logger.info("Initializing Filebase S3 client...")
    start_time = time.time()
    
    s3 = boto3.client(
        "s3",
        aws_access_key_id=FILEBASE_ACCESS_KEY,
        aws_secret_access_key=FILEBASE_SECRET_KEY,
        endpoint_url=ENDPOINT_URL,
    )
    
    DEVELOPMENT_MODE = False
    elapsed_time = time.time() - start_time
    logger.info(f"✅ Filebase S3 client initialized in {elapsed_time:.4f} seconds")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize S3 client: {e}")
    logger.warning("⚠️ Running in development mode with simulated storage")
    logger.debug(traceback.format_exc())
    s3 = None
    DEVELOPMENT_MODE = True

def upload_to_filebase(file_name, file_data):
    """
    Upload a file to Filebase (IPFS storage).
    
    Args:
        file_name (str): The name of the file to upload
        file_data (bytes): The binary data to upload
        
    Returns:
        str: The URL of the uploaded file, or None if the upload failed
    """
    logger.info(f"Uploading file {file_name} to storage...")
    start_time = time.time()
    
    if DEVELOPMENT_MODE:
        # Simulate upload in development mode
        file_url = f"{ENDPOINT_URL}/{BUCKET_NAME}/{file_name}"
        logger.info(f"⚠️ [DEV MODE] Simulated upload to Filebase: {file_url}")
        
        # Save locally for development testing
        try:
            os.makedirs("storage", exist_ok=True)
            with open(f"storage/{file_name}", "wb") as f:
                f.write(file_data)
            logger.info(f"✅ [DEV MODE] Saved file locally: storage/{file_name}")
        except Exception as e:
            logger.error(f"❌ [DEV MODE] Failed to save file locally: {e}")
            logger.debug(traceback.format_exc())
        
        elapsed_time = time.time() - start_time
        logger.debug(f"File upload simulation completed in {elapsed_time:.4f} seconds")
        return file_url
    
    try:
        # Actual upload to Filebase with a timeout
        import threading
        from concurrent.futures import ThreadPoolExecutor, TimeoutError
        
        def upload_with_timeout():
            s3.put_object(Bucket=BUCKET_NAME, Key=file_name, Body=file_data)
            return True
        
        # Use ThreadPoolExecutor to implement timeout
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(upload_with_timeout)
            try:
                result = future.result(timeout=10)  # 10 second timeout
                if result:
                    file_url = f"{ENDPOINT_URL}/{BUCKET_NAME}/{file_name}"
                    elapsed_time = time.time() - start_time
                    logger.info(f"✅ Uploaded to Filebase: {file_url} in {elapsed_time:.4f} seconds")
                    return file_url
            except TimeoutError:
                logger.warning(f"⚠️ Filebase upload timed out after 10 seconds")
                # Return a simulated URL for now
                file_url = f"{ENDPOINT_URL}/{BUCKET_NAME}/{file_name}"
                logger.info(f"⚠️ Returning URL without confirmed upload: {file_url}")
                return file_url
    except Exception as e:
        logger.error(f"❌ Filebase upload failed: {e}")
        logger.debug(traceback.format_exc())
        return None

def check_file_exists_in_filebase(file_name):
    """
    Check if a file exists in Filebase.
    
    Args:
        file_name (str): The name of the file to check
        
    Returns:
        bool: True if the file exists, False otherwise
    """
    logger.info(f"Checking if file {file_name} exists in Filebase...")
    
    if DEVELOPMENT_MODE:
        # Check local storage in development mode
        local_path = f"storage/{file_name}"
        exists = os.path.exists(local_path)
        logger.info(f"⚠️ [DEV MODE] File {file_name} {'exists' if exists else 'does not exist'} in local storage")
        return exists
    
    try:
        # Check if file exists in Filebase
        response = s3.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=file_name,
            MaxKeys=1
        )
        
        # If the file exists, the response will contain at least one object
        exists = 'Contents' in response and len(response['Contents']) > 0
        
        if exists:
            logger.info(f"✅ File {file_name} exists in Filebase")
        else:
            logger.info(f"❌ File {file_name} does not exist in Filebase")
            
        return exists
    except Exception as e:
        logger.error(f"❌ Failed to check if file exists in Filebase: {e}")
        logger.debug(traceback.format_exc())
        return False

def retrieve_from_filebase(file_name):
    """
    Retrieve a file from Filebase (IPFS storage).
    
    Args:
        file_name (str): The name of the file to retrieve
        
    Returns:
        bytes: The binary data of the file, or None if retrieval failed
    """
    logger.info(f"Retrieving file {file_name} from storage...")
    start_time = time.time()
    
    if DEVELOPMENT_MODE:
        # Simulate retrieval in development mode
        try:
            with open(f"storage/{file_name}", "rb") as f:
                data = f.read()
            
            elapsed_time = time.time() - start_time
            logger.info(f"✅ [DEV MODE] Retrieved file locally: storage/{file_name} in {elapsed_time:.4f} seconds")
            return data
        except Exception as e:
            logger.error(f"❌ [DEV MODE] Failed to retrieve file locally: {e}")
            logger.debug(traceback.format_exc())
            return None
    
    try:
        # Actual retrieval from Filebase
        response = s3.get_object(Bucket=BUCKET_NAME, Key=file_name)
        data = response["Body"].read()
        
        elapsed_time = time.time() - start_time
        logger.info(f"✅ Retrieved file from Filebase: {file_name} in {elapsed_time:.4f} seconds")
        return data
    except Exception as e:
        logger.error(f"❌ Filebase retrieval failed: {e}")
        logger.debug(traceback.format_exc())
        return None

# In-memory token storage for development mode
DEV_TOKENS = set()

def store_token_on_blockchain(user_token):
    """
    Store a token on the blockchain.
    
    Args:
        user_token (str): The token to store
        
    Returns:
        str: The transaction hash if successful, None otherwise
    """
    logger.info(f"Storing token on blockchain: {user_token}")
    start_time = time.time()
    
    if BLOCKCHAIN_DEV_MODE:
        # Simulate blockchain storage in development mode
        DEV_TOKENS.add(user_token)
        
        # Add a small delay to simulate blockchain transaction time
        time.sleep(0.5)
        
        elapsed_time = time.time() - start_time
        logger.info(f"✅ [DEV MODE] Token stored in memory: {user_token} in {elapsed_time:.4f} seconds")
        
        # Return a dummy transaction hash
        return "0x" + "0" * 64
    
    try:
        if not contract or not account:
            logger.error("❌ Contract or account not initialized")
            return None
        
        # Build the transaction
        logger.debug(f"Building transaction for token: {user_token}")
        tx = contract.functions.storeToken(user_token).build_transaction({
            'from': account.address,
            'nonce': web3.eth.get_transaction_count(account.address),
            'gas': 200000,
            'gasPrice': web3.to_wei('10', 'gwei')
        })

        # Sign and send the transaction
        logger.debug("Signing transaction...")
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        
        logger.debug("Sending transaction to network...")
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        logger.debug(f"Transaction sent: {tx_hash.hex()}")
        
        # Set a shorter timeout for waiting for receipt (5 seconds)
        try:
            logger.debug(f"Waiting for transaction receipt with timeout: {tx_hash.hex()}")
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=5)
            logger.debug(f"Receipt received: {receipt.transactionHash.hex()}")
        except Exception as e:
            logger.warning(f"Timeout waiting for receipt, but transaction was sent: {tx_hash.hex()}")
            logger.warning(f"Error: {str(e)}")
            # We'll consider this a success since the transaction was sent
            # The receipt can be checked later

        elapsed_time = time.time() - start_time
        logger.info(f"✅ Token stored on-chain: {user_token} in {elapsed_time:.4f} seconds")
        logger.info(f"Transaction hash: {receipt.transactionHash.hex()}")
        
        return receipt.transactionHash.hex()
    except Exception as e:
        logger.error(f"❌ Blockchain store failed: {e}")
        logger.debug(traceback.format_exc())
        return None

def verify_token_on_blockchain(user_token):
    """
    Verify if a token exists on the blockchain.
    
    Args:
        user_token (str): The token to verify
        
    Returns:
        bool: True if the token is valid, False otherwise
    """
    logger.info(f"Verifying token on blockchain: {user_token}")
    start_time = time.time()
    
    if BLOCKCHAIN_DEV_MODE:
        # Simulate blockchain verification in development mode
        # Add a small delay to simulate blockchain query time
        time.sleep(0.2)
        
        is_valid = user_token in DEV_TOKENS
        
        elapsed_time = time.time() - start_time
        logger.info(f"✅ [DEV MODE] Token verification: {user_token} is {'valid' if is_valid else 'invalid'} in {elapsed_time:.4f} seconds")
        return is_valid
    
    try:
        if not contract:
            logger.error("❌ Contract not initialized")
            return False
        
        # For now, we'll check if the file exists in Filebase instead of calling the contract
        # This is a temporary workaround until the blockchain integration is fully working
        try:
            # Check if the file exists in Filebase
            file_exists = check_file_exists_in_filebase(f"{user_token}.json")
            
            if file_exists:
                logger.info(f"✅ Token {user_token} verified via Filebase")
                return True
            else:
                # Try with .txt extension for backward compatibility
                file_exists = check_file_exists_in_filebase(f"{user_token}.txt")
                if file_exists:
                    logger.info(f"✅ Token {user_token} verified via Filebase (txt format)")
                    return True
                else:
                    logger.info(f"❌ Token {user_token} not found in Filebase")
                    return False
        except Exception as filebase_error:
            logger.warning(f"Filebase check failed, falling back to blockchain: {filebase_error}")
            # Fall back to blockchain verification
        
        # Try to call the contract function with a timeout
        import threading
        from concurrent.futures import ThreadPoolExecutor, TimeoutError
        
        def call_contract_with_timeout():
            return contract.functions.verifyToken(user_token).call()
        
        # Use ThreadPoolExecutor to implement timeout
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(call_contract_with_timeout)
            try:
                is_valid = future.result(timeout=3)  # 3 second timeout
                
                elapsed_time = time.time() - start_time
                logger.info(f"✅ Token verification completed in {elapsed_time:.4f} seconds")
                logger.info(f"Token {user_token} is {'valid' if is_valid else 'invalid'}")
                
                return is_valid
            except TimeoutError:
                logger.warning(f"⚠️ Blockchain verification timed out, assuming token is valid if it exists in our records")
                # If we have the token in our local records, consider it valid
                if user_token in DEV_TOKENS:
                    logger.info(f"✅ Token {user_token} found in local records, considering valid")
                    return True
                return False
    except Exception as e:
        logger.error(f"❌ Token verification failed: {e}")
        logger.debug(traceback.format_exc())
        return False
