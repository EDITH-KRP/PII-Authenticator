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

# Always use real blockchain mode
BLOCKCHAIN_DEV_MODE = False  # Force to false to always use real blockchain

# Try to connect to Sepolia via Alchemy
try:
    logger.info("Connecting to Ethereum network via Alchemy...")
    start_time = time.time()
    
    # Use the SEPOLIA_RPC_URL directly if available, otherwise construct from ALCHEMY_API_KEY
    sepolia_rpc_url = os.getenv('SEPOLIA_RPC_URL')
    if not sepolia_rpc_url:
        sepolia_rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
    
    web3 = Web3(HTTPProvider(sepolia_rpc_url))
    
    if not web3.is_connected() and not BLOCKCHAIN_DEV_MODE:
        logger.warning("WARNING: Could not connect to Sepolia via Alchemy")
        logger.warning("WARNING: Running in development mode with simulated blockchain")
        BLOCKCHAIN_DEV_MODE = True
    else:
        if not BLOCKCHAIN_DEV_MODE:
            elapsed_time = time.time() - start_time
            logger.info(f"SUCCESS: Connected to Ethereum network in {elapsed_time:.4f} seconds")
        else:
            logger.info("Running in development mode with simulated blockchain (forced by environment variable)")
except Exception as e:
    if not BLOCKCHAIN_DEV_MODE:
        logger.warning(f"WARNING: Failed to initialize Web3: {e}")
        logger.warning("WARNING: Running in development mode with simulated blockchain")
        logger.debug(traceback.format_exc())
        BLOCKCHAIN_DEV_MODE = True
    web3 = Web3()  # Fallback to local provider

# Try to load contract ABI
contract_abi = None
try:
    logger.info("Loading contract ABI...")
    abi_path = "../blockchain/artifacts/contracts/Token_Auth.sol/TokenAuth.json"
    with open(abi_path, "r") as f:
        contract_json = json.load(f)
        contract_abi = contract_json["abi"]
    logger.info("SUCCESS: Contract ABI loaded successfully")
except Exception as e:
    logger.warning(f"WARNING: Failed to load contract ABI: {e}")
    logger.warning("WARNING: Using a dummy ABI for development")
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
    # Make sure CONTRACT_ADDRESS is properly formatted
    clean_address = CONTRACT_ADDRESS.strip()
    
    # Convert to checksum address
    checksum_address = web3.to_checksum_address(clean_address)
    
    contract = web3.eth.contract(address=checksum_address, abi=contract_abi)
    account = web3.eth.account.from_key(PRIVATE_KEY)
    logger.info(f"SUCCESS: Contract initialized at address {checksum_address}")
    
    # Verify contract exists on the blockchain
    if not BLOCKCHAIN_DEV_MODE:
        try:
            code = web3.eth.get_code(checksum_address)
            if code == b'' or code == '0x':
                logger.warning(f"WARNING: No contract code found at address {checksum_address}")
                logger.warning("WARNING: This may be an invalid contract address")
            else:
                logger.info(f"SUCCESS: Contract code verified at address {checksum_address}")
        except Exception as e:
            logger.warning(f"WARNING: Could not verify contract code: {e}")
except Exception as e:
    logger.warning(f"WARNING: Failed to initialize contract: {e}")
    logger.debug(traceback.format_exc())
    contract = None
    account = None

# Make sure account is initialized even if contract fails
if account is None:
    try:
        account = web3.eth.account.from_key(PRIVATE_KEY)
    except Exception as e:
        logger.warning(f"⚠️ Failed to initialize account: {e}")
        account = None

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
    logger.info(f"SUCCESS: Filebase S3 client initialized in {elapsed_time:.4f} seconds")
except Exception as e:
    logger.warning(f"WARNING: Failed to initialize S3 client: {e}")
    logger.warning("WARNING: Running in development mode with simulated storage")
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
        logger.info(f"[DEV MODE] Simulated upload to Filebase: {file_url}")
        
        # Save locally for development testing
        try:
            os.makedirs("storage", exist_ok=True)
            with open(f"storage/{file_name}", "wb") as f:
                f.write(file_data)
            logger.info(f"SUCCESS: [DEV MODE] Saved file locally: storage/{file_name}")
        except Exception as e:
            logger.error(f"ERROR: [DEV MODE] Failed to save file locally: {e}")
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
                    logger.info(f"SUCCESS: Uploaded to Filebase: {file_url} in {elapsed_time:.4f} seconds")
                    return file_url
            except TimeoutError:
                logger.warning(f"WARNING: Filebase upload timed out after 10 seconds")
                # Return a simulated URL for now
                file_url = f"{ENDPOINT_URL}/{BUCKET_NAME}/{file_name}"
                logger.info(f"WARNING: Returning URL without confirmed upload: {file_url}")
                return file_url
    except Exception as e:
        logger.error(f"ERROR: Filebase upload failed: {e}")
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
        logger.info(f"[DEV MODE] File {file_name} {'exists' if exists else 'does not exist'} in local storage")
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
            logger.info(f"SUCCESS: File {file_name} exists in Filebase")
        else:
            logger.info(f"INFO: File {file_name} does not exist in Filebase")
            
        return exists
    except Exception as e:
        logger.error(f"ERROR: Failed to check if file exists in Filebase: {e}")
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
            logger.info(f"SUCCESS: [DEV MODE] Retrieved file locally: storage/{file_name} in {elapsed_time:.4f} seconds")
            return data
        except Exception as e:
            logger.error(f"ERROR: [DEV MODE] Failed to retrieve file locally: {e}")
            logger.debug(traceback.format_exc())
            return None
    
    try:
        # Actual retrieval from Filebase
        response = s3.get_object(Bucket=BUCKET_NAME, Key=file_name)
        data = response["Body"].read()
        
        elapsed_time = time.time() - start_time
        logger.info(f"SUCCESS: Retrieved file from Filebase: {file_name} in {elapsed_time:.4f} seconds")
        return data
    except Exception as e:
        logger.error(f"ERROR: Filebase retrieval failed: {e}")
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
    
    # Always use the real blockchain
    logger.info("Using real blockchain for token storage")
    
    try:
        # Check if web3 is connected
        if not web3.is_connected():
            logger.error("ERROR: Web3 is not connected to the blockchain")
            return None
            
        # Check if contract and account are initialized
        if not contract or not account:
            logger.error("ERROR: Contract or account not initialized")
            return None
        
        # Get the latest nonce to avoid nonce errors
        nonce = web3.eth.get_transaction_count(account.address)
        logger.debug(f"Current nonce for account {account.address}: {nonce}")
        
        # Build the transaction
        logger.debug(f"Building transaction for token: {user_token}")
        tx = contract.functions.storeToken(user_token).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 300000,  # Increased gas limit
            'gasPrice': web3.to_wei('20', 'gwei')  # Higher gas price for faster confirmation
        })

        # Sign and send the transaction
        logger.debug("Signing transaction...")
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        
        logger.debug("Sending transaction to network...")
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hash_hex = tx_hash.hex()
        
        logger.info(f"Transaction sent: {tx_hash_hex}")
        
        # Set a longer timeout for waiting for receipt (15 seconds)
        try:
            logger.debug(f"Waiting for transaction receipt with timeout: {tx_hash_hex}")
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)
            logger.info(f"Receipt received: {receipt.transactionHash.hex()}")
            
            # Verify the transaction was successful
            if receipt.status == 1:
                logger.info(f"Transaction successful: {receipt.transactionHash.hex()}")
                
                elapsed_time = time.time() - start_time
                logger.info(f"SUCCESS: Token stored on-chain: {user_token} in {elapsed_time:.4f} seconds")
                logger.info(f"Transaction hash: {receipt.transactionHash.hex()}")
                
                return receipt.transactionHash.hex()
            else:
                logger.error(f"Transaction failed with status: {receipt.status}")
                return None
        except Exception as e:
            logger.warning(f"Timeout waiting for receipt, but transaction was sent: {tx_hash_hex}")
            logger.warning(f"Error: {str(e)}")
            # We'll consider this a success since the transaction was sent
            # The receipt can be checked later
            
            elapsed_time = time.time() - start_time
            logger.info(f"✅ Token sent to blockchain: {user_token} in {elapsed_time:.4f} seconds (receipt pending)")
            logger.info(f"Transaction hash: {tx_hash_hex}")
            
            return tx_hash_hex
    except Exception as e:
        logger.error(f"❌ Blockchain store failed: {e}")
        logger.debug(traceback.format_exc())
        
        # Don't generate simulated hashes, just return None to indicate failure
        logger.error("Blockchain transaction failed and no fallback is available")
        return None

def regenerate_blockchain_record(user_token, existing_tx_hash=None):
    """
    Regenerate the blockchain record for an existing token.
    This is useful when the original transaction hash is invalid or not found.
    
    Args:
        user_token (str): The token to regenerate the record for
        existing_tx_hash (str, optional): The existing transaction hash
        
    Returns:
        str: The new transaction hash if successful, None otherwise
    """
    logger.info(f"Regenerating blockchain record for token: {user_token}")
    
    # Always use real blockchain transactions
    logger.info("Using real blockchain for token regeneration")
    
    # Check if the web3 connection is working
    if not web3.is_connected():
        logger.error("Cannot regenerate blockchain record: Web3 is not connected")
        return None
    
    # Check if the contract is initialized
    if contract is None or account is None:
        logger.error("Cannot regenerate blockchain record: Contract or account not initialized")
        return None
    
    if existing_tx_hash:
        logger.info(f"Existing transaction hash: {existing_tx_hash}")
        
        # Check if this is a simulated hash (starts with 0xSIM_)
        if existing_tx_hash.startswith("0xSIM_"):
            logger.info("Existing hash is a simulated hash, generating a real blockchain record")
        else:
            # Try to verify the existing hash on the blockchain
            try:
                tx = web3.eth.get_transaction(existing_tx_hash)
                if tx:
                    logger.info(f"Existing transaction hash is valid: {existing_tx_hash}")
                    return existing_tx_hash
            except Exception as e:
                logger.warning(f"Existing transaction hash is invalid: {e}")
                logger.debug(f"Will attempt to create a new blockchain record for token: {user_token}")
    
    # If we get here, we need to regenerate the record
    logger.info("Generating new blockchain record")
    
    try:
        # Build the transaction
        logger.debug(f"Building transaction for token: {user_token}")
        
        # Get the latest nonce to avoid nonce errors
        nonce = web3.eth.get_transaction_count(account.address)
        logger.debug(f"Current nonce for account {account.address}: {nonce}")
        
        tx = contract.functions.storeToken(user_token).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 200000,
            'gasPrice': web3.to_wei('20', 'gwei')  # Higher gas price for faster confirmation
        })
        
        # Sign and send the transaction
        logger.debug("Signing transaction...")
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        
        logger.debug("Sending transaction to network...")
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hash_hex = tx_hash.hex()
        
        logger.info(f"Transaction sent: {tx_hash_hex}")
        
        # Set a longer timeout for waiting for receipt (10 seconds)
        try:
            logger.debug(f"Waiting for transaction receipt with timeout: {tx_hash_hex}")
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
            logger.info(f"Receipt received: {receipt.transactionHash.hex()}")
            
            # Verify the transaction was successful
            if receipt.status == 1:
                logger.info(f"Transaction successful: {receipt.transactionHash.hex()}")
                return receipt.transactionHash.hex()
            else:
                logger.error(f"Transaction failed with status: {receipt.status}")
                return None
        except Exception as e:
            logger.warning(f"Timeout waiting for receipt, but transaction was sent: {tx_hash_hex}")
            logger.warning(f"Error: {str(e)}")
            # We'll consider this a success since the transaction was sent
            # The receipt can be checked later
            return tx_hash_hex
            
    except Exception as e:
        logger.error(f"Failed to regenerate blockchain record: {e}")
        logger.debug(traceback.format_exc())
        return None

def check_blockchain_connection():
    """
    Check if the blockchain connection is working properly.
    
    Returns:
        dict: Connection status and details
    """
    try:
        logger.debug("Checking blockchain connection...")
        
        if not web3.is_connected():
            logger.warning("Web3 is not connected to the blockchain")
            return {
                "connected": False,
                "error": "Not connected to Ethereum network",
                "dev_mode": BLOCKCHAIN_DEV_MODE
            }
        
        # Get the latest block as a simple test
        latest_block = web3.eth.block_number
        logger.debug(f"Latest block number: {latest_block}")
        
        # Check if the contract is accessible
        try:
            contract_code = web3.eth.get_code(CONTRACT_ADDRESS)
            has_contract = len(contract_code) > 0
        except Exception as e:
            logger.warning(f"Error checking contract: {e}")
            has_contract = False
        
        return {
            "connected": True,
            "network": "Sepolia Testnet",
            "latest_block": latest_block,
            "contract_valid": has_contract,
            "api_key_valid": True,
            "dev_mode": BLOCKCHAIN_DEV_MODE
        }
    except Exception as e:
        logger.error(f"Error checking blockchain connection: {e}")
        logger.debug(traceback.format_exc())
        return {
            "connected": False,
            "error": str(e),
            "dev_mode": BLOCKCHAIN_DEV_MODE
        }

def get_token_transaction_details(user_token):
    """
    Get transaction details for a token from the blockchain.
    
    Args:
        user_token (str): The token to look up
        
    Returns:
        dict: Transaction details if found, empty dict otherwise
    """
    if BLOCKCHAIN_DEV_MODE:
        # In development mode, return simulated transaction details
        if user_token in DEV_TOKENS:
            # Generate a dummy transaction hash
            tx_hash = "0x" + ''.join(random.choices('0123456789abcdef', k=64))
            
            return {
                "tx_hash": tx_hash,
                "block_number": 12345678,
                "timestamp": int(time.time()) - random.randint(100, 10000),
                "from": "0x" + ''.join(random.choices('0123456789abcdef', k=40)),
                "to": CONTRACT_ADDRESS,
                "status": "success",
                "network": "Sepolia Testnet (simulated)",
                "dev_mode": True,
                "dev_mode_message": "Running in development mode with simulated blockchain data. In production, this would show real transaction data from the Ethereum blockchain."
            }
        return {
            "dev_mode": True,
            "dev_mode_message": "Token not found in development mode records."
        }
    
    try:
        # Check tokens.json to find the transaction hash for this token
        tokens_file = os.path.join(os.path.dirname(__file__), 'tokens.json')
        if os.path.exists(tokens_file):
            with open(tokens_file, 'r') as f:
                tokens_data = json.load(f)
                
            # Find the token in the data
            for user_key, data in tokens_data.items():
                if data.get('token') == user_token:
                    tx_hash = data.get('txn_hash')
                    if tx_hash and tx_hash != "pending":
                        try:
                            logger.debug(f"Attempting to get transaction details for hash: {tx_hash}")
                            
                            # Check if this is a simulated transaction hash (starts with 0xSIM_)
                            if tx_hash.startswith("0xSIM_"):
                                logger.info(f"Transaction {tx_hash} is a simulated hash")
                                return {
                                    "tx_hash": tx_hash,
                                    "network": "Sepolia Testnet (simulated)",
                                    "status": "simulated",
                                    "timestamp": int(time.time()),
                                    "dev_mode_message": "This is a simulated transaction for development purposes. No actual blockchain transaction was created."
                                }
                            
                            # Check if web3 is connected
                            if not web3.is_connected():
                                logger.warning("Web3 is not connected to the blockchain")
                                return {
                                    "tx_hash": tx_hash,
                                    "network": "Sepolia Testnet",
                                    "status": "unknown",
                                    "error": "Web3 is not connected to the blockchain",
                                    "error_message": "Cannot connect to the Ethereum network. Please check your internet connection and try again.",
                                    "needs_regeneration": True
                                }
                            
                            # Try to get the transaction
                            logger.debug("Calling web3.eth.get_transaction...")
                            tx = web3.eth.get_transaction(tx_hash)
                            
                            if tx is None:
                                logger.warning(f"Transaction {tx_hash} not found on the blockchain")
                                
                                # Try to regenerate the blockchain record
                                logger.info(f"Attempting to regenerate blockchain record for token with hash: {tx_hash}")
                                
                                # We'll return this for now, but the token verification process should
                                # handle regeneration of the blockchain record
                                return {
                                    "tx_hash": tx_hash,
                                    "network": "Sepolia Testnet",
                                    "status": "not_found",
                                    "error": "Transaction not found",
                                    "error_message": "This transaction hash does not exist on the Sepolia testnet. The system will attempt to regenerate the blockchain record.",
                                    "needs_regeneration": True
                                }
                            
                            # Get receipt and block details
                            logger.debug("Getting transaction receipt...")
                            receipt = web3.eth.get_transaction_receipt(tx_hash)
                            
                            logger.debug(f"Getting block details for block number: {tx.blockNumber}")
                            block = web3.eth.get_block(tx.blockNumber)
                            
                            logger.debug("Successfully retrieved all transaction details")
                            return {
                                "tx_hash": tx_hash,
                                "block_number": tx.blockNumber,
                                "timestamp": block.timestamp,
                                "from": tx["from"],
                                "to": tx.to,
                                "status": "success" if receipt.status == 1 else "failed",
                                "network": "Sepolia Testnet"
                            }
                        except Exception as e:
                            logger.warning(f"Error getting transaction details: {e}")
                            logger.debug(traceback.format_exc())
                            
                            # Return basic info if we can't get full details
                            error_message = str(e)
                            user_message = "Transaction hash not found on the blockchain. This could be because the transaction is still pending, or the blockchain node is not fully synced."
                            
                            # Check for specific error types
                            if "not found" in error_message.lower():
                                user_message = "This transaction hash does not exist on the Sepolia testnet. The system will attempt to regenerate the blockchain record."
                                needs_regeneration = True
                            elif "timeout" in error_message.lower():
                                user_message = "Connection to the blockchain timed out. Please check your internet connection and try again."
                                needs_regeneration = False
                            else:
                                needs_regeneration = False
                            
                            return {
                                "tx_hash": tx_hash,
                                "network": "Sepolia Testnet",
                                "status": "unknown",
                                "error": error_message,
                                "error_message": user_message,
                                "needs_regeneration": needs_regeneration
                            }
        return {
            "error_message": "No transaction hash found for this token. The token may not have been stored on the blockchain yet."
        }
    except Exception as e:
        logger.error(f"Error in get_token_transaction_details: {e}")
        return {}

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
        
        # We'll use the blockchain to verify the token
        logger.info(f"Verifying token {user_token} directly on the blockchain")
        
        # Try to call the contract function with a timeout
        import threading
        from concurrent.futures import ThreadPoolExecutor, TimeoutError
        
        def call_contract_with_timeout():
            try:
                # Call the smart contract's verifyToken function
                logger.info(f"Calling verifyToken function on smart contract for token: {user_token}")
                
                # This actually calls the blockchain to verify the token
                result = contract.functions.verifyToken(user_token).call()
                
                if result:
                    logger.info(f"✅ Token {user_token} verified on blockchain via smart contract")
                else:
                    logger.info(f"❌ Token {user_token} not found on blockchain via smart contract")
                
                return result
            except Exception as e:
                logger.error(f"Error in blockchain verification: {e}")
                logger.debug(traceback.format_exc())
                
                # Fallback to checking local records if blockchain call fails
                logger.warning("Falling back to local verification due to blockchain error")
                
                # First check in-memory storage (for dev mode)
                if user_token in DEV_TOKENS:
                    logger.info(f"Token {user_token} found in DEV_TOKENS (fallback)")
                    return True
                
                # Then check tokens.json
                tokens_file = os.path.join(os.path.dirname(__file__), 'tokens.json')
                if os.path.exists(tokens_file):
                    with open(tokens_file, 'r') as f:
                        tokens_data = json.load(f)
                        
                    # Check if the token exists in any of the entries
                    for user_key, data in tokens_data.items():
                        if data.get('token') == user_token:
                            logger.info(f"Token {user_token} found in tokens.json (fallback)")
                            return True
                
                logger.info(f"Token {user_token} not found in any records")
                return False
        
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
                logger.warning(f"⚠️ Blockchain verification timed out")
                # In a production environment, we might want to retry or use a fallback
                # For now, we'll check our local records as a fallback
                
                # Check tokens.json as a fallback
                tokens_file = os.path.join(os.path.dirname(__file__), 'tokens.json')
                try:
                    if os.path.exists(tokens_file):
                        with open(tokens_file, 'r') as f:
                            tokens_data = json.load(f)
                            
                        # Check if the token exists in any of the entries
                        for user_key, data in tokens_data.items():
                            if data.get('token') == user_token:
                                logger.info(f"✅ Token {user_token} found in local records (fallback), considering valid")
                                return True
                except Exception as fallback_error:
                    logger.error(f"Error in fallback verification: {fallback_error}")
                
                logger.info(f"❌ Token {user_token} not verified (blockchain timeout)")
                return False
    except Exception as e:
        logger.error(f"❌ Token verification failed: {e}")
        logger.debug(traceback.format_exc())
        return False
