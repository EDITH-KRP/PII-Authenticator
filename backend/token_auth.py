# backend/token_auth.py
from w3_utils import store_token_on_blockchain, verify_token_on_blockchain
import random
import string
import time
import os
from logger import get_logger

# Get logger
logger = get_logger()

def generate_unique_token():
    """Generate a random unique token."""
    token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    logger.debug(f"Generated token: {token}")
    return token

def get_or_generate_token(user_id, user_data=None):
    """
    Generate a unique token for a user and store it on the blockchain.
    If a token already exists for this user, return that token instead.
    
    Args:
        user_id (str): The user ID to associate with the token
        user_data (dict, optional): User data to check for existing tokens
        
    Returns:
        str: The generated or existing token
        bool: Whether the token is newly generated or existing
    """
    logger.info(f"Checking/generating token for user: {user_id}")
    start_time = time.time()
    
    # Check if a token already exists for this user
    existing_token = check_existing_token(user_id, user_data)
    
    if existing_token:
        logger.info(f"Found existing token for user {user_id}: {existing_token}")
        return existing_token, False
    
    # Generate a new token with high entropy
    token = generate_unique_token()
    logger.debug(f"Generated new token for user {user_id}: {token}")
    
    # Store token on blockchain
    tx_hash = store_token_on_blockchain(token)
    
    if tx_hash:
        logger.info(f"Token {token} stored on blockchain for user {user_id}. TX: {tx_hash}")
    else:
        logger.warning(f"Failed to store token {token} on blockchain for user {user_id}")
        # Even if blockchain storage fails, we still return the token
        # The token can be re-stored later if needed
    
    elapsed_time = time.time() - start_time
    logger.debug(f"Token generation completed in {elapsed_time:.4f} seconds")
    
    return token, True

def check_existing_token(user_id, user_data=None):
    """
    Check if a token already exists for this user or for the same personal details.
    
    Args:
        user_id (str): The user ID to check
        user_data (dict, optional): User data to check for existing tokens
        
    Returns:
        str: The existing token if found, None otherwise
    """
    from os import listdir
    from os.path import isfile, join
    import json
    
    logger.info(f"Checking for existing token for user: {user_id}")
    
    # In development mode, check local storage directory
    storage_dir = "storage"
    
    try:
        # Get all files in the storage directory
        if not os.path.exists(storage_dir):
            logger.debug(f"Storage directory {storage_dir} does not exist")
            return None
            
        files = [f for f in listdir(storage_dir) if isfile(join(storage_dir, f))]
        
        # First, check for exact user_id match
        for file in files:
            if file.endswith(".json"):
                try:
                    with open(join(storage_dir, file), "r") as f:
                        data = json.load(f)
                        
                    if data.get("user_id") == user_id:
                        token = file.replace(".json", "")
                        logger.info(f"Found existing token for user_id {user_id}: {token}")
                        return token
                except Exception as e:
                    logger.warning(f"Error reading file {file}: {e}")
                    continue
        
        # If user_data is provided, check for matching personal details
        if user_data:
            for file in files:
                if file.endswith(".json"):
                    try:
                        with open(join(storage_dir, file), "r") as f:
                            data = json.load(f)
                        
                        # Check if critical fields match
                        if (data.get("name") == user_data.get("name") and
                            data.get("email") == user_data.get("email") and
                            data.get("id_type") == user_data.get("id_type") and
                            data.get("id_number") == user_data.get("id_number")):
                            
                            token = file.replace(".json", "")
                            logger.info(f"Found existing token for matching personal details: {token}")
                            return token
                    except Exception as e:
                        logger.warning(f"Error reading file {file}: {e}")
                        continue
        
        logger.info(f"No existing token found for user: {user_id}")
        return None
    except Exception as e:
        logger.error(f"Error checking for existing token: {e}")
        return None

def verify_token(token):
    """
    Verify if a token exists on the blockchain.
    
    Args:
        token (str): The token to verify
        
    Returns:
        bool: True if the token is valid, False otherwise
    """
    logger.info(f"Verifying token: {token}")
    start_time = time.time()
    
    # Verify token on blockchain
    is_valid = verify_token_on_blockchain(token)
    
    elapsed_time = time.time() - start_time
    logger.debug(f"Token verification completed in {elapsed_time:.4f} seconds")
    
    if is_valid:
        logger.info(f"Token {token} is valid")
    else:
        logger.info(f"Token {token} is invalid")
    
    return is_valid
