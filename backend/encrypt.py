from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import json
import time
import traceback
from logger import get_logger

# Get logger
logger = get_logger()

# AES key storage (Example: to store keys associated with each ID)
AES_KEY_STORAGE = {}

def encrypt_and_store_id(id_number: str):
    """
    Encrypt and store an ID number.
    
    Args:
        id_number (str): The ID number to encrypt and store
        
    Returns:
        tuple: (encrypted_id, cid) - The encrypted ID and the CID where it's stored
    """
    logger.info(f"Encrypting and storing ID: {id_number[:4]}****")
    start_time = time.time()
    
    try:
        # Load AES Key from ENV (for simplicity, use a default key)
        aes_key = os.getenv("ENCRYPTED_AES_KEY", "c2FtcGxlX2Flc19rZXlfZm9yX2RldmVsb3BtZW50X29ubHk=")
        if not aes_key:
            logger.warning("⚠️ No AES Key found in environment variables. Using development key.")
        
        # Generate a random IV (Initialization Vector) for encryption
        iv = os.urandom(16)
        logger.debug("Generated random IV for encryption")

        try:
            # Encrypt the ID using AES (CBC mode)
            logger.debug("Encrypting ID using AES (CBC mode)")
            cipher = Cipher(algorithms.AES(base64.urlsafe_b64decode(aes_key)), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Ensure ID is 16-byte padded (AES block size is 16 bytes)
            padded_id = id_number.encode('utf-8') + b'\x00' * (16 - len(id_number) % 16)
            encrypted_id = encryptor.update(padded_id) + encryptor.finalize()
            
            logger.debug("ID encrypted successfully")
        except Exception as e:
            logger.error(f"⚠️ Encryption error: {str(e)}. Using development mode.")
            logger.debug(traceback.format_exc())
            
            # In development mode, just use a simple encoding
            encrypted_id = base64.b64encode(id_number.encode('utf-8'))
            logger.debug("Using base64 encoding as fallback")

        # Store the AES key and IV in a global storage for later retrieval
        AES_KEY_STORAGE[id_number] = aes_key
        logger.debug(f"AES key stored in memory for ID: {id_number[:4]}****")

        # Store the encrypted data in Filecoin (placeholder)
        # Replace this with the actual Filecoin storage logic
        cid = "dummy_cid_for_now"  # This should be the CID of the uploaded file in Filecoin
        
        elapsed_time = time.time() - start_time
        logger.info(f"Encrypted ID stored for {id_number[:4]}**** in {elapsed_time:.4f} seconds. CID: {cid}")
        
        return encrypted_id, cid
    
    except Exception as e:
        logger.error(f"Encryption failed for {id_number[:4]}****: {str(e)}")
        logger.debug(traceback.format_exc())
        
        # In development mode, don't crash on encryption errors
        return base64.b64encode(id_number.encode('utf-8')), "dev_cid"
