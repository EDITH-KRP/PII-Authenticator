from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import logging
import json

# AES key storage (Example: to store keys associated with each ID)
AES_KEY_STORAGE = {}

def encrypt_and_store_id(id_number: str):
    try:
        # Load AES Key from ENV (for simplicity, use a default key)
        aes_key = os.getenv("ENCRYPTED_AES_KEY")
        if not aes_key:
            raise ValueError("No AES Key found in environment variables.")
        
        # Generate a random IV (Initialization Vector) for encryption
        iv = os.urandom(16)

        # Encrypt the ID using AES (CBC mode)
        cipher = Cipher(algorithms.AES(base64.urlsafe_b64decode(aes_key)), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Ensure ID is 16-byte padded (AES block size is 16 bytes)
        padded_id = id_number.encode('utf-8') + b'\x00' * (16 - len(id_number) % 16)
        encrypted_id = encryptor.update(padded_id) + encryptor.finalize()

        # Store the AES key and IV in a global storage for later retrieval (you can store in a secure database)
        AES_KEY_STORAGE[id_number] = aes_key

        # Store the encrypted data in Filecoin (assuming you have a function to do this)
        # Replace this with the actual Filecoin storage logic, the code here is a placeholder.
        cid = "dummy_cid_for_now"  # This should be the CID of the uploaded file in Filecoin
        
        logging.info(f"Encrypted ID stored for {id_number}. CID: {cid}")
        return encrypted_id, cid
    
    except Exception as e:
        logging.error(f"Encryption failed for {id_number}: {str(e)}")
        raise e
