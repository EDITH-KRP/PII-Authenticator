import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes

def encrypt_id(id_number):
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padded_id = id_number.ljust(32).encode()
    encrypted_id = encryptor.update(padded_id) + encryptor.finalize()

    hashed_id = hashlib.sha256(encrypted_id).hexdigest()
    return base64.b64encode(encrypted_id).decode(), hashed_id