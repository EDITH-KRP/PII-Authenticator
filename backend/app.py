import os
import logging
import base64
import jwt
from flask import Flask, request, jsonify
from encrypt import encrypt_and_store_id, AES_KEY_STORAGE
from token_auth import generate_token, verify_token
from w3storage import API
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from web3 import Web3

# Load environment variables
load_dotenv()

# Configure API and logging
WEB3_STORAGE_TOKEN = os.getenv("WEB3_STORAGE_TOKEN")
storage = API(token=WEB3_STORAGE_TOKEN)

INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ENCRYPTED_AES_KEY = os.getenv("ENCRYPTED_AES_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
FILECOIN_CID = os.getenv("FILECOIN_CID")

# Directory for storing tokens
TOKEN_DIR = "tokens"
os.makedirs(TOKEN_DIR, exist_ok=True)

LOG_FILE = "retrieval_logs.log"

# Configure Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Configure Web3 connection using Infura
w3 = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"))
assert w3.is_connected(), "Web3 is not connected to Infura"

# Configure Flask app
app = Flask(__name__)


# 🔹 Encrypt ID and store on Filecoin
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    try:
        encrypted_id, cid = encrypt_and_store_id(data['id_number'])

        # Convert bytes to Base64 string for JSON compatibility
        encrypted_id_b64 = base64.b64encode(encrypted_id).decode('utf-8')

        # Generate JWT Token for Secure Retrieval
        token = generate_token(data['id_number'])

        # Store token in a text file
        token_file = os.path.join(TOKEN_DIR, f"{data['id_number']}.txt")
        with open(token_file, "w") as f:
            f.write(token)

        logging.info(f"✅ ID successfully encrypted and stored on Filecoin for ID: {data['id_number']}.")

        return jsonify({"encrypted_id": encrypted_id_b64, "filecoin_cid": cid, "token": token}), 200
    except Exception as e:
        logging.error(f"❌ Encryption failed for ID: {data['id_number']}. Error: {str(e)}")
        return jsonify({"error": f"❌ Encryption failed. {str(e)}"}), 500


# 🔹 Retrieve and Decrypt File from Filecoin (Requires JWT Token)
@app.route('/retrieve', methods=['POST'])
def retrieve():
    data = request.json
    token = data.get("token")

    if not token:
        logging.warning("❌ No token provided.")
        return jsonify({"error": "❌ Token is required."}), 400

    # Verify JWT Token
    id_number = verify_token(token)
    if not id_number:
        logging.warning(f"❌ Unauthorized access attempt with invalid token.")
        return jsonify({"error": "❌ Invalid or Expired Token"}), 401

    if id_number not in AES_KEY_STORAGE:
        logging.warning(f"❌ AES Key missing for ID: {id_number}.")
        return jsonify({"error": "❌ AES Key not found for this ID"}), 400

    cid = FILECOIN_CID
    if not cid:
        logging.warning(f"❌ CID not found for ID: {id_number}.")
        return jsonify({"error": "❌ No CID found in environment variables."}), 400

    try:
        # Fetch file from Filecoin
        encrypted_data = storage.get(cid)

        if not encrypted_data:
            logging.warning(f"❌ Unable to fetch file from Filecoin for ID: {id_number}.")
            return jsonify({"error": "❌ Unable to fetch file from Filecoin"}), 500

        # Decrypt data
        aes_key = AES_KEY_STORAGE.get(id_number, ENCRYPTED_AES_KEY)  # Use the encrypted AES key if no specific key
        iv = encrypted_data[:16]  # Extract IV
        ciphertext = encrypted_data[16:]  # Extract encrypted content

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Log success
        logging.info(f"✅ Retrieval successful for ID: {id_number}.")

        return jsonify({"filecoin_cid": cid, "decrypted_id": decrypted_data.strip().decode()}), 200
    except Exception as e:
        logging.error(f"❌ Retrieval failed for ID: {id_number}. Error: {str(e)}")
        return jsonify({"error": f"❌ Retrieval failed: {str(e)}"}), 500


# 🔹 Retrieve stored token from file
@app.route('/get_token/<id_number>', methods=['GET'])
def get_token(id_number):
    token_file = os.path.join(TOKEN_DIR, f"{id_number}.txt")
    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            token = f.read().strip()
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "❌ Token not found"}), 404


# 🔹 Check Web3 Connection Status
@app.route('/check_connection', methods=['GET'])
def check_connection():
    try:
        if w3.isConnected():
            return jsonify({"status": "success", "message": "Web3 is connected!"}), 200
        else:
            return jsonify({"status": "error", "message": "Web3 is not connected!"}), 500
    except Exception as e:
        logging.error(f"❌ Web3 connection failed. Error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to check Web3 connection: {str(e)}"}), 500
    @app.route('/get-infura-key', methods=['GET'])
    def get_infura_key():
        return jsonify({"infuraAPIKey": INFURA_API_KEY}), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
