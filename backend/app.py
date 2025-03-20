import os
import logging
import base64
import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from web3 import Web3
from encrypt import encrypt_and_store_id, AES_KEY_STORAGE
from token_auth import get_or_generate_token, verify_token
from w3_utils import upload_to_filebase, retrieve_from_filebase

# Load environment variables
load_dotenv()

INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ENCRYPTED_AES_KEY = os.getenv("ENCRYPTED_AES_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

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

# ✅ Flask App Initialization
app = Flask(__name__)

# ✅ Enable CORS (Allow frontend to communicate with backend)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins

# ✅ Encrypt ID and store on Filecoin (User gets ONE token for all IDs)
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    logging.info(f"🔹 Received /encrypt request: {data}")

    user_id = data.get('user_id')
    id_number = data.get('id_number')

    if not user_id or not id_number:
        return jsonify({"error": "❌ Missing user_id or id_number"}), 400

    try:
        # ✅ Upload encrypted ID to Filebase
        file_url = upload_to_filebase(f"{user_id}_id.txt", id_number.encode())

        # ✅ Generate User Token
        token = get_or_generate_token(user_id)

        return jsonify({"token": token, "file_url": file_url}), 200
    except Exception as e:
        logging.error(f"❌ Encryption failed: {str(e)}")
        return jsonify({"error": f"❌ Encryption failed: {str(e)}"}), 500


# ✅ Retrieve and Decrypt File from Filecoin
@app.route('/retrieve', methods=['POST'])
def retrieve():
    data = request.json
    logging.info(f"🔹 Received /retrieve request: {data}")

    token = data.get("token")
    if not token:
        logging.warning("❌ No token provided.")
        return jsonify({"error": "❌ Token is required."}), 400

    # ✅ Verify JWT Token (Returns User ID)
    user_id = verify_token(token)
    if not user_id:
        logging.warning(f"❌ Unauthorized access attempt with invalid token.")
        return jsonify({"error": "❌ Invalid or Expired Token"}), 401

    try:
        # ✅ Retrieve encrypted ID from Filebase (Fixed function call)
        stored_data = retrieve_from_filebase(f"{user_id}_id.txt")
        if not stored_data:
            return jsonify({"error": "❌ No file found for this user"}), 400

        decrypted_id = stored_data.decode()  # Convert bytes to string

        return jsonify({"user_id": user_id, "decrypted_id": decrypted_id}), 200
    except Exception as e:
        logging.error(f"❌ Retrieval failed for User: {user_id}. Error: {str(e)}")
        return jsonify({"error": f"❌ Retrieval failed. {str(e)}"}), 500


# ✅ Retrieve stored token from Filebase
@app.route('/get_token/<user_id>', methods=['GET'])
def get_token(user_id):
    logging.info(f"🔹 Received /get_token request for user_id: {user_id}")

    try:
        token_data = retrieve_from_filebase(f"token_{user_id}.txt")
        if not token_data:
            return jsonify({"error": "❌ Token not found"}), 404

        return jsonify({"token": token_data.decode()}), 200
    except Exception as e:
        logging.error(f"❌ Failed to retrieve token: {str(e)}")
        return jsonify({"error": f"❌ Failed to retrieve token: {str(e)}"}), 500


# ✅ Check Web3 Connection Status
@app.route('/check_connection', methods=['GET'])
def check_connection():
    logging.info("🔹 Received /check_connection request")

    try:
        if w3.is_connected():
            return jsonify({"status": "success", "message": "Web3 is connected!"}), 200
        else:
            return jsonify({"status": "error", "message": "Web3 is not connected!"}), 500
    except Exception as e:
        logging.error(f"❌ Web3 connection failed. Error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to check Web3 connection: {str(e)}"}), 500


# ✅ Run Flask Application
if __name__ == '__main__':
    logging.info("🚀 Starting Flask Server...")
    app.run(host='0.0.0.0', port=5000, debug=True)
