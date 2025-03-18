from flask import Flask, request, jsonify
from encrypt import encrypt_and_store_id
from verify import verify_id_on_blockchain
from token_auth import generate_token, verify_token
from web3_storage import Web3Storage
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
WEB3_STORAGE_TOKEN = os.getenv("WEB3_STORAGE_TOKEN")
storage = Web3Storage(WEB3_STORAGE_TOKEN)

app = Flask(__name__)

# 🔹 Encrypt ID and store on Filecoin
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    encrypted_id, id_hash, cid = encrypt_and_store_id(data['id_number'])
    return jsonify({"encrypted_id": encrypted_id, "id_hash": id_hash, "filecoin_cid": cid})

# 🔹 Retrieve stored Filecoin data
@app.route('/retrieve', methods=['GET'])
def retrieve():
    cid = os.getenv("FILECOIN_CID")
    
    if not cid:
        return jsonify({"error": "❌ No CID found in .env"}), 400

    # Fetch file from Filecoin
    file_data = storage.get(cid)
    
    if not file_data:
        return jsonify({"error": "❌ Unable to fetch file from Filecoin"}), 500
    
    return jsonify({"filecoin_cid": cid, "file_data": file_data.decode()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
