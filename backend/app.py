from flask import Flask, request, jsonify
from encrypt import encrypt_id
from verify import verify_id_on_blockchain
from token_auth import generate_token, verify_token

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    encrypted_id, id_hash = encrypt_id(data['id_number'])
    return jsonify({"encrypted_id": encrypted_id, "id_hash": id_hash})

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    result = verify_id_on_blockchain(data['id_number'], data['id_hash'])
    return jsonify({"verified": result})

@app.route('/generate-token', methods=['POST'])
def generate_auth_token():
    data = request.json
    token = generate_token(data['id_number'])
    return jsonify({"token": token})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    verified = verify_token(data['token'])
    return jsonify({"authenticated": verified})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
