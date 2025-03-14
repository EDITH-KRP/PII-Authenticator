from flask import Flask, request, jsonify
from encrypt import encrypt_id
from verify import verify_id_on_blockchain
from token_auth import generate_token, verify_token

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the PII Authenticator API!"})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # Get the data from the request
        data = request.get_json()
        
        # Check if the 'id_number' field is present in the request data
        if 'id_number' not in data:
            return jsonify({"error": "ID number is required"}), 400
        
        # Call the encryption function
        encrypted_id, id_hash = encrypt_id(data['id_number'])
        
        # Return the encrypted ID and hash as a response
        return jsonify({"encrypted_id": encrypted_id, "id_hash": id_hash})
    
    except Exception as e:
        # Handle unexpected errors
        return jsonify({"error": str(e)}), 500


@app.route('/verify', methods=['POST'])
def verify():
    try:
        # Get the data from the request
        data = request.get_json()

        # Check if the required fields are present in the request
        if 'id_number' not in data or 'id_hash' not in data:
            return jsonify({"error": "ID number and ID hash are required"}), 400
        
        # Call the blockchain verification function
        result = verify_id_on_blockchain(data['id_number'], data['id_hash'])
        
        # Return the result as a response
        return jsonify({"verified": result})
    
    except Exception as e:
        # Handle unexpected errors
        return jsonify({"error": str(e)}), 500


@app.route('/generate-token', methods=['POST'])
def generate_auth_token():
    try:
        # Get the data from the request
        data = request.get_json()

        # Check if 'id_number' is present in the request
        if 'id_number' not in data:
            return jsonify({"error": "ID number is required"}), 400
        
        # Generate the token
        token = generate_token(data['id_number'])

        # Return the generated token as a response
        return jsonify({"token": token})
    
    except Exception as e:
        # Handle unexpected errors
        return jsonify({"error": str(e)}), 500


@app.route('/authenticate', methods=['POST'])
def authenticate():
    try:
        # Get the data from the request
        data = request.get_json()

        # Check if 'token' is present in the request
        if 'token' not in data:
            return jsonify({"error": "Token is required"}), 400
        
        # Verify the token
        verified = verify_token(data['token'])

        # Return the verification result
        return jsonify({"authenticated": verified})
    
    except Exception as e:
        # Handle unexpected errors
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Start the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
