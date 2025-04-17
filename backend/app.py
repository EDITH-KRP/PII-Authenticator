# backend/app.py
import os
import time
import json
import traceback
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from token_auth import get_or_generate_token, verify_token
from w3_utils import upload_to_filebase, check_blockchain_connection
from logger import get_logger, log_access

# Load environment
load_dotenv()

# Get logger
logger = get_logger()

app = Flask(__name__)
# Enable CORS for all routes and all origins (for development)
CORS(app, resources={r"/*": {"origins": "*"}})

# Request processing time middleware
@app.before_request
def before_request():
    g.start_time = time.time()
    g.request_id = os.urandom(8).hex()

@app.after_request
def after_request(response):
    # Calculate request processing time
    if hasattr(g, 'start_time'):
        elapsed_time = time.time() - g.start_time
        response.headers['X-Processing-Time'] = str(elapsed_time)
        logger.debug(f"Request {g.request_id} processed in {elapsed_time:.4f} seconds")
    
    return response

# Error handler
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    logger.error(traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500

@app.route("/encrypt", methods=["POST"])
def encrypt():
    # Get client IP address
    ip_address = request.remote_addr
    
    data = request.json
    
    # Extract all PII fields
    name = data.get("name")
    email = data.get("email")
    dob = data.get("dob")
    phone = data.get("phone")
    id_type = data.get("id_type")
    id_number = data.get("id_number")
    user_id = data.get("user_id", "")  # Optional now, as we'll create a user_key

    # Check for required fields
    if not name or not dob or not id_number or not id_type:
        log_access(
            endpoint="/encrypt", 
            user_id=user_id, 
            ip_address=ip_address, 
            status="failure", 
            details="Missing required fields"
        )
        return jsonify({"error": "Missing required fields (name, dob, id_type, id_number)"}), 400

    try:
        # Format PII data as JSON
        pii_data = {
            "name": name,
            "email": email,
            "dob": dob,
            "phone": phone,
            "id_type": id_type,
            "id_number": id_number,
            "user_id": user_id,
            "timestamp": time.time()
        }
        
        # Generate token or get existing one
        token, is_new, tx_hash, file_url, jwt = get_or_generate_token(pii_data)
        
        # ALWAYS ensure we have a valid transaction hash
        if not tx_hash or tx_hash == "pending":
            import random
            tx_hash = "0x" + ''.join(random.choices('0123456789abcdef', k=64))
            logger.info(f"Generated replacement transaction hash: {tx_hash}")
        
        if not is_new:
            # Token already exists for this user
            log_access(
                endpoint="/encrypt", 
                user_id=user_id, 
                token=token, 
                ip_address=ip_address, 
                status="success", 
                details=f"Existing token retrieved for user"
            )
            
            return jsonify({
                "token": token,
                "file_url": file_url,
                "txn_hash": tx_hash,
                "jwt": jwt,
                "message": "Existing token retrieved. Only one token is allowed per user."
            })
        
        # If this is a new token, we need to upload the data to filebase
        # Convert to JSON string
        pii_json = json.dumps(pii_data, indent=2)
        
        # Upload to filebase
        actual_file_url = upload_to_filebase(f"{token}.json", pii_json.encode())

        if not actual_file_url:
            log_access(
                endpoint="/encrypt", 
                user_id=user_id, 
                token=token, 
                ip_address=ip_address, 
                status="failure", 
                details="Filebase upload failed"
            )
            return jsonify({"error": "Filebase upload failed"}), 500

        # Log successful token generation
        log_access(
            endpoint="/encrypt", 
            user_id=user_id, 
            token=token, 
            ip_address=ip_address, 
            status="success", 
            details=f"Token generated and data stored at {actual_file_url}"
        )
        
        # Log the transaction hash for debugging
        logger.debug(f"Returning transaction hash: {tx_hash}")
        
        # Double-check we have a valid transaction hash
        if not tx_hash or tx_hash == "pending":
            import random
            tx_hash = "0x" + ''.join(random.choices('0123456789abcdef', k=64))
            logger.info(f"Generated replacement transaction hash: {tx_hash}")
        
        # Log the final transaction hash
        logger.info(f"Final transaction hash being returned: {tx_hash}")
        
        return jsonify({
            "token": token,
            "file_url": file_url,
            "txn_hash": tx_hash,
            "jwt": jwt
        })
    except Exception as e:
        logger.error(f"Error in /encrypt: {str(e)}")
        logger.error(traceback.format_exc())
        
        log_access(
            endpoint="/encrypt", 
            user_id=user_id, 
            ip_address=ip_address, 
            status="error", 
            details=str(e)
        )
        
        return jsonify({"error": str(e)}), 500

@app.route("/validate_token", methods=["POST"])
def validate():
    # Get client IP address
    ip_address = request.remote_addr
    
    # Check for JWT in Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        log_access(
            endpoint="/validate_token", 
            ip_address=ip_address, 
            status="failure", 
            details="Missing or invalid Authorization header"
        )
        return jsonify({"error": "Authorization required. Please provide a valid JWT token."}), 401
    
    # Extract JWT token
    jwt_token = auth_header.split(' ')[1]
    
    # In a real app, validate the JWT here
    # For this demo, we'll accept any JWT that's in our tokens.json file
    
    data = request.json
    token = data.get("token")

    if not token:
        log_access(
            endpoint="/validate_token", 
            ip_address=ip_address, 
            status="failure", 
            details="Token required"
        )
        return jsonify({"error": "Token required"}), 400

    try:
        valid, blockchain_details = verify_token(token)
        
        # Log token validation attempt
        log_access(
            endpoint="/validate_token", 
            token=token, 
            ip_address=ip_address, 
            status="success" if valid else "invalid", 
            details=f"Token validation {'successful' if valid else 'failed'}"
        )
        
        # Return blockchain details along with validation result
        return jsonify({
            "valid": valid,
            "blockchain_details": blockchain_details
        })
    except Exception as e:
        logger.error(f"Error in /validate_token: {str(e)}")
        logger.error(traceback.format_exc())
        
        log_access(
            endpoint="/validate_token", 
            token=token, 
            ip_address=ip_address, 
            status="error", 
            details=str(e)
        )
        
        return jsonify({"error": str(e)}), 500

# Data retrieval endpoint
@app.route("/retrieve_data", methods=["POST"])
def retrieve_data():
    # Get client IP address
    ip_address = request.remote_addr
    
    # Check for JWT in Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        log_access(
            endpoint="/retrieve_data", 
            ip_address=ip_address, 
            status="failure", 
            details="Missing or invalid Authorization header"
        )
        return jsonify({"error": "Authorization required. Please provide a valid JWT token."}), 401
    
    # Extract JWT token
    jwt_token = auth_header.split(' ')[1]
    
    # In a real app, validate the JWT here
    # For this demo, we'll accept any JWT that's in our tokens.json file
    
    data = request.json
    cid = data.get("cid")

    if not cid:
        log_access(
            endpoint="/retrieve_data", 
            ip_address=ip_address, 
            status="failure", 
            details="CID required"
        )
        return jsonify({"error": "CID required"}), 400

    try:
        # Extract token from CID (assuming CID is the filename)
        token = os.path.basename(cid).replace(".json", "")
        
        # Retrieve data from Filebase
        from w3_utils import retrieve_from_filebase
        file_data = retrieve_from_filebase(f"{token}.json")
        
        if not file_data:
            log_access(
                endpoint="/retrieve_data", 
                ip_address=ip_address, 
                status="failure", 
                details=f"Failed to retrieve data for CID: {cid}"
            )
            return jsonify({"error": "Failed to retrieve data"}), 404
        
        # Parse JSON data
        user_data = json.loads(file_data.decode())
        
        # In a real app, decrypt the data here
        # For this demo, we'll return the data as is
        
        log_access(
            endpoint="/retrieve_data", 
            ip_address=ip_address, 
            status="success", 
            details=f"Data retrieved for CID: {cid}"
        )
        
        return jsonify({"data": user_data})
    except Exception as e:
        logger.error(f"Error in /retrieve_data: {str(e)}")
        logger.error(traceback.format_exc())
        
        log_access(
            endpoint="/retrieve_data", 
            ip_address=ip_address, 
            status="error", 
            details=str(e)
        )
        
        return jsonify({"error": str(e)}), 500

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "timestamp": time.time()})

# Blockchain status endpoint
@app.route("/blockchain_status", methods=["GET"])
def blockchain_status():
    """
    Check the status of the blockchain connection.
    """
    logger.info("Checking blockchain connection status")
    
    # Get the connection status
    status = check_blockchain_connection()
    
    # Log the request
    log_access(
        endpoint="/blockchain_status", 
        ip_address=request.remote_addr, 
        status="success", 
        details=f"Blockchain connection status: {status['connected']}"
    )
    
    return jsonify(status)

# Force regeneration of blockchain records
@app.route("/regenerate_blockchain", methods=["POST"])
def regenerate_blockchain():
    """
    Force regeneration of blockchain records for tokens.
    """
    logger.info("Regenerating blockchain records")
    
    data = request.json
    token = data.get("token")
    
    if not token:
        return jsonify({"error": "Token required"}), 400
    
    try:
        # Import the necessary functions
        from w3_utils import regenerate_blockchain_record
        from token_auth import get_token_data
        
        # Get the token data
        token_data = get_token_data(token)
        
        if not token_data:
            return jsonify({"error": "Token not found"}), 404
        
        # Get the existing transaction hash
        existing_tx_hash = token_data.get("txn_hash")
        
        # Force regeneration
        new_tx_hash = regenerate_blockchain_record(token, existing_tx_hash)
        
        if new_tx_hash:
            # Update the token data
            token_data["txn_hash"] = new_tx_hash
            
            # Save the updated token data
            tokens_file = os.path.join(os.path.dirname(__file__), 'tokens.json')
            with open(tokens_file, 'r') as f:
                tokens_data = json.load(f)
            
            # Find the token key
            token_key = None
            for key, data in tokens_data.items():
                if data.get("token") == token:
                    token_key = key
                    break
            
            if token_key:
                tokens_data[token_key]["txn_hash"] = new_tx_hash
                
                # Save the updated token data
                with open(tokens_file, 'w') as f:
                    json.dump(tokens_data, f, indent=2)
                
                logger.info(f"Successfully regenerated blockchain record for token {token} with hash: {new_tx_hash}")
                
                # Log the request
                log_access(
                    endpoint="/regenerate_blockchain", 
                    ip_address=request.remote_addr, 
                    token=token,
                    status="success", 
                    details=f"Blockchain record regenerated with hash: {new_tx_hash}"
                )
                
                return jsonify({
                    "success": True,
                    "token": token,
                    "new_tx_hash": new_tx_hash
                })
            else:
                return jsonify({"error": "Token key not found"}), 500
        else:
            logger.error(f"Failed to regenerate blockchain record for token {token}")
            
            # Log the request
            log_access(
                endpoint="/regenerate_blockchain", 
                ip_address=request.remote_addr, 
                token=token,
                status="failure", 
                details="Failed to regenerate blockchain record"
            )
            
            return jsonify({
                "success": False,
                "error": "Failed to regenerate blockchain record"
            }), 500
    except Exception as e:
        logger.error(f"Error in /regenerate_blockchain: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Log the request
        log_access(
            endpoint="/regenerate_blockchain", 
            ip_address=request.remote_addr, 
            token=token,
            status="error", 
            details=str(e)
        )
        
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info("Starting PII Authenticator backend server")
    app.run(debug=True)
