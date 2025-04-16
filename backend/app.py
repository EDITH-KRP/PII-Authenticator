# backend/app.py
import os
import time
import json
import traceback
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from token_auth import get_or_generate_token, verify_token
from w3_utils import upload_to_filebase
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
    user_id = data.get("user_id")
    
    # Extract all PII fields
    name = data.get("name")
    email = data.get("email")
    dob = data.get("dob")
    phone = data.get("phone")
    id_type = data.get("id_type")
    id_number = data.get("id_number")

    # Check for required fields
    if not user_id or not id_number or not name:
        log_access(
            endpoint="/encrypt", 
            user_id=user_id, 
            ip_address=ip_address, 
            status="failure", 
            details="Missing required fields"
        )
        return jsonify({"error": "Missing required fields (user_id, name, id_number)"}), 400

    try:
        # Format PII data as JSON for checking existing tokens
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
        token, is_new = get_or_generate_token(user_id, pii_data)
        
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
                "file_url": f"https://s3.filebase.com/pii-authenticator-test/{token}.json",
                "message": "Existing token retrieved. Only one token is allowed per user."
            })
        
        # Convert to JSON string
        pii_json = json.dumps(pii_data, indent=2)
        
        # Upload to filebase
        file_url = upload_to_filebase(f"{token}.json", pii_json.encode())

        if not file_url:
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
            details=f"Token generated and data stored at {file_url}"
        )
        
        return jsonify({
            "token": token,
            "file_url": file_url
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
        valid = verify_token(token)
        
        # Log token validation attempt
        log_access(
            endpoint="/validate_token", 
            token=token, 
            ip_address=ip_address, 
            status="success" if valid else "invalid", 
            details=f"Token validation {'successful' if valid else 'failed'}"
        )
        
        return jsonify({"valid": valid})
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

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "timestamp": time.time()})

if __name__ == "__main__":
    logger.info("Starting PII Authenticator backend server")
    app.run(debug=True)
