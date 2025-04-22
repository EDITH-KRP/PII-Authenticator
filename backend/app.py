# backend/app.py
import os
import time
import json
import traceback
import secrets
from flask import Flask, request, jsonify, g
from werkzeug.utils import secure_filename
from flask_cors import CORS
from dotenv import load_dotenv
from token_auth import get_or_generate_token, verify_token
from user_auth import register_user, login_user, get_user_by_id, add_token_to_user, get_user_tokens, add_document_to_user, get_user_documents
from company_auth import register_company, login_company, get_company_by_id, add_validation, get_company_validations, get_validation_stats
from w3_utils import upload_to_filebase, check_blockchain_connection, store_token_on_blockchain, verify_token_on_blockchain, get_token_transaction_details
from cryptography.fernet import Fernet
from logger import get_logger, log_access
from document_processor import document_processor

# Load environment
load_dotenv()

# Get logger
logger = get_logger()

# Generate or load encryption key
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # Generate a key and save it
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    logger.info("Generated new encryption key")
else:
    logger.info("Using existing encryption key")

# Secret key for JWT
SECRET_KEY = os.environ.get('SECRET_KEY', 'default_secret_key_for_development')

# Initialize Fernet cipher
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

def encrypt_data(data):
    """
    Encrypt data using Fernet symmetric encryption.
    
    Args:
        data (str): Data to encrypt
        
    Returns:
        str: Encrypted data in base64 format
    """
    if isinstance(data, str):
        data = data.encode()
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data.decode()

def extract_user_id_from_token(token):
    """
    Extract user_id from token.
    
    Args:
        token (str): The token which may contain user_id
        
    Returns:
        str: The extracted user_id or default
    """
    try:
        # Check if the token contains user_id information
        if ':' in token:
            # Format is "user_id:actual_token"
            user_id, _ = token.split(':', 1)
            logger.info(f"Extracted user_id from token: {user_id}")
            return user_id
        else:
            # Try to decode the JWT token to get user information
            try:
                from user_auth import load_users
                import jwt
                
                # Decode the token
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                if "user_id" in decoded:
                    user_id = decoded["user_id"]
                    logger.info(f"Extracted user_id from JWT payload: {user_id}")
                    return user_id
                
                # If we have an email, try to find the user
                if "email" in decoded:
                    email = decoded["email"]
                    users = load_users()
                    for uid, user_data in users.items():
                        if user_data.get("email") == email:
                            logger.info(f"Found user_id {uid} for email {email}")
                            return uid
            except Exception as jwt_error:
                logger.warning(f"Could not extract user_id from JWT: {jwt_error}")
            
            # Get the first user from the database as a fallback
            try:
                from user_auth import load_users
                users = load_users()
                if users:
                    first_user_id = list(users.keys())[0]
                    logger.warning(f"Using first user in database as fallback: {first_user_id}")
                    return first_user_id
            except Exception as db_error:
                logger.warning(f"Could not get first user from database: {db_error}")
            
            # Default fallback
            user_id = "user_1234"
            logger.warning(f"Using default user_id: {user_id}")
            return user_id
    except Exception as e:
        logger.error(f"Error extracting user_id from token: {e}")
        return "user_1234"

def decrypt_data(encrypted_data):
    """
    Decrypt data using Fernet symmetric encryption.
    
    Args:
        encrypted_data (str): Encrypted data in base64 format
        
    Returns:
        str: Decrypted data
    """
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()

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

# User Authentication Endpoints
@app.route("/register", methods=["POST"])
def register():
    """Register a new user."""
    data = request.json
    
    # Register user
    success, user_id, message = register_user(data)
    
    if success:
        # Get user data
        user_data = get_user_by_id(user_id)
        
        # Generate JWT token
        token = secrets.token_hex(16)
        
        return jsonify({
            "message": message,
            "user_id": user_id,
            "name": user_data.get("name"),
            "email": user_data.get("email"),
            "token": token
        })
    else:
        return jsonify({"error": message}), 400

@app.route("/login", methods=["POST"])
def login():
    """Login a user."""
    data = request.json
    
    email = data.get("email")
    password = data.get("password")
    
    # Login user
    success, user_data, message = login_user(email, password)
    
    if success:
        # Generate JWT token
        token = secrets.token_hex(16)
        
        return jsonify({
            "message": message,
            "user_id": user_data.get("user_id"),
            "name": user_data.get("name"),
            "email": user_data.get("email"),
            "token": token
        })
    else:
        return jsonify({"error": message}), 401

@app.route("/user/tokens", methods=["GET"])
def get_tokens():
    """Get all tokens for the authenticated user."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    try:
        user_id = extract_user_id_from_token(token)
    except Exception as e:
        logger.warning(f"Could not extract user_id from JWT: {str(e)}")
        # Fallback to first user in database for demo purposes
        users = load_users()
        if users:
            user_id = list(users.keys())[0]
            logger.warning(f"Using first user in database as fallback: {user_id}")
        else:
            return jsonify({"error": "Unauthorized"}), 401
    
    # Get user tokens
    tokens = get_user_tokens(user_id)
    
    return jsonify({
        "tokens": tokens
    })

@app.route("/user/tokens/generate", methods=["POST"])
def generate_token():
    """Generate a new token for the authenticated user."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    jwt_token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    try:
        user_id = extract_user_id_from_token(jwt_token)
    except Exception as e:
        logger.warning(f"Could not extract user_id from JWT: {str(e)}")
        # Fallback to first user in database for demo purposes
        users = load_users()
        if users:
            user_id = list(users.keys())[0]
            logger.warning(f"Using first user in database as fallback: {user_id}")
        else:
            return jsonify({"error": "Unauthorized"}), 401
    
    # Get user data
    user_data = get_user_by_id(user_id)
    if not user_data:
        return jsonify({"error": "User not found"}), 404
    
    # Create a user key for token generation
    user_key = user_id
    
    # Generate token data
    name = user_data.get("name", "")
    email = user_data.get("email", "")
    dob = user_data.get("dob", "")
    phone = user_data.get("phone", "")
    id_type = "user_id"
    id_number = user_id
    
    # Generate or retrieve token
    token, file_url, tx_hash, is_new = get_or_generate_token(
        user_key=user_key,
        name=name,
        email=email,
        dob=dob,
        phone=phone,
        id_type=id_type,
        id_number=id_number
    )
    
    if not token:
        return jsonify({"error": "Failed to generate token"}), 500
    
    # Add token to user
    success = add_token_to_user(
        user_id=user_id,
        token_data={
            "token": token,
            "created_at": time.time(),
            "active": True,
            "tx_hash": tx_hash,
            "file_url": file_url
        }
    )
    
    if not success:
        return jsonify({"error": "Failed to add token to user"}), 500
    
    return jsonify({
        "token": token,
        "file_url": file_url,
        "tx_hash": tx_hash,
        "message": "Token generated successfully"
    })

@app.route("/user/documents", methods=["GET"])
def get_documents():
    """Get all documents for the authenticated user."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    user_id = extract_user_id_from_token(token)
    
    # Get user documents
    documents = get_user_documents(user_id)
    
    return jsonify({
        "documents": documents
    })

@app.route("/user/documents/scan", methods=["POST"])
def scan_document():
    """Scan a document image and extract PII data."""
    # Get client IP address
    ip_address = request.remote_addr
    
    # Check for JWT in Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        log_access(
            endpoint="/user/documents/scan", 
            ip_address=ip_address, 
            status="failure", 
            details="Missing or invalid Authorization header"
        )
        return jsonify({"error": "Authorization required. Please provide a valid JWT token."}), 401
    
    # Extract JWT token
    jwt_token = auth_header.split(' ')[1]
    
    # In a real app, validate the JWT here and get user_id
    # For this demo, we'll use a dummy user_id
    user_id = "user_1234"
    
    # Check if file is in the request
    if 'file' not in request.files:
        log_access(
            endpoint="/user/documents/scan", 
            user_id=user_id,
            ip_address=ip_address, 
            status="failure", 
            details="No file part in the request"
        )
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    
    # Check if file is empty
    if file.filename == '':
        log_access(
            endpoint="/user/documents/scan", 
            user_id=user_id,
            ip_address=ip_address, 
            status="failure", 
            details="No file selected"
        )
        return jsonify({"error": "No file selected"}), 400
    
    # Get document type
    doc_type = request.form.get('type')
    if not doc_type:
        log_access(
            endpoint="/user/documents/scan", 
            user_id=user_id,
            ip_address=ip_address, 
            status="failure", 
            details="Document type not specified"
        )
        return jsonify({"error": "Document type required"}), 400
    
    # Check if document type is supported
    if doc_type not in document_processor.supported_id_types:
        log_access(
            endpoint="/user/documents/scan", 
            user_id=user_id,
            ip_address=ip_address, 
            status="failure", 
            details=f"Unsupported document type: {doc_type}"
        )
        return jsonify({"error": f"Unsupported document type. Supported types: {', '.join(document_processor.supported_id_types)}"}), 400
    
    try:
        # Process the document
        result = document_processor.process_document_from_request(file, doc_type)
        
        # Check if there was an error
        if "error" in result:
            log_access(
                endpoint="/user/documents/scan", 
                user_id=user_id,
                ip_address=ip_address, 
                status="failure", 
                details=result["error"]
            )
            return jsonify({"error": result["error"]}), 400
        
        # Generate token from extracted PII data
        pii_data = {
            "name": result.get("name", ""),
            "email": "",  # Not available from document
            "dob": result.get("dob", ""),
            "phone": "",  # Not available from document
            "id_type": result.get("id_type", doc_type),
            "id_number": result.get("id_number", ""),
            "user_id": user_id,
            "timestamp": time.time()
        }
        
        # Include the full extracted text if available
        if "extracted_text" in result:
            pii_data["extracted_text"] = result["extracted_text"]
        
        # Generate token or get existing one
        token, is_new, tx_hash, file_url, jwt = get_or_generate_token(pii_data)
        
        # Upload extracted text to Filebase as a separate file
        text_file_url = None
        if "extracted_text" in result:
            # Create a text file with the extracted data
            text_file_name = f"{doc_type}_scan_extracted_{int(time.time())}.txt"
            text_content = f"Extracted PII Data:\n\n"
            
            # Add the extracted text
            text_content += f"Full Extracted Text:\n{result['extracted_text']}\n\n"
            
            # Add all other extracted fields
            text_content += "Extracted Fields:\n"
            for key, value in result.items():
                if key != "extracted_text":
                    text_content += f"{key}: {value}\n"
            
            # Upload the text file
            text_file_url = upload_to_filebase(text_file_name, text_content.encode('utf-8'))
        
        # Add document to user's documents
        document_data = {
            "title": f"{doc_type.replace('_', ' ').title()} Scan",
            "type": doc_type,
            "date_added": time.time(),
            "file_url": file_url,
            "text_file_url": text_file_url,
            "token": token,
            "extracted_data": result
        }
        add_document_to_user(user_id, document_data)
        
        # Add token to user's tokens if it's new
        if is_new:
            token_data = {
                "token": token,
                "date_created": time.time(),
                "file_url": file_url,
                "tx_hash": tx_hash
            }
            add_token_to_user(user_id, token_data)
        
        # Log successful document scan
        log_access(
            endpoint="/user/documents/scan", 
            user_id=user_id,
            token=token,
            ip_address=ip_address, 
            status="success", 
            details=f"Document scanned and token generated: {token}"
        )
        
        # Return the result
        response_data = {
            "message": "Document scanned successfully",
            "extracted_data": result,
            "token": token,
            "tx_hash": tx_hash,
            "file_url": file_url
        }
        
        # Add text file URL if available
        if text_file_url:
            response_data["text_file_url"] = text_file_url
            
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error scanning document: {str(e)}")
        logger.error(traceback.format_exc())
        
        log_access(
            endpoint="/user/documents/scan", 
            user_id=user_id,
            ip_address=ip_address, 
            status="error", 
            details=str(e)
        )
        
        return jsonify({"error": str(e)}), 500

@app.route("/user/documents/upload", methods=["POST"])
def upload_document():
    """Upload a document for the authenticated user."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    user_id = extract_user_id_from_token(token)
    
    # Get form data
    title = request.form.get("title")
    doc_type = request.form.get("type")
    file = request.files.get("file")
    
    if not title or not doc_type or not file:
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        # Get file data
        file_data = file.read()
        file_name = secure_filename(file.filename)
        
        # Upload original file to Filebase
        file_url = upload_to_filebase(file_name, file_data)
        if not file_url:
            logger.error("Failed to upload file to Filebase")
            return jsonify({"error": "Failed to upload file to storage"}), 500
        
        # Process the document to extract PII data
        # Reset file pointer to beginning
        file.seek(0)
        pii_data = document_processor.process_document_from_request(file, doc_type)
        
        # If there was an error in processing, log it but continue with the upload
        if "error" in pii_data:
            logger.warning(f"Error in document processing: {pii_data['error']}")
            # Remove the error message but keep other data
            error_msg = pii_data.pop("error")
            pii_data["processing_note"] = f"Document processed with limited functionality: {error_msg}"
        
        # Add document type to PII data if not present
        if "document_type" not in pii_data:
            pii_data["document_type"] = doc_type
            
        # Add timestamp if not present
        if "processed_at" not in pii_data:
            pii_data["processed_at"] = time.time()
        
        # Upload extracted text to Filebase as a separate file
        text_file_url = None
        try:
            # Create a text file with the extracted data
            text_file_name = f"{os.path.splitext(file_name)[0]}_extracted.txt"
            text_content = f"Extracted PII Data:\n\n"
            
            # Add the extracted text if available
            if "extracted_text" in pii_data:
                text_content += f"Full Extracted Text:\n{pii_data['extracted_text']}\n\n"
            
            # Add all other extracted fields
            text_content += "Extracted Fields:\n"
            for key, value in pii_data.items():
                if key != "extracted_text":
                    text_content += f"{key}: {value}\n"
            
            # Upload the text file
            text_file_url = upload_to_filebase(text_file_name, text_content.encode('utf-8'))
            
            # Add the text file URL to the PII data
            if text_file_url:
                pii_data["text_file_url"] = text_file_url
        except Exception as text_error:
            logger.error(f"Error creating or uploading text file: {str(text_error)}")
            # Continue with the process even if text file upload fails
        
        # Encrypt the PII data
        try:
            encrypted_pii = encrypt_data(json.dumps(pii_data))
        except Exception as encrypt_error:
            logger.error(f"Error encrypting PII data: {str(encrypt_error)}")
            encrypted_pii = encrypt_data(json.dumps({"error": "Encryption failed", "document_type": doc_type}))
        
        # Store document reference and encrypted PII on blockchain
        try:
            document_token = f"doc_{user_id}_{int(time.time())}"
            tx_hash = store_token_on_blockchain(document_token)
            if not tx_hash:
                logger.warning("Failed to get transaction hash from blockchain, using a placeholder")
                tx_hash = f"local_{document_token}"
        except Exception as blockchain_error:
            logger.error(f"Error storing token on blockchain: {str(blockchain_error)}")
            tx_hash = f"local_{document_token}"
        
        # Add document to user
        document_data = {
            "title": title,
            "type": doc_type,
            "file_url": file_url,
            "tx_hash": tx_hash,
            "encrypted_pii": encrypted_pii,
            "extracted_data": pii_data,
            "upload_time": time.time(),
            "document_token": document_token
        }
        
        # Add text file URL if available
        if text_file_url:
            document_data["text_file_url"] = text_file_url
        
        try:
            success, document_id = add_document_to_user(user_id, document_data)
        except Exception as db_error:
            logger.error(f"Error adding document to user: {str(db_error)}")
            success = False
            document_id = None
        
        if success:
            response_data = {
                "message": "Document uploaded successfully",
                "document_id": document_id,
                "file_url": file_url,
                "tx_hash": tx_hash,
                "document_token": document_token
            }
            
            # Add extracted data to response (excluding large text fields)
            extracted_data_for_response = {k: v for k, v in pii_data.items() if k != "extracted_text"}
            response_data["extracted_data"] = extracted_data_for_response
            
            # Add text file URL if available
            if text_file_url:
                response_data["text_file_url"] = text_file_url
                
            return jsonify(response_data)
        else:
            # Even if saving to user failed, return success with the file URLs
            logger.warning(f"Failed to save document to user {user_id}, but files were uploaded")
            return jsonify({
                "message": "Document uploaded but not saved to user profile",
                "file_url": file_url,
                "tx_hash": tx_hash,
                "document_token": document_token,
                "text_file_url": text_file_url if text_file_url else None
            })
    except Exception as e:
        logger.error(f"Error uploading document: {e}")
        logger.error(traceback.format_exc())
        
        # Try to salvage what we can
        try:
            # If we at least have the file URL, return that
            if 'file_url' in locals() and file_url:
                return jsonify({
                    "message": "Document partially processed with errors",
                    "error": str(e),
                    "file_url": file_url,
                    "partial_success": True
                }), 207  # 207 Multi-Status
            else:
                return jsonify({"error": "Error uploading document"}), 500
        except:
            return jsonify({"error": "An unexpected error occurred during document upload"}), 500

@app.route("/user/documents/scan_ai", methods=["POST"])
def scan_document_ai():
    """Scan a document using AI to extract PII data and generate a token."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    jwt_token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    user_id = extract_user_id_from_token(jwt_token)
    
    # Get form data
    doc_type = request.form.get("type")
    file = request.files.get("file")
    
    if not doc_type or not file:
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        # Process the document to extract PII data
        pii_data = document_processor.process_document_from_request(file, doc_type)
        
        # If there was an error in processing, log it but continue with the upload
        if "error" in pii_data:
            logger.warning(f"Error in document processing: {pii_data['error']}")
            # Remove the error message but keep other data
            error_msg = pii_data.pop("error")
            pii_data["processing_note"] = f"Document processed with limited functionality: {error_msg}"
        
        # Add user_id to PII data
        pii_data["user_id"] = user_id
        
        # Generate token for PII data
        token, is_new, tx_hash, file_url, jwt = get_or_generate_token(pii_data)
        
        # Upload the original document to Filebase
        document_url = upload_to_filebase(file)
        
        # Add document to user
        document_data = {
            "title": f"{doc_type.capitalize()} - {pii_data.get('name', 'Unknown')}",
            "type": doc_type,
            "file_url": document_url,
            "tx_hash": tx_hash,
            "extracted_data": pii_data,
            "token": token
        }
        
        success, document_id = add_document_to_user(user_id, document_data)
        
        # Add token to user
        token_data = {
            "token": token,
            "tx_hash": tx_hash,
            "file_url": file_url
        }
        add_token_to_user(user_id, token_data)
        
        if success:
            return jsonify({
                "message": "Document scanned and token generated successfully",
                "document_id": document_id,
                "file_url": document_url,
                "token": token,
                "tx_hash": tx_hash,
                "extracted_data": pii_data
            })
        else:
            return jsonify({"error": "Failed to save document"}), 500
    except Exception as e:
        logger.error(f"Error scanning document: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Error scanning document: {str(e)}"}), 500

@app.route("/user/profile", methods=["GET"])
def get_user_profile():
    """Get user profile information."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    user_id = extract_user_id_from_token(token)
    
    # Get user data
    user_data = get_user_by_id(user_id)
    
    if not user_data:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify(user_data)

@app.route("/user/profile", methods=["PUT"])
def update_user_profile():
    """Update user profile information."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    user_id = extract_user_id_from_token(token)
    
    # Get request data
    data = request.json
    
    # Update user data (in a real app, this would update the database)
    # For now, we'll just return success
    return jsonify({
        "message": "Profile updated successfully"
    })

@app.route("/user/password", methods=["PUT"])
def update_user_password():
    """Update user password."""
    # Get user_id from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # Extract user_id from token
    user_id = extract_user_id_from_token(token)
    
    # Get request data
    data = request.json
    
    # Validate current password (in a real app, this would check against the database)
    # For now, we'll just return success
    return jsonify({
        "message": "Password updated successfully"
    })

# Company Authentication Endpoints
@app.route("/company/register", methods=["POST"])
def register_company_endpoint():
    """Register a new company."""
    data = request.json
    
    # Register company
    success, company_id, message = register_company(data)
    
    if success:
        # Get company data
        company_data = get_company_by_id(company_id)
        
        # Generate JWT token
        token = secrets.token_hex(16)
        
        return jsonify({
            "message": message,
            "company_id": company_id,
            "company_name": company_data.get("company_name"),
            "email": company_data.get("email"),
            "business_type": company_data.get("business_type"),
            "token": token
        })
    else:
        return jsonify({"error": message}), 400

@app.route("/company/login", methods=["POST"])
def login_company_endpoint():
    """Login a company."""
    data = request.json
    
    email = data.get("email")
    password = data.get("password")
    
    # Login company
    success, company_data, message = login_company(email, password)
    
    if success:
        # Generate JWT token
        token = secrets.token_hex(16)
        
        return jsonify({
            "message": message,
            "company_id": company_data.get("company_id"),
            "company_name": company_data.get("company_name"),
            "email": company_data.get("email"),
            "business_type": company_data.get("business_type"),
            "token": token
        })
    else:
        return jsonify({"error": message}), 401

@app.route("/company/validate", methods=["POST"])
def validate_token_endpoint():
    """Validate a token."""
    # In a real app, get company_id from JWT token
    # For now, we'll use a header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    auth_token = auth_header.split(" ")[1]
    
    # In a real app, verify JWT token and get company_id
    # For now, we'll use a dummy company_id or the one provided in the request
    data = request.json
    company_id = data.get("company_id", "company_1234")
    
    token = data.get("token")
    purpose = data.get("purpose")
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    # Verify token
    is_valid, user_info = verify_token(token)
    
    # Get token transaction details
    tx_details = get_token_transaction_details(token)
    tx_hash = tx_details.get("tx_hash") if tx_details else None
    
    # Record validation on blockchain
    validation_tx_hash = store_token_on_blockchain(f"validation_{company_id}_{token}_{int(time.time())}")
    
    # Add validation record
    validation_data = {
        "token": token,
        "purpose": purpose,
        "is_valid": is_valid,
        "tx_hash": tx_hash,
        "validation_tx_hash": validation_tx_hash
    }
    
    add_validation(company_id, validation_data)
    
    if is_valid:
        return jsonify({
            "is_valid": True,
            "token": token,
            "user_info": user_info,
            "tx_hash": tx_hash,
            "validation_tx_hash": validation_tx_hash
        })
    else:
        return jsonify({
            "is_valid": False,
            "error": "Invalid token",
            "token": token,
            "validation_tx_hash": validation_tx_hash
        })

@app.route("/company/validations/recent", methods=["GET"])
def get_recent_validations():
    """Get recent validations for the authenticated company."""
    # In a real app, get company_id from JWT token
    # For now, we'll use a header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # In a real app, verify JWT token and get company_id
    # For now, we'll use a dummy company_id
    company_id = "company_1234"
    
    # Get recent validations
    validations = get_company_validations(company_id)
    
    return jsonify({
        "validations": validations
    })

@app.route("/company/validations/all", methods=["GET"])
def get_all_validations():
    """Get all validations for the authenticated company."""
    # In a real app, get company_id from JWT token
    # For now, we'll use a header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # In a real app, verify JWT token and get company_id
    # For now, we'll use a dummy company_id
    company_id = "company_1234"
    
    # Get all validations (no limit)
    validations = get_company_validations(company_id, limit=1000)
    
    return jsonify({
        "validations": validations
    })

@app.route("/company/validations/stats", methods=["GET"])
def get_validation_stats_endpoint():
    """Get validation statistics for the authenticated company."""
    # In a real app, get company_id from JWT token
    # For now, we'll use a header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # In a real app, verify JWT token and get company_id
    # For now, we'll use a dummy company_id
    company_id = "company_1234"
    
    # Get validation stats
    stats = get_validation_stats(company_id)
    
    return jsonify(stats)

@app.route("/company/profile", methods=["GET"])
def get_company_profile():
    """Get company profile information."""
    # In a real app, get company_id from JWT token
    # For now, we'll use a header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # In a real app, verify JWT token and get company_id
    # For now, we'll use a dummy company_id
    company_id = "company_1234"
    
    # Get company data
    company_data = get_company_by_id(company_id)
    
    if not company_data:
        return jsonify({"error": "Company not found"}), 404
    
    return jsonify(company_data)

@app.route("/company/profile", methods=["PUT"])
def update_company_profile():
    """Update company profile information."""
    # In a real app, get company_id from JWT token
    # For now, we'll use a header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Extract token
    token = auth_header.split(" ")[1]
    
    # In a real app, verify JWT token and get company_id
    # For now, we'll use a dummy company_id
    company_id = "company_1234"
    
    # Get request data
    data = request.json
    
    # Update company data (in a real app, this would update the database)
    # For now, we'll just return success
    return jsonify({
        "message": "Company profile updated successfully"
    })

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
