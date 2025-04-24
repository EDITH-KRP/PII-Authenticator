# backend/user_auth.py
import os
import json
import time
import hashlib
import secrets
from logger import get_logger

# Get logger
logger = get_logger()

# Path to data directory and users.json file
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

def load_users():
    """
    Load users from the users.json file.
    
    Returns:
        dict: Dictionary of users, or empty dict if file doesn't exist or is invalid
    """
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
            logger.debug(f"Loaded {len(users)} existing users from {USERS_FILE}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing users file: {e}")
            # Create a backup of the corrupted file
            backup_file = f"{USERS_FILE}.bak.{int(time.time())}"
            try:
                import shutil
                shutil.copy2(USERS_FILE, backup_file)
                logger.info(f"Created backup of corrupted users file: {backup_file}")
            except Exception as backup_err:
                logger.error(f"Failed to create backup of corrupted users file: {backup_err}")
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
    else:
        logger.info(f"Users file not found at {USERS_FILE}. Will create new users database when needed.")
    
    return users

def save_users(users):
    """
    Save users to the users.json file.
    
    Args:
        users (dict): Dictionary of users to save
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Ensure data directory exists
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        logger.debug(f"Saved {len(users)} users to {USERS_FILE}")
        return True
    except Exception as e:
        logger.error(f"Error saving users to {USERS_FILE}: {e}")
        return False

def hash_password(password, salt=None):
    """
    Hash a password with a salt using PBKDF2.
    
    Args:
        password (str): The password to hash
        salt (str, optional): The salt to use. If None, a new salt is generated.
        
    Returns:
        tuple: (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    # In a production environment, use a proper password hashing library
    # This is a simplified version for demonstration
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    
    return key, salt

def register_user(user_data):
    """
    Register a new user.
    
    Args:
        user_data (dict): User data containing name, email, phone, dob, and password
        
    Returns:
        tuple: (success, user_id, message)
    """
    logger.info(f"Registering new user: {user_data.get('email')}")
    
    name = user_data.get("name", "").strip()
    email = user_data.get("email", "").strip().lower()
    phone = user_data.get("phone", "").strip()
    dob = user_data.get("dob", "").strip()
    password = user_data.get("password", "")
    
    # Validate required fields
    if not name or not email or not password:
        logger.warning("Missing required fields for user registration")
        return False, None, "Missing required fields (name, email, password)"
    
    # Load existing users
    users = load_users()
    
    # Check if email already exists
    for user_id, user in users.items():
        if user.get("email") == email:
            logger.warning(f"User with email {email} already exists")
            return False, None, "Email already registered"
    
    # Generate user ID
    user_id = f"user_{int(time.time())}_{secrets.token_hex(4)}"
    
    # Hash password
    hashed_password, salt = hash_password(password)
    
    # Create user object
    user = {
        "id": user_id,
        "name": name,
        "email": email,
        "phone": phone,
        "dob": dob,
        "password_hash": hashed_password,
        "password_salt": salt,
        "created_at": time.time(),
        "tokens": [],
        "documents": []
    }
    
    # Save user
    users[user_id] = user
    
    if save_users(users):
        logger.info(f"User {user_id} registered successfully")
        return True, user_id, "User registered successfully"
    else:
        logger.error(f"Error saving user {user_id}")
        return False, None, "Error saving user"

def generate_login_nonce(user_id):
    """
    Generate a unique nonce for login challenge.
    
    Args:
        user_id (str): User ID
        
    Returns:
        str: Nonce value
        int: Expiration timestamp
    """
    import secrets
    import time
    
    # Generate a random nonce
    nonce = secrets.token_hex(16)
    
    # Set expiration time (5 minutes from now)
    expiration = int(time.time()) + 300
    
    # Load existing users
    users = load_users()
    if not users or user_id not in users:
        return None, None
    
    # Store nonce in user data
    if "login_nonces" not in users[user_id]:
        users[user_id]["login_nonces"] = {}
    
    users[user_id]["login_nonces"][nonce] = expiration
    
    # Clean up expired nonces
    current_time = int(time.time())
    expired_nonces = [n for n, exp in users[user_id]["login_nonces"].items() if exp < current_time]
    for expired in expired_nonces:
        del users[user_id]["login_nonces"][expired]
    
    # Save updated user data
    save_users(users)
    
    logger.info(f"Generated login nonce for user {user_id}: {nonce}")
    return nonce, expiration

def verify_login_nonce(user_id, nonce):
    """
    Verify a login nonce.
    
    Args:
        user_id (str): User ID
        nonce (str): Nonce to verify
        
    Returns:
        bool: True if nonce is valid, False otherwise
    """
    import time
    
    # Load existing users
    users = load_users()
    if not users or user_id not in users:
        return False
    
    # Check if user has nonces
    if "login_nonces" not in users[user_id]:
        return False
    
    # Check if nonce exists and is not expired
    current_time = int(time.time())
    if nonce in users[user_id]["login_nonces"]:
        expiration = users[user_id]["login_nonces"][nonce]
        if current_time <= expiration:
            # Remove the nonce after use (one-time use)
            del users[user_id]["login_nonces"][nonce]
            save_users(users)
            return True
    
    return False

def login_user(email, password):
    """
    Login a user.
    
    Args:
        email (str): User email
        password (str): User password
        
    Returns:
        tuple: (success, user_data, message)
    """
    logger.info(f"Login attempt for user: {email}")
    
    email = email.strip().lower()
    
    # Load existing users
    users = load_users()
    if not users:
        logger.warning("No users found in database")
        return False, None, "Invalid email or password"
    
    # Find user by email
    user_id = None
    user = None
    
    for uid, u in users.items():
        if u.get("email") == email:
            user_id = uid
            user = u
            break
    
    if not user:
        logger.warning(f"User with email {email} not found")
        return False, None, "Invalid email or password"
    
    # Verify password
    hashed_password, _ = hash_password(password, user.get("password_salt"))
    
    if hashed_password != user.get("password_hash"):
        logger.warning(f"Invalid password for user {email}")
        return False, None, "Invalid email or password"
    
    # Generate a login nonce for additional security
    nonce, expiration = generate_login_nonce(user_id)
    
    # Record login attempt
    current_time = int(time.time())
    if "login_history" not in user:
        user["login_history"] = []
    
    # Add login record
    login_record = {
        "timestamp": current_time,
        "ip_address": request.remote_addr if 'request' in globals() else "unknown",
        "user_agent": request.headers.get("User-Agent", "unknown") if 'request' in globals() else "unknown",
        "success": True
    }
    
    user["login_history"] = [login_record] + user["login_history"][:9]  # Keep last 10 logins
    users[user_id] = user
    save_users(users)
    
    # Create user data to return (exclude sensitive information)
    user_data = {
        "user_id": user_id,
        "name": user.get("name"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "dob": user.get("dob"),
        "created_at": user.get("created_at"),
        "login_nonce": nonce,
        "nonce_expiration": expiration,
        "last_login": user.get("login_history", [{}])[0].get("timestamp") if user.get("login_history") else None
    }
    
    logger.info(f"User {email} logged in successfully")
    return True, user_data, "Login successful"

def get_user_by_id(user_id):
    """
    Get user by ID.
    
    Args:
        user_id (str): User ID
        
    Returns:
        dict: User data or None if not found
    """
    # Load existing users
    users = load_users()
    if not users:
        logger.warning("No users found in database")
        return None
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return None
    
    # Create user data to return (exclude sensitive information)
    user_data = {
        "user_id": user_id,
        "name": user.get("name"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "dob": user.get("dob"),
        "created_at": user.get("created_at"),
        "tokens": user.get("tokens", []),
        "documents": user.get("documents", [])
    }
    
    return user_data

def add_token_to_user(user_id, token_data, tx_hash=None):
    """
    Add a token to a user.
    
    Args:
        user_id (str): User ID
        token_data (dict or str): Token data or token string
        tx_hash (str, optional): Transaction hash if token_data is a string
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Handle both string and dict inputs for token_data
    if isinstance(token_data, str):
        token = token_data
        token_obj = {
            "token": token,
            "tx_hash": tx_hash,
            "created_at": time.time(),
            "active": True
        }
    else:
        token = token_data.get("token")
        token_obj = {
            "token": token,
            "tx_hash": token_data.get("tx_hash", tx_hash),
            "created_at": time.time(),
            "active": True
        }
        
        # Add additional fields if they exist
        if "file_url" in token_data:
            token_obj["file_url"] = token_data["file_url"]
            
    logger.info(f"Adding token {token} to user {user_id}")
    
    # Load existing users
    users = load_users()
    if not users:
        logger.warning("No users found in database, creating new users database")
        users = {}
    
    # Find user by ID
    user = users.get(user_id)
    
    # If user doesn't exist, create a new one
    if not user:
        logger.warning(f"User with ID {user_id} not found, creating a new user")
        user = {
            "id": user_id,
            "name": "Anonymous User",
            "email": f"anonymous_{user_id}@example.com",
            "created_at": time.time(),
            "tokens": [],
            "documents": []
        }
        users[user_id] = user
    
    if "tokens" not in user:
        user["tokens"] = []
    
    # Check if this user already has a token
    if user["tokens"]:
        # If the user already has a token, check if it's the same one
        existing_token = user["tokens"][0]
        if existing_token.get("token") == token:
            logger.info(f"Token {token} already exists for user {user_id}")
            return True
        else:
            # If it's a different token, replace it to ensure one token per user
            logger.info(f"Replacing existing token {existing_token.get('token')} with {token} for user {user_id}")
            user["tokens"] = [token_obj]
    else:
        # If the user doesn't have a token yet, add this one
        user["tokens"].append(token_obj)
    
    # Save users
    if save_users(users):
        logger.info(f"Token {token} added to user {user_id}")
        return True
    else:
        logger.error(f"Error saving token for user {user_id}")
        return False

def get_user_tokens(user_id):
    """
    Get all tokens for a user.
    
    Args:
        user_id (str): User ID
        
    Returns:
        list: List of token objects
    """
    logger.info(f"Getting tokens for user {user_id}")
    
    # Load existing users
    users = load_users()
    if not users:
        logger.warning("No users found in database")
        return []
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return []
    
    return user.get("tokens", [])

def add_token_to_user(user_id, token_data):
    """
    Add a token to a user's profile.
    
    Args:
        user_id (str): User ID
        token_data (dict): Token data
        
    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Adding token to user {user_id}")
    
    # Load existing users
    users = load_users()
    if not users:
        logger.error("No users found in database")
        return False
    
    # Find user by ID
    if user_id not in users:
        logger.error(f"User {user_id} not found")
        return False
    
    # Initialize tokens list if it doesn't exist
    if "tokens" not in users[user_id]:
        users[user_id]["tokens"] = []
    
    # Add token to user's tokens
    users[user_id]["tokens"].append(token_data)
    
    # Save users
    if save_users(users):
        logger.info(f"Token added to user {user_id}")
        return True
    else:
        logger.error(f"Error adding token to user {user_id}")
        return False

def add_document_to_user(user_id, document_data):
    """
    Add a document to a user.
    
    Args:
        user_id (str): User ID
        document_data (dict): Document data
        
    Returns:
        tuple: (success, document_id)
    """
    logger.info(f"Adding document to user {user_id}")
    
    # Load existing users
    users = load_users()
    if not users:
        logger.warning("No users found in database, creating new users database")
        users = {}
    
    # Find user by ID
    user = users.get(user_id)
    
    # If user doesn't exist, create a new one
    if not user:
        logger.warning(f"User with ID {user_id} not found, creating a new user")
        user = {
            "id": user_id,
            "name": "Anonymous User",
            "email": f"anonymous_{user_id}@example.com",
            "created_at": time.time(),
            "tokens": [],
            "documents": []
        }
        users[user_id] = user
    
    # Generate document ID
    document_id = f"doc_{int(time.time())}_{secrets.token_hex(4)}"
    
    # Add document to user
    document = {
        "id": document_id,
        "title": document_data.get("title", "Untitled Document"),
        "type": document_data.get("type", "unknown"),
        "file_url": document_data.get("file_url", ""),
        "tx_hash": document_data.get("tx_hash", ""),
        "uploaded_at": time.time()
    }
    
    # Add additional fields if they exist
    if "text_file_url" in document_data:
        document["text_file_url"] = document_data["text_file_url"]
    
    if "extracted_data" in document_data:
        document["extracted_data"] = document_data["extracted_data"]
    
    if "token" in document_data:
        document["token"] = document_data["token"]
    
    if "document_token" in document_data:
        document["document_token"] = document_data["document_token"]
    
    # Ensure documents array exists
    if "documents" not in user:
        user["documents"] = []
    
    user["documents"].append(document)
    
    # Save users
    if save_users(users):
        logger.info(f"Document {document_id} added to user {user_id}")
        return True, document_id
    else:
        logger.error(f"Error saving document for user {user_id}")
        return False, None

def get_user_documents(user_id):
    """
    Get all documents for a user.
    
    Args:
        user_id (str): User ID
        
    Returns:
        list: List of document objects
    """
    logger.info(f"Getting documents for user {user_id}")
    
    # Load existing users
    users = load_users()
    if not users:
        logger.warning("No users found in database")
        return []
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return []  # Return empty list if user not found
    
    # Return only this specific user's documents
    return user.get("documents", [])

def get_document_by_id(user_id, document_id):
    """
    Get a specific document by ID for a user.
    
    Args:
        user_id (str): User ID
        document_id (str): Document ID
        
    Returns:
        dict: Document object if found, None otherwise
    """
    logger.info(f"Getting document {document_id} for user {user_id}")
    
    # Get all documents for the user
    documents = get_user_documents(user_id)
    
    # Find the document with the matching ID
    for document in documents:
        if document.get("id") == document_id:
            return document
    
    logger.warning(f"Document {document_id} not found for user {user_id}")
    return None