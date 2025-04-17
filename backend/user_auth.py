# backend/user_auth.py
import os
import json
import time
import hashlib
import secrets
from logger import get_logger

# Get logger
logger = get_logger()

# Path to users.json file
USERS_FILE = "users.json"

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
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
    
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
    
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        logger.info(f"User {user_id} registered successfully")
        return True, user_id, "User registered successfully"
    except Exception as e:
        logger.error(f"Error saving user: {e}")
        return False, None, "Error saving user"

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
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
            return False, None, "Error loading users"
    
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
    
    # Create user data to return (exclude sensitive information)
    user_data = {
        "user_id": user_id,
        "name": user.get("name"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "dob": user.get("dob"),
        "created_at": user.get("created_at")
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
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
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

def add_token_to_user(user_id, token, tx_hash):
    """
    Add a token to a user.
    
    Args:
        user_id (str): User ID
        token (str): Token value
        tx_hash (str): Transaction hash
        
    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Adding token {token} to user {user_id}")
    
    # Load existing users
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
            return False
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return False
    
    # Add token to user
    token_data = {
        "token": token,
        "tx_hash": tx_hash,
        "created_at": time.time(),
        "active": True
    }
    
    if "tokens" not in user:
        user["tokens"] = []
    
    # Check if token already exists
    for existing_token in user["tokens"]:
        if existing_token.get("token") == token:
            logger.info(f"Token {token} already exists for user {user_id}")
            return True
    
    user["tokens"].append(token_data)
    
    # Save users
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        logger.info(f"Token {token} added to user {user_id}")
        return True
    except Exception as e:
        logger.error(f"Error saving user: {e}")
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
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
            return []
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return []
    
    return user.get("tokens", [])

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
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
            return False, None
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return False, None
    
    # Generate document ID
    document_id = f"doc_{int(time.time())}_{secrets.token_hex(4)}"
    
    # Add document to user
    document = {
        "id": document_id,
        "title": document_data.get("title"),
        "type": document_data.get("type"),
        "file_url": document_data.get("file_url"),
        "tx_hash": document_data.get("tx_hash"),
        "uploaded_at": time.time()
    }
    
    if "documents" not in user:
        user["documents"] = []
    
    user["documents"].append(document)
    
    # Save users
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        logger.info(f"Document {document_id} added to user {user_id}")
        return True, document_id
    except Exception as e:
        logger.error(f"Error saving user: {e}")
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
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
            return []
    
    # Find user by ID
    user = users.get(user_id)
    
    if not user:
        logger.warning(f"User with ID {user_id} not found")
        return []
    
    return user.get("documents", [])