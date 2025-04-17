# backend/company_auth.py
import os
import json
import time
import hashlib
import secrets
from logger import get_logger

# Get logger
logger = get_logger()

# Path to companies.json file
COMPANIES_FILE = "companies.json"
VALIDATIONS_FILE = "validations.json"

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

def register_company(company_data):
    """
    Register a new company.
    
    Args:
        company_data (dict): Company data containing name, business_type, registration_number, email, phone, address, and password
        
    Returns:
        tuple: (success, company_id, message)
    """
    logger.info(f"Registering new company: {company_data.get('company_name')}")
    
    company_name = company_data.get("company_name", "").strip()
    business_type = company_data.get("business_type", "").strip()
    registration_number = company_data.get("registration_number", "").strip()
    email = company_data.get("email", "").strip().lower()
    phone = company_data.get("phone", "").strip()
    address = company_data.get("address", "").strip()
    password = company_data.get("password", "")
    
    # Validate required fields
    if not company_name or not email or not password or not registration_number:
        logger.warning("Missing required fields for company registration")
        return False, None, "Missing required fields (company_name, email, registration_number, password)"
    
    # Load existing companies
    companies = {}
    if os.path.exists(COMPANIES_FILE):
        try:
            with open(COMPANIES_FILE, "r") as f:
                companies = json.load(f)
        except Exception as e:
            logger.error(f"Error loading companies file: {e}")
    
    # Check if email already exists
    for company_id, company in companies.items():
        if company.get("email") == email:
            logger.warning(f"Company with email {email} already exists")
            return False, None, "Email already registered"
        
        if company.get("registration_number") == registration_number:
            logger.warning(f"Company with registration number {registration_number} already exists")
            return False, None, "Registration number already registered"
    
    # Generate company ID
    company_id = f"company_{int(time.time())}_{secrets.token_hex(4)}"
    
    # Hash password
    hashed_password, salt = hash_password(password)
    
    # Create company object
    company = {
        "id": company_id,
        "company_name": company_name,
        "business_type": business_type,
        "registration_number": registration_number,
        "email": email,
        "phone": phone,
        "address": address,
        "password_hash": hashed_password,
        "password_salt": salt,
        "created_at": time.time(),
        "validations": []
    }
    
    # Save company
    companies[company_id] = company
    
    try:
        with open(COMPANIES_FILE, "w") as f:
            json.dump(companies, f, indent=2)
        logger.info(f"Company {company_id} registered successfully")
        return True, company_id, "Company registered successfully"
    except Exception as e:
        logger.error(f"Error saving company: {e}")
        return False, None, "Error saving company"

def login_company(email, password):
    """
    Login a company.
    
    Args:
        email (str): Company email
        password (str): Company password
        
    Returns:
        tuple: (success, company_data, message)
    """
    logger.info(f"Login attempt for company: {email}")
    
    email = email.strip().lower()
    
    # Load existing companies
    companies = {}
    if os.path.exists(COMPANIES_FILE):
        try:
            with open(COMPANIES_FILE, "r") as f:
                companies = json.load(f)
        except Exception as e:
            logger.error(f"Error loading companies file: {e}")
            return False, None, "Error loading companies"
    
    # Find company by email
    company_id = None
    company = None
    
    for cid, c in companies.items():
        if c.get("email") == email:
            company_id = cid
            company = c
            break
    
    if not company:
        logger.warning(f"Company with email {email} not found")
        return False, None, "Invalid email or password"
    
    # Verify password
    hashed_password, _ = hash_password(password, company.get("password_salt"))
    
    if hashed_password != company.get("password_hash"):
        logger.warning(f"Invalid password for company {email}")
        return False, None, "Invalid email or password"
    
    # Create company data to return (exclude sensitive information)
    company_data = {
        "company_id": company_id,
        "company_name": company.get("company_name"),
        "business_type": company.get("business_type"),
        "email": company.get("email"),
        "phone": company.get("phone"),
        "address": company.get("address"),
        "created_at": company.get("created_at")
    }
    
    logger.info(f"Company {email} logged in successfully")
    return True, company_data, "Login successful"

def get_company_by_id(company_id):
    """
    Get company by ID.
    
    Args:
        company_id (str): Company ID
        
    Returns:
        dict: Company data or None if not found
    """
    # Load existing companies
    companies = {}
    if os.path.exists(COMPANIES_FILE):
        try:
            with open(COMPANIES_FILE, "r") as f:
                companies = json.load(f)
        except Exception as e:
            logger.error(f"Error loading companies file: {e}")
            return None
    
    # Find company by ID
    company = companies.get(company_id)
    
    if not company:
        logger.warning(f"Company with ID {company_id} not found")
        return None
    
    # Create company data to return (exclude sensitive information)
    company_data = {
        "company_id": company_id,
        "company_name": company.get("company_name"),
        "business_type": company.get("business_type"),
        "email": company.get("email"),
        "phone": company.get("phone"),
        "address": company.get("address"),
        "created_at": company.get("created_at")
    }
    
    return company_data

def add_validation(company_id, validation_data):
    """
    Add a validation record.
    
    Args:
        company_id (str): Company ID
        validation_data (dict): Validation data
        
    Returns:
        tuple: (success, validation_id)
    """
    logger.info(f"Adding validation for company {company_id}")
    
    # Load existing validations
    validations = {}
    if os.path.exists(VALIDATIONS_FILE):
        try:
            with open(VALIDATIONS_FILE, "r") as f:
                validations = json.load(f)
        except Exception as e:
            logger.error(f"Error loading validations file: {e}")
            validations = {}
    
    # Generate validation ID
    validation_id = f"val_{int(time.time())}_{secrets.token_hex(4)}"
    
    # Create validation object
    validation = {
        "id": validation_id,
        "company_id": company_id,
        "token": validation_data.get("token"),
        "purpose": validation_data.get("purpose"),
        "is_valid": validation_data.get("is_valid", False),
        "tx_hash": validation_data.get("tx_hash"),
        "validation_tx_hash": validation_data.get("validation_tx_hash"),
        "timestamp": time.time()
    }
    
    # Save validation
    validations[validation_id] = validation
    
    try:
        with open(VALIDATIONS_FILE, "w") as f:
            json.dump(validations, f, indent=2)
        logger.info(f"Validation {validation_id} added successfully")
        
        # Also add to company's validations
        add_validation_to_company(company_id, validation_id)
        
        return True, validation_id
    except Exception as e:
        logger.error(f"Error saving validation: {e}")
        return False, None

def add_validation_to_company(company_id, validation_id):
    """
    Add a validation ID to a company's validation list.
    
    Args:
        company_id (str): Company ID
        validation_id (str): Validation ID
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Load existing companies
    companies = {}
    if os.path.exists(COMPANIES_FILE):
        try:
            with open(COMPANIES_FILE, "r") as f:
                companies = json.load(f)
        except Exception as e:
            logger.error(f"Error loading companies file: {e}")
            return False
    
    # Find company by ID
    company = companies.get(company_id)
    
    if not company:
        logger.warning(f"Company with ID {company_id} not found")
        return False
    
    # Add validation ID to company
    if "validations" not in company:
        company["validations"] = []
    
    company["validations"].append(validation_id)
    
    # Save companies
    try:
        with open(COMPANIES_FILE, "w") as f:
            json.dump(companies, f, indent=2)
        logger.info(f"Validation {validation_id} added to company {company_id}")
        return True
    except Exception as e:
        logger.error(f"Error saving company: {e}")
        return False

def get_company_validations(company_id, limit=10):
    """
    Get recent validations for a company.
    
    Args:
        company_id (str): Company ID
        limit (int): Maximum number of validations to return
        
    Returns:
        list: List of validation objects
    """
    logger.info(f"Getting validations for company {company_id}")
    
    # Load existing companies
    companies = {}
    if os.path.exists(COMPANIES_FILE):
        try:
            with open(COMPANIES_FILE, "r") as f:
                companies = json.load(f)
        except Exception as e:
            logger.error(f"Error loading companies file: {e}")
            return []
    
    # Find company by ID
    company = companies.get(company_id)
    
    if not company:
        logger.warning(f"Company with ID {company_id} not found")
        return []
    
    validation_ids = company.get("validations", [])
    
    # Load validations
    validations = {}
    if os.path.exists(VALIDATIONS_FILE):
        try:
            with open(VALIDATIONS_FILE, "r") as f:
                validations = json.load(f)
        except Exception as e:
            logger.error(f"Error loading validations file: {e}")
            return []
    
    # Get validation objects
    result = []
    for val_id in validation_ids:
        validation = validations.get(val_id)
        if validation:
            result.append(validation)
    
    # Sort by timestamp (newest first)
    result.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    
    # Limit results
    return result[:limit]

def get_validation_stats(company_id):
    """
    Get validation statistics for a company.
    
    Args:
        company_id (str): Company ID
        
    Returns:
        dict: Validation statistics
    """
    logger.info(f"Getting validation stats for company {company_id}")
    
    # Get all validations
    all_validations = get_company_validations(company_id, limit=1000)
    
    # Calculate statistics
    total_count = len(all_validations)
    valid_count = sum(1 for v in all_validations if v.get("is_valid", False))
    
    # Calculate today's count
    today_start = time.time() - (24 * 60 * 60)  # 24 hours ago
    today_count = sum(1 for v in all_validations if v.get("timestamp", 0) >= today_start)
    
    # Calculate success rate
    success_rate = 0
    if total_count > 0:
        success_rate = round((valid_count / total_count) * 100)
    
    return {
        "total_count": total_count,
        "today_count": today_count,
        "valid_count": valid_count,
        "success_rate": success_rate
    }