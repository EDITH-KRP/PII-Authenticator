import random
import string
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")

# ✅ Define storage path
TOKEN_STORAGE_DIR = "storage"
TOKEN_STORAGE_FILE = os.path.join(TOKEN_STORAGE_DIR, "token_data.json")

# ✅ Ensure `storage/` directory exists
os.makedirs(TOKEN_STORAGE_DIR, exist_ok=True)

# ✅ Ensure `token_data.json` file exists
if not os.path.exists(TOKEN_STORAGE_FILE):
    with open(TOKEN_STORAGE_FILE, "w") as f:
        json.dump({}, f)

def load_tokens():
    """Load stored tokens from file."""
    with open(TOKEN_STORAGE_FILE, "r") as f:
        return json.load(f)

def save_tokens(tokens):
    """Save tokens to file."""
    with open(TOKEN_STORAGE_FILE, "w") as f:
        json.dump(tokens, f)

def generate_unique_token():
    """Generate a unique 10-character token."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))

def get_or_generate_token(user_id):
    """Generate or retrieve the existing token for a user."""
    tokens = load_tokens()
    if user_id in tokens:
        return tokens[user_id]  # ✅ Return existing token
    else:
        new_token = generate_unique_token()
        tokens[user_id] = new_token
        save_tokens(tokens)  # ✅ Save new token
        return new_token

def verify_token(token):
    """Verify token and return user_id if valid."""
    tokens = load_tokens()
    for user_id, stored_token in tokens.items():
        if stored_token == token:
            return user_id
    return None  # ❌ Invalid token
