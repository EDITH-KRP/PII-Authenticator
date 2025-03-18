import jwt
import datetime
import json
from config import JWT_SECRET

def generate_token(id_numbers):
    payload = {
        'id_numbers': id_numbers,  # Store multiple IDs
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return decoded['id_numbers']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
