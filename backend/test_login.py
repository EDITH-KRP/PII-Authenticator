import requests
import json

# API URL
API_URL = 'http://127.0.0.1:5000'

# Test user credentials
login_data = {
    "email": "test@example.com",
    "password": "password123"
}

# Make API call to login
try:
    response = requests.post(
        f"{API_URL}/login",
        headers={'Content-Type': 'application/json'},
        data=json.dumps(login_data)
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
except Exception as e:
    print(f"Error: {str(e)}")