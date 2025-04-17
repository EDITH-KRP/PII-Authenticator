import requests
import json

# API URL
API_URL = 'http://127.0.0.1:5000'

# Test user data
test_user = {
    "name": "Test User",
    "email": "test@example.com",
    "phone": "1234567890",
    "dob": "1990-01-01",
    "password": "password123"
}

# Make API call to register
try:
    response = requests.post(
        f"{API_URL}/register",
        headers={'Content-Type': 'application/json'},
        data=json.dumps(test_user)
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
except Exception as e:
    print(f"Error: {str(e)}")