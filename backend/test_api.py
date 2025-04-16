"""
Manual API Testing Script for PII Authenticator Backend

This script provides functions to test the backend API endpoints.
It can be run as a standalone script or used interactively in a Python shell.
"""

import requests
import json
import time
import argparse
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init()

# API base URL
BASE_URL = "http://127.0.0.1:5000"

def print_header(text):
    """Print a formatted header."""
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f" {text}")
    print(f"{'=' * 80}{Style.RESET_ALL}\n")

def print_success(text):
    """Print a success message."""
    print(f"{Fore.GREEN}[SUCCESS] {text}{Style.RESET_ALL}")

def print_error(text):
    """Print an error message."""
    print(f"{Fore.RED}[ERROR] {text}{Style.RESET_ALL}")

def print_info(text):
    """Print an info message."""
    print(f"{Fore.YELLOW}[INFO] {text}{Style.RESET_ALL}")

def print_response(response):
    """Print a formatted API response."""
    print(f"\n{Fore.BLUE}Response Status: {response.status_code}{Style.RESET_ALL}")
    
    try:
        json_response = response.json()
        print(f"{Fore.BLUE}Response Body:{Style.RESET_ALL}")
        print(json.dumps(json_response, indent=2))
    except:
        print(f"{Fore.BLUE}Response Body:{Style.RESET_ALL}")
        print(response.text)
    
    print(f"{Fore.BLUE}Response Time: {response.elapsed.total_seconds():.4f} seconds{Style.RESET_ALL}")
    print()

def test_health_check():
    """Test the health check endpoint."""
    print_header("Testing Health Check Endpoint")
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        print_response(response)
        
        if response.status_code == 200:
            print_success("Health check successful")
        else:
            print_error(f"Health check failed with status code {response.status_code}")
    except Exception as e:
        print_error(f"Error: {str(e)}")

def test_token_generation(user_id=None, id_number=None):
    """
    Test the token generation endpoint.
    
    Args:
        user_id (str, optional): User ID to use for testing
        id_number (str, optional): ID number to use for testing
    
    Returns:
        str: The generated token if successful, None otherwise
    """
    print_header("Testing Token Generation Endpoint")
    
    if user_id is None:
        user_id = f"test_user_{int(time.time())}"
    
    if id_number is None:
        id_number = f"ID{int(time.time())}"
    
    print_info(f"Using user_id: {user_id}")
    print_info(f"Using id_number: {id_number}")
    
    payload = {
        "user_id": user_id,
        "id_number": id_number
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/encrypt",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        print_response(response)
        
        if response.status_code == 200:
            token = response.json().get("token")
            file_url = response.json().get("file_url")
            
            print_success(f"Token generated successfully: {token}")
            print_success(f"File URL: {file_url}")
            return token
        else:
            print_error(f"Token generation failed with status code {response.status_code}")
            return None
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return None

def test_token_validation(token=None):
    """
    Test the token validation endpoint.
    
    Args:
        token (str, optional): Token to validate. If None, a new token will be generated.
    
    Returns:
        bool: True if the token is valid, False otherwise
    """
    print_header("Testing Token Validation Endpoint")
    
    if token is None:
        print_info("No token provided, generating a new one...")
        token = test_token_generation()
        
        if token is None:
            print_error("Failed to generate a token for validation")
            return False
    
    print_info(f"Validating token: {token}")
    
    payload = {
        "token": token
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/validate_token",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        print_response(response)
        
        if response.status_code == 200:
            is_valid = response.json().get("valid", False)
            
            if is_valid:
                print_success(f"Token {token} is valid")
            else:
                print_error(f"Token {token} is invalid")
            
            return is_valid
        else:
            print_error(f"Token validation failed with status code {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return False

def test_invalid_token():
    """Test validation with an invalid token."""
    print_header("Testing Invalid Token Validation")
    
    invalid_token = "INVALID123"
    print_info(f"Using invalid token: {invalid_token}")
    
    payload = {
        "token": invalid_token
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/validate_token",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        print_response(response)
        
        if response.status_code == 200:
            is_valid = response.json().get("valid", True)
            
            if not is_valid:
                print_success(f"Invalid token correctly identified as invalid")
            else:
                print_error(f"Invalid token incorrectly identified as valid")
        else:
            print_error(f"Token validation failed with status code {response.status_code}")
    except Exception as e:
        print_error(f"Error: {str(e)}")

def test_missing_fields():
    """Test token generation with missing fields."""
    print_header("Testing Token Generation with Missing Fields")
    
    # Test with missing user_id
    payload1 = {
        "id_number": "12345"
    }
    
    print_info("Testing with missing user_id")
    try:
        response = requests.post(
            f"{BASE_URL}/encrypt",
            json=payload1,
            headers={"Content-Type": "application/json"}
        )
        print_response(response)
        
        if response.status_code == 400:
            print_success("Correctly returned 400 for missing user_id")
        else:
            print_error(f"Unexpected status code {response.status_code} for missing user_id")
    except Exception as e:
        print_error(f"Error: {str(e)}")
    
    # Test with missing id_number
    payload2 = {
        "user_id": "test_user"
    }
    
    print_info("Testing with missing id_number")
    try:
        response = requests.post(
            f"{BASE_URL}/encrypt",
            json=payload2,
            headers={"Content-Type": "application/json"}
        )
        print_response(response)
        
        if response.status_code == 400:
            print_success("Correctly returned 400 for missing id_number")
        else:
            print_error(f"Unexpected status code {response.status_code} for missing id_number")
    except Exception as e:
        print_error(f"Error: {str(e)}")

def test_empty_token():
    """Test validation with an empty token."""
    print_header("Testing Empty Token Validation")
    
    payload = {
        "token": ""
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/validate_token",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        print_response(response)
        
        if response.status_code == 400:
            print_success("Correctly returned 400 for empty token")
        else:
            print_error(f"Unexpected status code {response.status_code} for empty token")
    except Exception as e:
        print_error(f"Error: {str(e)}")

def run_all_tests():
    """Run all tests in sequence."""
    print_header("Running All Tests")
    
    # Test health check
    test_health_check()
    
    # Test token generation
    token = test_token_generation()
    
    # Test token validation with the generated token
    if token:
        test_token_validation(token)
    
    # Test with invalid token
    test_invalid_token()
    
    # Test with missing fields
    test_missing_fields()
    
    # Test with empty token
    test_empty_token()
    
    print_header("All Tests Completed")

def main():
    """Main function to parse arguments and run tests."""
    global BASE_URL
    
    parser = argparse.ArgumentParser(description="Test PII Authenticator Backend API")
    parser.add_argument("--url", help="Base URL of the API (default: http://127.0.0.1:5000)", default=BASE_URL)
    parser.add_argument("--test", choices=["all", "health", "generate", "validate", "invalid", "missing", "empty"], 
                        help="Specific test to run (default: all)", default="all")
    parser.add_argument("--user-id", help="User ID for token generation")
    parser.add_argument("--id-number", help="ID number for token generation")
    parser.add_argument("--token", help="Token for validation")
    
    args = parser.parse_args()
    BASE_URL = args.url
    
    if args.test == "all":
        run_all_tests()
    elif args.test == "health":
        test_health_check()
    elif args.test == "generate":
        test_token_generation(args.user_id, args.id_number)
    elif args.test == "validate":
        test_token_validation(args.token)
    elif args.test == "invalid":
        test_invalid_token()
    elif args.test == "missing":
        test_missing_fields()
    elif args.test == "empty":
        test_empty_token()

if __name__ == "__main__":
    main()