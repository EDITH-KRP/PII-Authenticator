"""
Load Testing Script for PII Authenticator Backend

This script performs load testing on the backend API endpoints.
It measures response times and success rates under various loads.
"""

import requests
import json
import time
import threading
import statistics
import argparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
import numpy as np

# Initialize colorama for colored terminal output
init()

# API base URL
BASE_URL = "http://127.0.0.1:5000"

# Global results storage
results = {
    "generate": {
        "response_times": [],
        "success_count": 0,
        "error_count": 0
    },
    "validate": {
        "response_times": [],
        "success_count": 0,
        "error_count": 0
    }
}

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

def generate_token(user_id=None, id_number=None):
    """
    Generate a token and measure response time.
    
    Args:
        user_id (str, optional): User ID to use
        id_number (str, optional): ID number to use
    
    Returns:
        tuple: (success, token, response_time)
    """
    if user_id is None:
        user_id = f"test_user_{int(time.time() * 1000)}"
    
    if id_number is None:
        id_number = f"ID{int(time.time() * 1000)}"
    
    payload = {
        "user_id": user_id,
        "id_number": id_number
    }
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/encrypt",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        end_time = time.time()
        response_time = end_time - start_time
        
        if response.status_code == 200:
            token = response.json().get("token")
            return True, token, response_time
        else:
            return False, None, response_time
    except Exception as e:
        return False, None, 0

def validate_token(token):
    """
    Validate a token and measure response time.
    
    Args:
        token (str): Token to validate
    
    Returns:
        tuple: (success, is_valid, response_time)
    """
    payload = {
        "token": token
    }
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/validate_token",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        end_time = time.time()
        response_time = end_time - start_time
        
        if response.status_code == 200:
            is_valid = response.json().get("valid", False)
            return True, is_valid, response_time
        else:
            return False, False, response_time
    except Exception as e:
        return False, False, 0

def run_generate_test(num_requests, concurrency):
    """
    Run a load test for token generation.
    
    Args:
        num_requests (int): Number of requests to make
        concurrency (int): Number of concurrent requests
    """
    print_header(f"Running Generate Token Load Test ({num_requests} requests, {concurrency} concurrent)")
    
    results["generate"]["response_times"] = []
    results["generate"]["success_count"] = 0
    results["generate"]["error_count"] = 0
    
    tokens = []
    
    def worker():
        success, token, response_time = generate_token()
        
        if success:
            results["generate"]["success_count"] += 1
            if token:
                tokens.append(token)
        else:
            results["generate"]["error_count"] += 1
        
        if response_time > 0:
            results["generate"]["response_times"].append(response_time)
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        for _ in range(num_requests):
            executor.submit(worker)
    
    return tokens

def run_validate_test(tokens, num_requests, concurrency):
    """
    Run a load test for token validation.
    
    Args:
        tokens (list): List of tokens to validate
        num_requests (int): Number of requests to make
        concurrency (int): Number of concurrent requests
    """
    print_header(f"Running Validate Token Load Test ({num_requests} requests, {concurrency} concurrent)")
    
    results["validate"]["response_times"] = []
    results["validate"]["success_count"] = 0
    results["validate"]["error_count"] = 0
    
    def worker():
        # Randomly select a token from the list, or use a random invalid token
        if tokens and np.random.random() > 0.2:  # 80% valid tokens
            token = np.random.choice(tokens)
        else:
            token = f"INVALID{int(time.time() * 1000)}"
        
        success, is_valid, response_time = validate_token(token)
        
        if success:
            results["validate"]["success_count"] += 1
        else:
            results["validate"]["error_count"] += 1
        
        if response_time > 0:
            results["validate"]["response_times"].append(response_time)
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        for _ in range(num_requests):
            executor.submit(worker)

def print_results():
    """Print the test results."""
    print_header("Test Results")
    
    for endpoint, data in results.items():
        print(f"{Fore.BLUE}Endpoint: {endpoint.upper()}{Style.RESET_ALL}")
        
        total_requests = data["success_count"] + data["error_count"]
        success_rate = (data["success_count"] / total_requests * 100) if total_requests > 0 else 0
        
        print(f"Total Requests: {total_requests}")
        print(f"Success Count: {data['success_count']}")
        print(f"Error Count: {data['error_count']}")
        print(f"Success Rate: {success_rate:.2f}%")
        
        if data["response_times"]:
            avg_time = statistics.mean(data["response_times"])
            min_time = min(data["response_times"])
            max_time = max(data["response_times"])
            p95_time = np.percentile(data["response_times"], 95)
            
            print(f"Average Response Time: {avg_time:.4f} seconds")
            print(f"Min Response Time: {min_time:.4f} seconds")
            print(f"Max Response Time: {max_time:.4f} seconds")
            print(f"95th Percentile Response Time: {p95_time:.4f} seconds")
        else:
            print("No response time data available")
        
        print()

def plot_results():
    """Plot the test results."""
    plt.figure(figsize=(12, 8))
    
    # Plot response time histograms
    plt.subplot(2, 2, 1)
    if results["generate"]["response_times"]:
        plt.hist(results["generate"]["response_times"], bins=20, alpha=0.7, color='blue')
        plt.title('Generate Token Response Times')
        plt.xlabel('Response Time (seconds)')
        plt.ylabel('Frequency')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
    
    plt.subplot(2, 2, 2)
    if results["validate"]["response_times"]:
        plt.hist(results["validate"]["response_times"], bins=20, alpha=0.7, color='green')
        plt.title('Validate Token Response Times')
        plt.xlabel('Response Time (seconds)')
        plt.ylabel('Frequency')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
    
    # Plot success vs error counts
    plt.subplot(2, 2, 3)
    endpoints = list(results.keys())
    success_counts = [results[endpoint]["success_count"] for endpoint in endpoints]
    error_counts = [results[endpoint]["error_count"] for endpoint in endpoints]
    
    x = np.arange(len(endpoints))
    width = 0.35
    
    plt.bar(x - width/2, success_counts, width, label='Success', color='green')
    plt.bar(x + width/2, error_counts, width, label='Error', color='red')
    
    plt.xlabel('Endpoint')
    plt.ylabel('Count')
    plt.title('Success vs Error Counts')
    plt.xticks(x, [endpoint.capitalize() for endpoint in endpoints])
    plt.legend()
    
    # Plot average response times
    plt.subplot(2, 2, 4)
    avg_times = []
    for endpoint in endpoints:
        if results[endpoint]["response_times"]:
            avg_times.append(statistics.mean(results[endpoint]["response_times"]))
        else:
            avg_times.append(0)
    
    plt.bar(x, avg_times, color=['blue', 'green'])
    plt.xlabel('Endpoint')
    plt.ylabel('Average Response Time (seconds)')
    plt.title('Average Response Times')
    plt.xticks(x, [endpoint.capitalize() for endpoint in endpoints])
    
    plt.tight_layout()
    plt.savefig('load_test_results.png')
    print_info("Results plot saved to 'load_test_results.png'")

def run_load_test(num_requests=100, concurrency=10, plot=True):
    """
    Run a complete load test.
    
    Args:
        num_requests (int): Number of requests per endpoint
        concurrency (int): Number of concurrent requests
        plot (bool): Whether to plot the results
    """
    print_header(f"Starting Load Test with {num_requests} requests per endpoint and {concurrency} concurrent requests")
    
    # Generate tokens
    tokens = run_generate_test(num_requests, concurrency)
    
    # Validate tokens
    run_validate_test(tokens, num_requests, concurrency)
    
    # Print results
    print_results()
    
    # Plot results if requested
    if plot:
        try:
            plot_results()
        except Exception as e:
            print_error(f"Failed to plot results: {str(e)}")

def main():
    """Main function to parse arguments and run tests."""
    global BASE_URL
    
    parser = argparse.ArgumentParser(description="Load Test PII Authenticator Backend API")
    parser.add_argument("--url", help="Base URL of the API (default: http://127.0.0.1:5000)", default=BASE_URL)
    parser.add_argument("--requests", type=int, help="Number of requests per endpoint (default: 100)", default=100)
    parser.add_argument("--concurrency", type=int, help="Number of concurrent requests (default: 10)", default=10)
    parser.add_argument("--no-plot", action="store_true", help="Disable plotting of results")
    
    args = parser.parse_args()
    BASE_URL = args.url
    
    run_load_test(args.requests, args.concurrency, not args.no_plot)

if __name__ == "__main__":
    main()