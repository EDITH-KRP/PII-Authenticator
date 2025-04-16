import requests
import socket
import sys
import subprocess
import time
import os
import signal
import atexit

def is_server_running(host="127.0.0.1", port=5000):
    """Check if the server is already running on the specified port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

def start_server():
    """Start the Flask server if it's not already running."""
    if not is_server_running():
        print("Starting Flask server...")
        # Start the server in a new process
        server_process = subprocess.Popen(["python", "app.py"])
        
        # Register a function to kill the server when the script exits
        def cleanup():
            print("Shutting down Flask server...")
            server_process.terminate()
            server_process.wait()
        
        atexit.register(cleanup)
        
        # Wait for the server to start
        for _ in range(5):  # Try 5 times
            if is_server_running():
                print("Server started successfully!")
                break
            time.sleep(1)
        else:
            print("Failed to start server. Exiting.")
            sys.exit(1)
    else:
        print("Server is already running.")

# Start the server if needed
start_server()

url = "http://127.0.0.1:5000/encrypt"

payload = {
    "user_id": "testuser001",
    "id_number": "AADHAR-1234-5678"
}

headers = {
    "Content-Type": "application/json"
}

try:
    response = requests.post(url, json=payload, headers=headers)
    print("Status Code:", response.status_code)
    print("Response JSON:", response.json())
except requests.exceptions.ConnectionError:
    print("Error: Could not connect to the server. Make sure it's running.")
    sys.exit(1)
