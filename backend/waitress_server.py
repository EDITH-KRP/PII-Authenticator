import sys
import socket
import time
from waitress import serve

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def wait_for_port_to_be_free(port, timeout=30):
    start_time = time.time()
    while is_port_in_use(port):
        if time.time() - start_time > timeout:
            print(f"ERROR: Port {port} is still in use after waiting {timeout} seconds.")
            print("Please close any applications using this port and try again.")
            sys.exit(1)
        print(f"Waiting for port {port} to be free...")
        time.sleep(1)

if __name__ == '__main__':
    port = 5000
    
    # Check if port is already in use
    if is_port_in_use(port):
        print(f"WARNING: Port {port} is already in use.")
        print("Waiting for it to be released...")
        wait_for_port_to_be_free(port)
    
    try:
        print(f"Starting server with Waitress on http://127.0.0.1:{port}")
        # Import app here to avoid circular imports
        from app import app
        serve(app, host='127.0.0.1', port=port)
    except Exception as e:
        print(f"ERROR: Failed to start server: {e}")
        sys.exit(1)