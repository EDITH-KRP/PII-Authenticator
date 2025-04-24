import http.server
import socketserver
import os

# Set the directory to serve files from
os.chdir('PII/PII')

# Set the port
PORT = 8000

# Create the HTTP server
Handler = http.server.SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(("", PORT), Handler)

print(f"Serving at http://localhost:{PORT}")
print("Press Ctrl+C to stop the server")

# Start the server
httpd.serve_forever()