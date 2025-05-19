from flask import Flask, jsonify
from w3_utils import check_blockchain_connection

app = Flask(__name__)

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"status": "ok", "message": "Server is running"})

@app.route('/blockchain', methods=['GET'])
def blockchain():
    result = check_blockchain_connection()
    return jsonify(result)

if __name__ == '__main__':
    print("Starting simplified backend server on http://localhost:8080")
    app.run(host='localhost', port=8080)