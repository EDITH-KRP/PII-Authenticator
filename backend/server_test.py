from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"status": "ok", "message": "Server is running"})

if __name__ == '__main__':
    print("Starting test server on http://127.0.0.1:8080")
    app.run(host='127.0.0.1', port=8080, debug=False)