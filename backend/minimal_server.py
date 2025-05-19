from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    print("Starting minimal server on port 8888")
    app.run(host='0.0.0.0', port=8888)