from flask import Flask, request, send_file, render_template
import socket
import hashlib
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def sha256sum(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, f.filename)
    f.save(filepath)

    # Tính hash và gửi file qua socket
    file_hash = sha256sum(filepath)
    send_file_to_server(filepath, file_hash)
    return "File uploaded and sent successfully!"

@app.route('/download')
def download():
    files = os.listdir(UPLOAD_FOLDER)
    if not files:
        return "No file available."
    return send_file(os.path.join(UPLOAD_FOLDER, files[0]), as_attachment=True)

def send_file_to_server(filepath, file_hash):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 5001))
    filename = os.path.basename(filepath).encode()

    client.send(len(filename).to_bytes(4, 'big'))
    client.send(filename)

    with open(filepath, 'rb') as f:
        data = f.read()
    client.send(len(data).to_bytes(8, 'big'))
    client.send(data)

    client.send(file_hash.encode())  # SHA-256 hash
    client.close()

if __name__ == '__main__':
    app.run(debug=True)
