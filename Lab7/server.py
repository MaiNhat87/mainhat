import socket
import hashlib
import os

def sha256sum_bytes(data):
    return hashlib.sha256(data).hexdigest()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 5001))
server.listen(5)

print("Server is listening...")

while True:
    conn, addr = server.accept()
    print(f"Connected by {addr}")

    filename_len = int.from_bytes(conn.recv(4), 'big')
    filename = conn.recv(filename_len).decode()

    data_len = int.from_bytes(conn.recv(8), 'big')
    file_data = b""
    while len(file_data) < data_len:
        file_data += conn.recv(4096)

    received_hash = conn.recv(64).decode()

    calculated_hash = sha256sum_bytes(file_data)
    if received_hash == calculated_hash:
        print("✅ File integrity verified.")
        with open(os.path.join("uploads", filename), 'wb') as f:
            f.write(file_data)
    else:
        print("❌ Integrity check failed.")

    conn.close()
