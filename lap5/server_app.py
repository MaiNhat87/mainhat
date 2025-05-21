# server_app.py
from flask import Flask, render_template, request, send_file, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets
import hashlib
import io
import socket
import threading
import uuid
import time

app = Flask(__name__, template_folder='server_templates')

# Thư mục để lưu trữ các file đã nhận (đã mã hóa)
RECEIVED_FILES_DIR = 'received_files'
if not os.path.exists(RECEIVED_FILES_DIR):
    os.makedirs(RECEIVED_FILES_DIR)

# Kích thước khối AES là 128 bit (16 byte)
AES_BLOCK_SIZE_BYTES = 16
# Kích thước buffer để đọc dữ liệu từ socket
BUFFER_SIZE = 4096

# Danh sách để lưu trữ thông tin về các file đã nhận
# (Trong môi trường thực tế nên dùng database)
received_files_metadata = []

# --- Crypto Functions (Shared) ---
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Tạo khóa AES 256-bit từ mật khẩu người dùng và salt.
    Sử dụng PBKDF2-HMAC-SHA256 để tăng cường bảo mật.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

def decrypt_data(encrypted_data_with_meta: bytes, password: str) -> bytes:
    """
    Giải mã dữ liệu đã mã hóa bằng AES ở chế độ CBC.
    Đọc salt và IV từ đầu dữ liệu mã hóa.
    """
    # Dữ liệu mã hóa bao gồm: [salt (16 bytes)] + [IV (16 bytes)] + [ciphertext]
    if len(encrypted_data_with_meta) < 2 * AES_BLOCK_SIZE_BYTES:
        raise ValueError("Dữ liệu mã hóa không hợp lệ: quá ngắn để chứa salt và IV.")

    salt = encrypted_data_with_meta[:AES_BLOCK_SIZE_BYTES]
    iv = encrypted_data_with_meta[AES_BLOCK_SIZE_BYTES : 2 * AES_BLOCK_SIZE_BYTES]
    ciphertext = encrypted_data_with_meta[2 * AES_BLOCK_SIZE_BYTES:]

    key = derive_key(password, salt)

    cipher = algorithms.AES(key)
    decryptor = Cipher(cipher, modes.CBC(iv), backend=default_backend()).decryptor()

    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Lỗi giải mã: Mật khẩu không đúng hoặc dữ liệu bị hỏng. ({e})")

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext_data = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext_data

# --- Socket Server Logic ---
def handle_client_connection(client_socket):
    """
    Xử lý kết nối từ một client socket.
    Nhận tên file và dữ liệu file đã mã hóa.
    """
    try:
        # 1. Nhận kích thước tên file (4 bytes)
        filename_len_bytes = client_socket.recv(4)
        if not filename_len_bytes:
            print("Client disconnected before sending filename length.")
            return
        filename_len = int.from_bytes(filename_len_bytes, 'big')

        # 2. Nhận tên file
        filename_bytes = client_socket.recv(filename_len)
        original_filename = filename_bytes.decode('utf-8')
        print(f"Đang nhận file: {original_filename}")

        # 3. Nhận kích thước file mã hóa (8 bytes)
        encrypted_file_size_bytes = client_socket.recv(8)
        if not encrypted_file_size_bytes:
            print("Client disconnected before sending encrypted file size.")
            return
        encrypted_file_size = int.from_bytes(encrypted_file_size_bytes, 'big')
        print(f"Kích thước file mã hóa dự kiến: {encrypted_file_size} bytes")

        # 4. Nhận dữ liệu file mã hóa
        received_data = b''
        bytes_received = 0
        while bytes_received < encrypted_file_size:
            chunk = client_socket.recv(min(BUFFER_SIZE, encrypted_file_size - bytes_received))
            if not chunk:
                print("Client disconnected unexpectedly during file transfer.")
                break
            received_data += chunk
            bytes_received += len(chunk)
            # print(f"Đã nhận {bytes_received}/{encrypted_file_size} bytes") # Để debug

        if bytes_received != encrypted_file_size:
            print(f"Cảnh báo: Kích thước file nhận được ({bytes_received}) không khớp với kích thước dự kiến ({encrypted_file_size}).")

        # Lưu file đã mã hóa
        file_id = str(uuid.uuid4()) # Tạo ID duy nhất cho file
        encrypted_filepath = os.path.join(RECEIVED_FILES_DIR, f"{file_id}.enc")
        with open(encrypted_filepath, 'wb') as f:
            f.write(received_data)
        
        # Thêm vào danh sách metadata
        received_files_metadata.append({
            'id': file_id,
            'original_filename': original_filename,
            'encrypted_filepath': encrypted_filepath,
            'received_at': time.strftime("%Y-%m-%d %H:%M:%S")
        })
        print(f"Đã nhận và lưu file mã hóa: {original_filename} ({file_id})")

    except Exception as e:
        print(f"Lỗi khi xử lý kết nối client: {e}")
    finally:
        client_socket.close()
        print("Đã đóng kết nối client.")

def start_socket_server(host, port):
    """
    Khởi động server socket để lắng nghe kết nối.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Cho phép tái sử dụng địa chỉ
    try:
        server_socket.bind((host, port))
        server_socket.listen(5) # Lắng nghe tối đa 5 kết nối đang chờ
        print(f"Server socket đang lắng nghe trên {host}:{port}")
        while True:
            client_sock, address = server_socket.accept()
            print(f"Đã chấp nhận kết nối từ {address[0]}:{address[1]}")
            # Xử lý client trong một luồng riêng
            client_handler = threading.Thread(target=handle_client_connection, args=(client_sock,))
            client_handler.start()
    except Exception as e:
        print(f"Lỗi khi khởi động server socket: {e}")
    finally:
        server_socket.close()

# --- Flask Routes ---
@app.route('/')
def index():
    """Trang chủ server, hiển thị các file đã nhận."""
    return render_template('index.html', files=received_files_metadata)

@app.route('/decrypt_download/<file_id>', methods=['POST'])
def decrypt_download(file_id):
    """
    Giải mã một file đã nhận và cho phép tải xuống.
    """
    password = request.form.get('password', '')
    if not password:
        return jsonify({"success": False, "message": "Vui lòng nhập mật khẩu."}), 400

    file_meta = next((f for f in received_files_metadata if f['id'] == file_id), None)
    if not file_meta:
        return jsonify({"success": False, "message": "File không tìm thấy."}), 404

    try:
        with open(file_meta['encrypted_filepath'], 'rb') as f:
            encrypted_data_with_meta = f.read()
        
        decrypted_data = decrypt_data(encrypted_data_with_meta, password)
        
        # Trả về file đã giải mã
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file_meta['original_filename'],
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
    except Exception as e:
        print(f"Lỗi khi giải mã hoặc tải xuống file: {e}")
        return jsonify({"success": False, "message": "Đã xảy ra lỗi trong quá trình giải mã file."}), 500

# --- Main execution ---
if __name__ == '__main__':
    SERVER_HOST = '0.0.0.0' # Lắng nghe trên tất cả các giao diện
    SERVER_PORT = 12345    # Cổng mặc định cho truyền file

    # Khởi động server socket trong một luồng riêng
    socket_thread = threading.Thread(target=start_socket_server, args=(SERVER_HOST, SERVER_PORT))
    socket_thread.daemon = True # Đặt luồng là daemon để nó tự động kết thúc khi chương trình chính kết thúc
    socket_thread.start()

    # Khởi động Flask web server
    print(f"Server Flask đang chạy trên http://127.0.0.1:5000")
    print(f"Đảm bảo cổng {SERVER_PORT} được mở trên tường lửa nếu bạn muốn nhận file từ máy khác.")
    app.run(debug=True, port=5000) # Flask web server chạy trên cổng 5000
