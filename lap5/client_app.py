# client_app.py
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets
import hashlib
import socket
import io

app = Flask(__name__, template_folder='client_templates')

# Kích thước khối AES là 128 bit (16 byte)
AES_BLOCK_SIZE_BYTES = 16
# Kích thước buffer để gửi dữ liệu qua socket
BUFFER_SIZE = 4096

# --- Crypto Functions (Shared) ---
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Tạo khóa AES 256-bit từ mật khẩu người dùng và salt.
    Sử dụng PBKDF2-HMAC-SHA256 để tăng cường bảo mật.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

def encrypt_data(plaintext_data: bytes, password: str) -> bytes:
    """
    Mã hóa dữ liệu bằng AES ở chế độ CBC.
    IV (Initialization Vector) ngẫu nhiên được tạo và thêm vào đầu dữ liệu mã hóa.
    """
    # Tạo salt ngẫu nhiên cho mỗi lần mã hóa
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    
    # Tạo IV ngẫu nhiên
    iv = secrets.token_bytes(AES_BLOCK_SIZE_BYTES)
    
    cipher = algorithms.AES(key)
    encryptor = Cipher(cipher, modes.CBC(iv), backend=default_backend()).encryptor()

    # Thêm padding PKCS7 vào dữ liệu để đảm bảo độ dài là bội số của kích thước khối AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext_data) + padder.finalize()

    # Mã hóa dữ liệu
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Trả về salt + IV + ciphertext
    return salt + iv + ciphertext

# --- Socket Client Logic ---
def send_file_over_socket(server_host: str, server_port: int, original_filename: str, encrypted_data_with_meta: bytes):
    """
    Kết nối đến server socket và gửi dữ liệu file đã mã hóa.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_host, server_port))
        print(f"Đã kết nối đến server: {server_host}:{server_port}")

        # 1. Gửi kích thước tên file (4 bytes)
        filename_bytes = original_filename.encode('utf-8')
        filename_len = len(filename_bytes)
        client_socket.sendall(filename_len.to_bytes(4, 'big')) # Gửi 4 bytes kích thước tên file

        # 2. Gửi tên file
        client_socket.sendall(filename_bytes)

        # 3. Gửi kích thước file mã hóa (8 bytes)
        encrypted_file_size = len(encrypted_data_with_meta)
        client_socket.sendall(encrypted_file_size.to_bytes(8, 'big')) # Gửi 8 bytes kích thước file mã hóa

        # 4. Gửi dữ liệu file mã hóa theo từng chunk
        data_stream = io.BytesIO(encrypted_data_with_meta)
        while True:
            chunk = data_stream.read(BUFFER_SIZE)
            if not chunk:
                break
            client_socket.sendall(chunk)
        
        print(f"Đã gửi thành công {encrypted_file_size} bytes dữ liệu mã hóa.")
        return True
    except socket.error as e:
        print(f"Lỗi socket khi gửi file: {e}")
        return False
    except Exception as e:
        print(f"Lỗi không xác định khi gửi file: {e}")
        return False
    finally:
        client_socket.close()
        print("Đã đóng kết nối socket.")

# --- Flask Routes ---
@app.route('/')
def index():
    """Trang chủ client, hiển thị form gửi file."""
    return render_template('index.html')

@app.route('/send_file', methods=['POST'])
def send_file_route():
    """
    Xử lý yêu cầu gửi file từ frontend.
    """
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "Không tìm thấy file được tải lên."}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    server_ip = request.form.get('server_ip', '127.0.0.1')
    server_port_str = request.form.get('server_port', '12345')

    if file.filename == '':
        return jsonify({"success": False, "message": "Không có file nào được chọn."}), 400
    
    if not password:
        return jsonify({"success": False, "message": "Mật khẩu không được để trống."}), 400

    try:
        server_port = int(server_port_str)
        if not (1 <= server_port <= 65535):
            raise ValueError("Cổng server không hợp lệ.")
    except ValueError:
        return jsonify({"success": False, "message": "Cổng server phải là một số nguyên hợp lệ."}), 400

    file_content = file.read()
    original_filename = file.filename

    try:
        # Mã hóa dữ liệu
        encrypted_data_with_meta = encrypt_data(file_content, password)
        
        # Gửi dữ liệu qua socket
        success = send_file_over_socket(server_ip, server_port, original_filename, encrypted_data_with_meta)

        if success:
            return jsonify({"success": True, "message": "File đã được gửi thành công!"})
        else:
            return jsonify({"success": False, "message": "Không thể gửi file. Vui lòng kiểm tra địa chỉ IP/cổng server và kết nối mạng."}), 500

    except Exception as e:
        print(f"Lỗi khi xử lý gửi file: {e}")
        return jsonify({"success": False, "message": f"Đã xảy ra lỗi: {str(e)}"}), 500

# --- Main execution ---
if __name__ == '__main__':
    print(f"Client Flask đang chạy trên http://127.0.0.1:5001")
    app.run(debug=True, port=5001) # Client web server chạy trên cổng 5001
