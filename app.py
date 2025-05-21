# app.py
from flask import Flask, request, send_file, render_template, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets
import hashlib
import io
import sys # Thêm import sys để kiểm tra đường dẫn Python

app = Flask(__name__)

# Kích thước khối AES là 128 bit (16 byte)
AES_BLOCK_SIZE_BYTES = 16

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Tạo khóa AES 256-bit từ mật khẩu người dùng và salt.
    Sử dụng PBKDF2-HMAC-SHA256 để tăng cường bảo mật.
    """
    # Sử dụng 100,000 vòng lặp để làm chậm quá trình brute-force
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    return key

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
    
    # Khởi tạo đối tượng mã hóa AES với khóa và IV
    cipher = algorithms.AES(key)
    encryptor = Cipher(cipher, modes.CBC(iv), backend=default_backend()).encryptor()

    # Thêm padding PKCS7 vào dữ liệu để đảm bảo độ dài là bội số của kích thước khối AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext_data) + padder.finalize()

    # Mã hóa dữ liệu
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Trả về salt + IV + ciphertext
    return salt + iv + ciphertext

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """
    Giải mã dữ liệu đã mã hóa bằng AES ở chế độ CBC.
    Đọc salt và IV từ đầu dữ liệu mã hóa.
    """
    # Đảm bảo dữ liệu đủ dài để chứa salt và IV
    if len(encrypted_data) < 2 * AES_BLOCK_SIZE_BYTES:
        raise ValueError("Dữ liệu mã hóa không hợp lệ: quá ngắn để chứa salt và IV.")

    # Tách salt và IV từ dữ liệu mã hóa
    salt = encrypted_data[:AES_BLOCK_SIZE_BYTES]
    iv = encrypted_data[AES_BLOCK_SIZE_BYTES : 2 * AES_BLOCK_SIZE_BYTES]
    ciphertext = encrypted_data[2 * AES_BLOCK_SIZE_BYTES:]

    key = derive_key(password, salt)

    # Khởi tạo đối tượng giải mã AES với khóa và IV
    cipher = algorithms.AES(key)
    decryptor = Cipher(cipher, modes.CBC(iv), backend=default_backend()).decryptor()

    # Giải mã dữ liệu
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        # Xử lý lỗi nếu mật khẩu sai hoặc dữ liệu bị hỏng
        raise ValueError(f"Lỗi giải mã: Mật khẩu không đúng hoặc dữ liệu bị hỏng. ({e})")

    # Loại bỏ padding PKCS7
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext_data = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext_data

@app.route('/', methods=['GET'])
def index():
    """Render trang HTML chính."""
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_file():
    """
    Xử lý yêu cầu mã hóa hoặc giải mã file từ frontend.
    """
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "Không tìm thấy file được tải lên."}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    action = request.form.get('action', '') # 'encrypt' or 'decrypt'

    if file.filename == '':
        return jsonify({"success": False, "message": "Không có file nào được chọn."}), 400
    
    if not password:
        return jsonify({"success": False, "message": "Mật khẩu không được để trống."}), 400

    file_content = file.read()
    processed_data = None
    output_filename = file.filename

    try:
        if action == 'encrypt':
            processed_data = encrypt_data(file_content, password)
            output_filename += '.enc' # Thêm đuôi .enc cho file mã hóa
            mimetype = 'application/octet-stream' # Kiểu MIME chung cho dữ liệu nhị phân
        elif action == 'decrypt':
            processed_data = decrypt_data(file_content, password)
            # Cố gắng loại bỏ đuôi .enc nếu có
            if output_filename.endswith('.enc'):
                output_filename = output_filename[:-4]
            else:
                output_filename += '.decrypted' # Nếu không có .enc, thêm .decrypted
            mimetype = 'application/octet-stream' # Có thể cố gắng đoán kiểu MIME nếu cần
        else:
            return jsonify({"success": False, "message": "Hành động không hợp lệ."}), 400

        # Trả về file đã xử lý
        return send_file(
            io.BytesIO(processed_data),
            download_name=output_filename,
            as_attachment=True,
            mimetype=mimetype
        )

    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
    except Exception as e:
        # Ghi log lỗi chi tiết hơn trong môi trường sản xuất
        print(f"Lỗi không xác định: {e}") 
        return jsonify({"success": False, "message": "Đã xảy ra lỗi trong quá trình xử lý file."}), 500

if __name__ == '__main__':
    # In ra đường dẫn của trình thông dịch Python đang chạy
    print(f"Ứng dụng đang chạy với trình thông dịch Python tại: {sys.executable}")
    app.run(debug=True)
