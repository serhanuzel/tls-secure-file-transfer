import socket
import ssl
import sqlite3
import hashlib
import threading
import os
import json
from logger import start_logging
from sanitizer import sanitize_json_metadata

start_logging("receiver_server_logs")

BUFFER_SIZE = 1024 # 1 KB Chunks
STORAGE_DIR = "server_storage"

# Create storage directory if it doesn't exist
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)


def verify_password(stored_salt, stored_hash, input_password):
    """Verifies the input password using stored salt and PBKDF2."""
    new_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode('utf-8'), stored_salt, 100000)
    return new_hash == stored_hash

def handle_client(secure_conn, addr):
    print(f"[+] Handling secure session for {addr}")
    try:
        # 1. Authentication Phase
        auth_data = secure_conn.recv(BUFFER_SIZE).decode('utf-8')
        if ":" not in auth_data:
            secure_conn.send("AUTH_FAILED".encode('utf-8'))
            return
            
        username, password = auth_data.split(':', 1)
        
        # Database Check
        db_conn = sqlite3.connect('users.db')
        cursor = db_conn.cursor()
        cursor.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        db_conn.close()
        
        if result and verify_password(result[0], result[1], password):
            secure_conn.send("AUTH_SUCCESS".encode('utf-8'))
            print(f"[+] User '{username}' authenticated successfully.")
        else:
            secure_conn.send("AUTH_FAILED".encode('utf-8'))
            print(f"[-] Authentication failed for user '{username}'.")
            return

        # 2. File Metadata Phase
        metadata = secure_conn.recv(BUFFER_SIZE).decode('utf-8')
        raw_filename, expected_hash, file_size = metadata.split(':')
        filename = os.path.basename(raw_filename) # PATH TRAVERSAL FIX
        file_size = int(file_size)
        print(f"[+] Receiving file: {filename} ({file_size} bytes) | Expected SHA-256: {expected_hash}")

        # 3. Secure File Transfer Phase (Chunk-based)
        file_path = os.path.join(STORAGE_DIR, filename)
        sha256_hash = hashlib.sha256()
        bytes_received = 0
        
        with open(file_path, "wb") as f:
            while bytes_received < file_size:
                to_read = min(BUFFER_SIZE, file_size - bytes_received)
                chunk = secure_conn.recv(to_read)
                if not chunk:
                    break
                
                f.write(chunk)
                sha256_hash.update(chunk) 
                bytes_received += len(chunk)

        # 4. Integrity Verification Phase
        calculated_hash = sha256_hash.hexdigest()
        print(f"[+] Transfer done. Calculated SHA-256: {calculated_hash}")
        
        if calculated_hash == expected_hash:
            # Centralized Sanitization Call
            if filename.lower().endswith('.json'):
                sanitize_json_metadata(file_path)
                
            secure_conn.send("INTEGRITY_SUCCESS".encode('utf-8'))
            print(f"[+] SUCCESS: File '{filename}' verified perfectly. No corruption.")
        else:
            secure_conn.send("INTEGRITY_FAILED".encode('utf-8'))
            print(f"[-] ERROR: File verification failed. Hashes do not match!")
            if os.path.exists(file_path):
                os.remove(file_path)

    except Exception as e:
        print(f"[-] Error handling client {addr}: {e}")
    finally:
        secure_conn.close()
        print(f"[-] Connection with {addr} closed.\n" + "="*40)

def start_server():
    # Setup raw socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5001))
    server_socket.listen(5)
    print("[*] Server listening on 127.0.0.1:5001...")

    # Wrap socket with modern TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    while True:
        try:
            raw_conn, addr = server_socket.accept()
            # Perform TLS Handshake
            secure_conn = context.wrap_socket(raw_conn, server_side=True)
            print(f"\n[+] TLS Handshake successful with {addr}")
            
            # Multi-threading to handle multiple clients
            client_thread = threading.Thread(target=handle_client, args=(secure_conn, addr))
            client_thread.start()
        except Exception as e:
            print(f"[-] TLS Handshake failed: {e}")

if __name__ == "__main__":
    start_server()