import socket
import ssl
import hashlib
import os
import tkinter as tk
from tkinter import filedialog

BUFFER_SIZE = 1024

def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the main Tk window

    file_path = filedialog.askopenfilename(
        title="Select a file to upload"
    )

    return file_path

def calculate_file_sha256(file_path):
    """Calculates the SHA-256 hash of a file by reading it in chunks."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def start_client():
    # Setup standard client socket
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Configure TLS Context for Client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE # Accept self-signed certificates for testing

    print("[*] Connecting to secure server via TLS...")
    try:
        secure_socket = context.wrap_socket(raw_socket, server_hostname='127.0.0.1')
        secure_socket.connect(('127.0.0.1', 5001))
        print("[+] Connected securely using TLS encryption.")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # 1. Authentication Phase
    username = input("Username: ")
    password = input("Password: ")
    
    auth_payload = f"{username}:{password}"
    secure_socket.send(auth_payload.encode('utf-8'))
    
    auth_response = secure_socket.recv(BUFFER_SIZE).decode('utf-8')
    if auth_response != "AUTH_SUCCESS":
        print("[-] Access Denied: Invalid username or password.")
        secure_socket.close()
        return
    print("[+] Login successful!")

    # 2. File Selection & Metadata Phase
    file_path = select_file()

    if not file_path:
        print("[-] No file selected.")
        secure_socket.close()
        return

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    
    print("[*] Calculating SHA-256 cryptographic checksum...")
    file_hash = calculate_file_sha256(file_path)
    
    # Send metadata (filename:hash:size)
    metadata_payload = f"{filename}:{file_hash}:{file_size}"
    secure_socket.send(metadata_payload.encode('utf-8'))

    # 3. Dynamic Chunk-Based Transfer Phase
    print(f"[*] Uploading '{filename}'...")
    with open(file_path, "rb") as f:
        while chunk := f.read(buffer_size := BUFFER_SIZE):
            secure_socket.sendall(chunk)

    # 4. Verification Response
    result = secure_socket.recv(BUFFER_SIZE).decode('utf-8')
    if result == "INTEGRITY_SUCCESS":
        print("[++] SUCCESS: File uploaded and integrity verified by the server!")
    else:
        print("[--] FAILED: Server rejected the file. Integrity check failed/corrupted.")

    secure_socket.close()

if __name__ == "__main__":
    start_client()