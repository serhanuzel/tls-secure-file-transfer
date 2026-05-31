# Comparative Analysis of TLS-Based Secure File Transfer Architectures

This repository explores secure file transfer over untrusted networks using TLS, PBKDF2 cryptography, and SHA-256 chunked integrity verification.

## 🏗️ Project Architectures
To demonstrate the evolution of network abstraction, this project includes three distinct implementations:
1. **Raw Sockets:** A pure Peer-to-Peer TCP implementation. (sender_client.py and receiver_server.py)
2. **Flask Server:** A production-like web framework approach.
3. **Pure Server:** A custom `http.server` implementation that processes raw TLS byte streams manually without external web frameworks.

## 🚀 How to Run Locally

### Step 1: Generate TLS Certificates (Required)
For security reasons, private keys are NOT included in this repository. You must generate a self-signed certificate to run the TLS servers. Run this command in the directory of the architecture you wish to test:
```bash
openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key
