# Comparative Analysis of TLS-Based Secure File Transfer Architectures

This repository contains the source code for a Computer Engineering Graduation Thesis exploring secure file transfer over untrusted networks using TLS, PBKDF2 cryptography, and SHA-256 chunked integrity verification.

---

## 🚀 Quick Start Setup

Before testing any architecture, initialize the local environment.

### 1. Generate TLS Certificates (Required)

For security reasons, private keys are **NOT** included in this repository. You must generate a self-signed certificate to run the TLS servers.

```bash
openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key
```

This command generates:

* `server.crt` — TLS certificate
* `server.key` — Private key

### 2. Initialize the Database

Each architecture can use the same local SQLite database.

Run the setup script to create the database and the default administrator account:

```bash
python setup_db.py
```

Default credentials:

```text
Username: admin
Password: password123
```

---

## 🏗️ Architectures & Execution Guide

This project evaluates three distinct levels of network abstraction. After completing the setup steps above, you can test each approach by navigating to its directory.

---

### Approach 1: Raw Sockets (Peer-to-Peer TCP)

Demonstrates fundamental transport-layer control without HTTP overhead. It reads explicit 1024-byte chunks directly from the TLS-wrapped TCP stream.

#### Run Server

```bash
python receiver_server.py
```

Server listens on:

```text
127.0.0.1:5001
```

#### Run Client

Open a second terminal and run:

```bash
python sender_client.py
```

#### Characteristics

* Direct TLS-over-TCP communication
* Manual chunk management
* Fine-grained transport-layer visibility
* Minimal abstraction

---

### Approach 2: Flask Server

A production-oriented implementation utilizing a high-level web framework. While highly accessible, it demonstrates how framework abstraction obscures manual packet-level manipulation.

#### Install Dependencies

```bash
pip install Flask werkzeug
```

#### Run Server

```bash
python flask_server.py
```

#### Access

Open:

```text
https://127.0.0.1:8080
```

in your web browser.

> Note: Because a self-signed certificate is used, your browser will display a security warning. Proceed manually for local testing.

#### Characteristics

* Framework-managed routing
* Simplified file upload handling
* Rapid development workflow
* Reduced visibility into raw network operations

---

### Approach 3: Pure Python Server (The Middle Ground)

A custom implementation built using Python's standard `http.server` infrastructure.

This architecture bridges the gap between raw sockets and Flask by providing a browser-accessible interface while manually processing incoming TLS byte streams through low-level operations such as:

```python
self.rfile.read()
```

This enables real-time SHA-256 chunk hashing during transfer while maintaining HTTP compatibility.

#### Run Server

```bash
python pure_server.py
```

#### Access

Open:

```text
https://127.0.0.1:8080
```

in your browser.

#### Characteristics

* No external web framework
* Manual request processing
* Browser-based user interface
* Direct access to incoming TLS stream data
* Suitable balance between abstraction and control

---

## 🔒 Security Architecture

All implementations share a common security model built around transport security, authentication hardening, and integrity verification.

### TLS Encryption

* End-to-end encrypted communication
* Self-signed X.509 certificates
* TLS-wrapped sockets and HTTPS connections

### Password Security

* PBKDF2-based password hashing
* Salted credential storage
* No plaintext passwords stored in the database

### File Integrity Verification

* SHA-256 chunk hashing
* Integrity validation during transfer
* Detection of corruption or tampering

### Local Authentication Database

* SQLite-based credential storage
* Isolated per architecture
* Supports secure login workflows

---

## 🛡️ Implemented Security Defenses

### Directory Traversal Prevention

Uploaded filenames are sanitized before being written to disk.

Examples:

```python
os.path.basename()
```

or

```python
secure_filename()
```

This prevents malicious paths such as:

```text
../../../etc/passwd
```

from escaping the designated upload directory.

---

### JSON Prototype Pollution Defense

A centralized `sanitizer.py` module validates JSON structures and removes dangerous keys.

Examples include:

```text
__proto__
constructor
prototype
```

This prevents malicious object pollution attacks and enforces strict schema validation.

---

### Stored Cross-Site Scripting (XSS) Mitigation

All user-supplied values displayed within dynamic dashboards are properly escaped before rendering.

Benefits:

* Prevents execution of injected JavaScript
* Protects administrator sessions
* Secures file metadata displays
* Reduces attack surface for browser-based exploits

---

## 📊 Research Objective

The purpose of this project is to compare three different implementation strategies for secure file transfer:

1. Raw TLS sockets
2. Framework-based web servers (Flask)
3. Custom HTTP server implementations

The analysis focuses on:

* Security
* Performance
* Developer complexity
* Level of abstraction
* Visibility into network operations
* Ease of maintenance
