import http.server
import ssl
import hashlib
import os
import urllib.parse
import sqlite3
import secrets
import sys
import html
import json
from http import cookies
from datetime import datetime
from logger import start_logging
from sanitizer import sanitize_json_metadata

start_logging("pure_server_logs")


STORAGE_DIR = "server_storage"
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# In-memory session storage (Maps session_id to username)
# In a production environment, this should be stored in a database.
ACTIVE_SESSIONS = {}

def verify_password(stored_salt, stored_hash, input_password):
    """Verifies the password using PBKDF2."""
    new_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode('utf-8'), stored_salt, 100000)
    return new_hash == stored_hash

class SecureThesisHandler(http.server.BaseHTTPRequestHandler):
    
    def get_current_user(self):
        """Reads the HTTP Cookie to identify the logged-in user."""
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = cookies.SimpleCookie(cookie_header)
            if 'session_id' in cookie:
                session_id = cookie['session_id'].value
                return ACTIVE_SESSIONS.get(session_id)
        return None

    def redirect(self, location):
        """Helper to send a 302 Redirect."""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def do_GET(self):
        """Handles page rendering and file downloading."""
        user = self.get_current_user()

        # 1. Login Page Route
        if self.path == '/login':
            if user:
                return self.redirect('/')
                
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>Secure Login</title></head>
            <body style="font-family: Arial; padding: 50px; text-align: center; background: #f4f4f4;">
                <div style="max-width: 300px; margin: auto; background: white; padding: 30px; border-radius: 8px;">
                    <h2>System Login</h2>
                    <form method="POST" action="/login">
                        <input type="text" name="username" placeholder="Username" required style="width: 90%; padding: 8px; margin-bottom: 10px;"><br>
                        <input type="password" name="password" placeholder="Password" required style="width: 90%; padding: 8px; margin-bottom: 20px;"><br>
                        <button type="submit" style="width: 100%; padding: 10px; background: #007BFF; color: white; border: none; cursor: pointer;">Login</button>
                    </form>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
            return

        # 2. Dashboard Route (Requires Login)
        elif self.path == '/':
            if not user:
                return self.redirect('/login')

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            # Generate file list dynamically
            files = os.listdir(STORAGE_DIR)
            file_rows = ""
            for f in files:
                safe_f = html.escape(f) # XSS FIX
                file_rows += f"<tr><td style='padding:10px; border:1px solid #ddd;'>{safe_f}</td><td style='padding:10px; border:1px solid #ddd;'><a href='/download/{urllib.parse.quote(f)}'>Download</a></td></tr>"
            
            if not files:
                file_rows = "<tr><td colspan='2' style='padding:10px; text-align:center;'>No files found.</td></tr>"

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Secure Dashboard</title></head>
            <body style="font-family: Arial; padding: 50px; background: #f4f4f4;">
                <div style="max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between;">
                        <h2>Welcome, {user}</h2>
                        <a href="/logout" style="color: red; margin-top: 25px;">Logout</a>
                    </div>
                    <hr>
                    
                    <h3>Upload File (Raw Socket Stream)</h3>
                    <input type="file" id="fileInput" style="margin-bottom: 10px;"><br>
                    <button onclick="uploadFile()" style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">Upload File</button>
                    <p id="status" style="color: blue; font-weight: bold;"></p>
                    
                    <h3 style="margin-top: 30px;">Server Storage</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr style="background: #eee;">
                            <th style="padding:10px; border:1px solid #ddd; text-align:left;">Filename</th>
                            <th style="padding:10px; border:1px solid #ddd; text-align:left;">Action</th>
                        </tr>
                        {file_rows}
                    </table>
                </div>

                <script>
                    async function uploadFile() {{
                        const fileInput = document.getElementById('fileInput');
                        const statusText = document.getElementById('status');
                        
                        if (fileInput.files.length === 0) {{
                            alert("Please select a file.");
                            return;
                        }}

                        const file = fileInput.files[0];
                        statusText.innerText = "Uploading via TLS Stream...";

                        const response = await fetch('/upload', {{
                            method: 'POST',
                            headers: {{
                                'X-File-Name': encodeURIComponent(file.name),
                                'Content-Length': file.size
                            }},
                            body: file
                        }});

                        const result = await response.text();
                        statusText.innerText = result;
                        
                        // Reload page to show the new file after 2 seconds
                        if(response.ok) {{
                            setTimeout(() => location.reload(), 2000);
                        }}
                    }}
                </script>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
            return

        # 3. File Download Route
        elif self.path.startswith('/download/'):
            if not user:
                return self.redirect('/login')
                
            filename = urllib.parse.unquote(self.path.split('/')[-1])
            file_path = os.path.join(STORAGE_DIR, filename)
            
            if os.path.exists(file_path):
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(os.path.getsize(file_path)))
                self.end_headers()
                
                print(f"[*] Sending file to {user}: {filename}")
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        self.wfile.write(chunk)
            else:
                self.send_error(404, "File not found")
            return

        # 4. Logout Route
        elif self.path == '/logout':
            self.send_response(302)
            self.send_header('Set-Cookie', 'session_id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.send_header('Location', '/login')
            self.end_headers()
            return

        else:
            self.send_error(404, "Page Not Found")

    def do_POST(self):
        """Handles Authentication and Raw Binary Uploads."""
        
        # 1. Handle Login Form Submission
        if self.path == '/login':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = urllib.parse.parse_qs(post_data)
            
            username = parsed_data.get('username', [''])[0]
            password = parsed_data.get('password', [''])[0]
            
            db_conn = sqlite3.connect('users.db')
            cursor = db_conn.cursor()
            cursor.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            db_conn.close()
            
            if result and verify_password(result[0], result[1], password):
                # Generate a secure random token and store it
                session_token = secrets.token_hex(16)
                ACTIVE_SESSIONS[session_token] = username
                
                print(f"[+] User '{username}' authenticated successfully.")
                self.send_response(302)
                # Set HTTP-Only Cookie to prevent JavaScript access to the session
                self.send_header('Set-Cookie', f'session_id={session_token}; HttpOnly; Path=/')
                self.send_header('Location', '/')
                self.end_headers()
            else:
                print(f"[-] Failed login attempt for '{username}'.")
                self.redirect('/login')
            return

        # 2. Handle File Upload (Requires Login)
        elif self.path == '/upload':
            user = self.get_current_user()
            if not user:
                self.send_error(401, "Unauthorized")
                return

            raw_filename = urllib.parse.unquote(self.headers.get('X-File-Name', 'unknown_file.bin'))
            filename = os.path.basename(raw_filename) # PATH TRAVERSAL FIX
            file_size = int(self.headers.get('Content-Length', 0))
            
            print(f"[*] Incoming stream from {user} for: {filename} ({file_size} bytes)")
            
            file_path = os.path.join(STORAGE_DIR, filename)
            sha256_hash = hashlib.sha256()
            bytes_received = 0
            
            with open(file_path, 'wb') as f:
                while bytes_received < file_size:
                    chunk_size = min(1024, file_size - bytes_received) 
                    chunk = self.rfile.read(chunk_size) 
                    if not chunk:
                        break
                        
                    f.write(chunk)
                    sha256_hash.update(chunk)
                    bytes_received += len(chunk)
            
            calculated_hash = sha256_hash.hexdigest()
            print(f"[+] Transfer Complete. Server-side SHA-256: {calculated_hash}")
            
            # Centralized Sanitization Call
            if filename.lower().endswith('.json'):
                sanitize_json_metadata(file_path)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            success_msg = f"SUCCESS! Integrity Check (SHA-256): {calculated_hash}"
            self.wfile.write(success_msg.encode('utf-8'))
            return

def start_pure_server():
    server_address = ('127.0.0.1', 8080)
    httpd = http.server.HTTPServer(server_address, SecureThesisHandler)
    
    # Wrap the server's socket with own TLS Context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print("[*] Pure Python Secure Web Server running on https://127.0.0.1:8080")
    print("[*] Waiting for TLS connections...")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Server shutting down.")
        httpd.server_close()

if __name__ == '__main__':
    start_pure_server()