from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import sqlite3
import hashlib
import os
import json
from werkzeug.utils import secure_filename
from sanitizer import sanitize_json_metadata

app = Flask(__name__)
# Secret key required for session security and flash messages
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
STORAGE_DIR = "server_storage"

# Create the storage directory if it does not exist
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

def verify_password(stored_salt, stored_hash, input_password):
    """Verifies the input password using the stored salt and PBKDF2-HMAC-SHA256."""
    new_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode('utf-8'), stored_salt, 100000)
    return new_hash == stored_hash

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the database for the user credentials
        db_conn = sqlite3.connect('users.db')
        cursor = db_conn.cursor()
        cursor.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        db_conn.close()

        # Check if user exists and password hash matches
        if result and verify_password(result[0], result[1], password):
            session['user'] = username # Initialize session
            print(f"[+] Web Login successful for user: {username}")
            return redirect(url_for('dashboard'))
        else:
            print(f"[-] Failed web login attempt for user: {username}")
            flash("Invalid username or password!")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # Route protection: Only allow authenticated users
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # List all files currently in the secure storage directory
    files = os.listdir(STORAGE_DIR)
    return render_template('dashboard.html', username=session['user'], files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    if 'file' not in request.files:
        flash("No file part selected!")
        return redirect(url_for('dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash("No file chosen for upload!")
        return redirect(url_for('dashboard'))
        
    if file:
        safe_filename = secure_filename(file.filename)
        file_path = os.path.join(STORAGE_DIR, safe_filename)
        file.save(file_path)
        
        # Centralized Sanitization Call
        if safe_filename.lower().endswith('.json'):
            sanitize_json_metadata(file_path)
            
        print(f"[+] File '{safe_filename}' uploaded successfully via Web UI.")
        flash(f"File '{safe_filename}' uploaded successfully.")
        
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    print(f"[+] File '{filename}' requested for download via Web UI.")
    return send_from_directory(STORAGE_DIR, filename, as_attachment=True)

@app.route('/logout')
def logout():
    username = session.get('user')
    session.pop('user', None)
    print(f"[+] User '{username}' logged out from Web UI.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Run the web server locally on port 8080 with TLS (HTTPS) enabled
    app.run(debug=True, port=8080, ssl_context=('server.crt', 'server.key'))