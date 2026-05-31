import sqlite3
import hashlib
import os

def hash_password(password):
    """Generates a secure random 32-byte salt and hashes the password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, pwd_hash

def init_database():
    """Initializes the database and seeds a test user."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt BLOB,
            password_hash BLOB
        )
    ''')
    
    # Insert a test user (Username: admin, Password: password123)
    username = "admin2"
    password = "password12"
    salt, pwd_hash = hash_password(password)
    
    try:
        cursor.execute("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)", 
                       (username, salt, pwd_hash))
        conn.commit()
        print("[+] Database initialized. Test user 'admin' with password 'password123' created.")
    except sqlite3.IntegrityError:
        print("[!] Database already initialized. Test user exists.")
        
    conn.close()

if __name__ == "__main__":
    init_database()