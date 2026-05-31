# view_db.py
import sqlite3

def view_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT username, salt, password_hash FROM users")
        rows = cursor.fetchall()
        
        print("\n" + "="*85)
        print(f"{'USERNAME':<12} | {'SALT (Hexadecimal Prefix)':<32} | {'PASSWORD HASH (Hexadecimal Prefix)':<32}")
        print("="*85)
        
        for row in rows:
            username = row[0]
            # Convert secure binary bytes to readable Hex strings for demonstration
            salt_hex = row[1].hex()[:28] + "..."
            hash_hex = row[2].hex()[:28] + "..."
            
            print(f"{username:<12} | {salt_hex:<32} | {hash_hex:<32}")
        print("="*85 + "\n")
        
    except sqlite3.OperationalError:
        print("[-] Error: 'users' table or 'users.db' not found. Run setup_db.py first.")
    finally:
        conn.close()

if __name__ == "__main__":
    view_database()