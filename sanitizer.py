import os
import json

def sanitize_json_metadata(file_path):
    """
    Validates JSON structural schema and sanitizes against prototype pollution vectors.
    Deletes the file if it contains malicious formatting or structural violations.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Structure Check: Ensure the root element is a JSON object (dictionary)
        if not isinstance(data, dict):
            raise ValueError("Invalid JSON schema: Root payload must be an object.")
            
        # Security Check: Mitigate Prototype Pollution targets
        dangerous_keys = ['__proto__', 'constructor', 'prototype']
        keys_to_remove = [k for k in data.keys() if k in dangerous_keys]
        
        for key in keys_to_remove:
            del data[key]
            print(f"[!] Security Alert: Sanitized dangerous key '{key}' from JSON.")
                
        # Rewrite the file with clean, structured configuration data
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
            
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[-] Defended Threat: Malicious/Invalid JSON structure rejected: {e}")
        if os.path.exists(file_path):
            os.remove(file_path) # Drop the payload completely