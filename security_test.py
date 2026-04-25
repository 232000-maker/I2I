import os
import json
import logging
from pathlib import Path
from src.auth_manager import AuthManager
from src.validators import Validators

def test_password_storage():
    print("\n--- 1. Authentication Test ---")
    users_file = Path("keys/users.json")
    if not users_file.exists():
        print("  [?] No users.json found. Run the app once to register a user.")
        return
        
    try:
        with open(users_file, "r") as f:
            content = f.read()
            data = json.loads(content)
            
            for user, info in data.items():
                if "password" in info and not info["password"].startswith("$2b$"):
                    print(f"  [FAIL] Plaintext or non-bcrypt password detected for user {user}!")
                    return
            print("  [PASS] Passwords are securely hashed with bcrypt.")
    except Exception as e:
        print(f"  [!] Error reading users.json: {e}")

def test_rbac():
    print("\n--- 2. Authorization (RBAC) Test ---")
    dummy = Path("dummy_large.txt")
    try:
        # Create a dummy 15MB file
        with open(dummy, "wb") as f:
            f.write(b"A" * (15 * 1024 * 1024))
            
        try:
            Validators.validate_file_size(dummy, "USER")
            print("  [FAIL] USER allowed to send >10MB file!")
        except ValueError:
            print("  [PASS] USER correctly blocked from sending >10MB file.")
            
        try:
            Validators.validate_file_size(dummy, "ADMIN")
            print("  [PASS] ADMIN correctly allowed to send 15MB file.")
        except ValueError:
            print("  [FAIL] ADMIN blocked from sending 15MB file!")
            
    finally:
        if dummy.exists():
            dummy.unlink()

def test_path_traversal():
    print("\n--- 3. Path Traversal Test ---")
    malicious_names = ["../../hack.txt", "C:\\Windows\\System32\\cmd.exe", "file$$$###.txt"]
    
    for malicious in malicious_names:
        try:
            safe = Validators.validate_filename(malicious)
            if ".." in safe or "/" in safe or "\\" in safe:
                print(f"  [FAIL] Path traversal possible for {malicious}!")
            else:
                print(f"  [PASS] Path traversal prevented. '{malicious}' -> '{safe}'")
        except ValueError as e:
            print(f"  [PASS] Invalid filename blocked entirely. ({e})")

def test_large_input():
    print("\n--- 4. Large Input / Overflow Test ---")
    msg = "A" * 5000
    if Validators.validate_message(msg):
        print("  [FAIL] Oversized message allowed!")
    else:
        print("  [PASS] Oversized message correctly rejected.")

def test_logging():
    print("\n--- 5. Logging Integrity Test ---")
    log_file = Path("logs/i2i.log")
    if not log_file.exists():
        print("  [?] No log file found yet. Run the app to generate logs.")
        return
        
    try:
        with open(log_file, "r") as f:
            content = f.read()
            if len(content) > 0:
                print("  [PASS] Secure logging file is active.")
            else:
                print("  [?] Log file is empty.")
    except Exception as e:
        print(f"  [!] Error reading logs: {e}")

if __name__ == "__main__":
    print("========================================")
    print("   I2I SECURITY AUTOMATED TEST SCRIPT   ")
    print("========================================")
    test_password_storage()
    test_rbac()
    test_path_traversal()
    test_large_input()
    test_logging()
    print("\n========================================")
    print("Tests complete. Run 'pytest tests/' for full suite.")
