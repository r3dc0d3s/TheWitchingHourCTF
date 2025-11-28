#!/usr/bin/env python3
import os, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 1. SETUP
# Random keys every time script runs (prevents static analysis)
KEY = os.urandom(16)
IV = os.urandom(16)
FLAG = "CyberZ{cbc_b1t_fl1pp1ng_is_th3_r34l_d34l}"

def get_token(username):
    # Prevent easy win
    if "admin" in username: 
        return "Forbidden"
    
    # Format: "user={username};role=guest"
    # "user=" is 5 bytes. 
    # We rely on the player aligning "bdmin" to the start of the next block.
    data = f"user={username};role=guest".encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(data, 16)).hex()

def verify_token(token_hex):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        # Decrypt
        pt = unpad(cipher.decrypt(bytes.fromhex(token_hex)), 16)
        
        # THE CHECK: If they managed to flip 'guest' to 'admin'
        if b";role=admin" in pt: 
            return True
    except:
        pass
    return False

# 2. MENU
print("--- CBC BIT-FLIPPER ---")
sys.stdout.flush()

while True:
    print("\n1. Register (Get Token)")
    print("2. Login (Submit Token)")
    try:
        choice = input("> ").strip()
        
        if choice == '1':
            u = input("Username: ").strip()
            token = get_token(u)
            print(f"Token: {token}")
            
        elif choice == '2':
            t = input("Token: ").strip()
            if verify_token(t): 
                print(f"[+] SUCCESS! Flag: {FLAG}")
                sys.exit(0)
            else: 
                print("[-] Access Denied. You are not admin.")
                
    except:
        break