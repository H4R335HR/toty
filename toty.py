import argparse
from pathlib import Path
import hmac
import hashlib
import base64
import struct
import time
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os

class SecureTotp:
    def __init__(self, db_path='~/.toty/totp.db'):
        self.db_path = os.path.expanduser(db_path)
        self._ensure_db_directory()
        self.master_password = None
        self.fernet = None

    def _ensure_db_directory(self):
        db_dir = os.path.dirname(self.db_path)
        os.makedirs(db_dir, mode=0o700, exist_ok=True)

    def _derive_key(self, master_password):
        salt = b'totp_salt_v1'  # In production, generate and store a unique salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tokens (
                    nickname TEXT PRIMARY KEY,
                    encrypted_secret BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP
                )
            ''')

    def initialize(self, master_password=None):
        if master_password is None:
            master_password = getpass.getpass("Enter master password: ")
        self.master_password = master_password
        self.fernet = Fernet(self._derive_key(master_password))
        self._init_db()

    def store_token(self, nickname, secret):
        if not self.fernet:
            raise ValueError("Must initialize with master password first")
        
        # Validate the secret by generating a test token
        try:
            get_totp_token(secret)
        except Exception as e:
            raise ValueError(f"Invalid secret format: {str(e)}")

        encrypted = self.fernet.encrypt(secret.encode())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO tokens 
                (nickname, encrypted_secret, last_used) 
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (nickname, encrypted))

    def get_token(self, nickname):
        if not self.fernet:
            raise ValueError("Must initialize with master password first")

        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                'SELECT encrypted_secret FROM tokens WHERE nickname = ?', 
                (nickname,)
            ).fetchone()
            
            if not result:
                raise ValueError(f"No token found for nickname: {nickname}")

            conn.execute(
                'UPDATE tokens SET last_used = CURRENT_TIMESTAMP WHERE nickname = ?',
                (nickname,)
            )
            
            encrypted_secret = result[0]
            secret = self.fernet.decrypt(encrypted_secret).decode()
            return get_totp_token(secret)

def get_hotp_token(secret, intervals_no):
    """Generate HOTP token"""
    try:
        key = base64.b32decode(secret.upper(), casefold=True)
    except Exception:
        raise ValueError("Invalid base32 secret format")
    
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0xf
    code = ((h[offset] & 0x7f) << 24 |
            (h[offset + 1] & 0xff) << 16 |
            (h[offset + 2] & 0xff) << 8 |
            (h[offset + 3] & 0xff))
    code = code % 1000000
    return '{:06d}'.format(code)

def get_totp_token(secret):
    """Generate TOTP token"""
    intervals_no = int(time.time()) // 30
    return get_hotp_token(secret, intervals_no)

def parse_args():
    parser = argparse.ArgumentParser(description='Secure TOTP generator')
    parser.add_argument('nickname', help='Nickname for the TOTP token')
    parser.add_argument('-s', '--secret', help='Secret token to store (if registering)')
    return parser.parse_args()

def main():
    args = parse_args()
    totp = SecureTotp()
    
    try:
        totp.initialize()
        
        if args.secret:
            # Register new token
            totp.store_token(args.nickname, args.secret)
            print(f"Successfully stored token for {args.nickname}")
        else:
            # Generate token
            token = totp.get_token(args.nickname)
            print(token)
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
