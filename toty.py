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
    def __init__(self, db_path='~/.config/toty/main.db'):
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
                    issuer TEXT,
                    comments TEXT,
                    type TEXT DEFAULT 'TOTP',
                    hash_function TEXT DEFAULT 'SHA1',
                    period INTEGER DEFAULT 30,
                    digits INTEGER DEFAULT 6,
                    last_used TIMESTAMP
                )
            ''')

    def initialize(self, master_password=None):
        if master_password is None:
            master_password = getpass.getpass("Enter master password: ")
        self.master_password = master_password
        self.fernet = Fernet(self._derive_key(master_password))
        self._init_db()

    def store_token(self, nickname, secret, issuer=None, comments=None, 
                    type='TOTP', hash_function='SHA1', 
                    period=30, digits=6):
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
                (nickname, encrypted_secret, issuer, comments, type, 
                 hash_function, period, digits, last_used) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (nickname, encrypted, issuer, comments, type, 
                  hash_function, period, digits))

    def get_token(self, nickname):
        if not self.fernet:
            raise ValueError("Must initialize with master password first")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT encrypted_secret, period, digits FROM tokens WHERE nickname = ?', 
                (nickname,)
            )
            row = cursor.fetchone()
            
            if not row:
                raise ValueError(f"No token found for nickname: {nickname}")
                
            encrypted_secret, period, digits = row
            secret = self.fernet.decrypt(encrypted_secret).decode()
            
            conn.execute(
                'UPDATE tokens SET last_used = CURRENT_TIMESTAMP WHERE nickname = ?',
                (nickname,)
            )
            
            return get_totp_token(secret, period=period, digits=digits)

    def delete_token(self, nickname):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('DELETE FROM tokens WHERE nickname = ?', (nickname,))
            if cursor.rowcount == 0:
                raise ValueError(f"No token found for nickname: {nickname}")
            conn.commit()

    def list_tokens(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT nickname, issuer, comments, type, last_used 
                FROM tokens 
                ORDER BY nickname
            ''')
            return cursor.fetchall()

def get_hotp_token(secret, intervals_no, digits=6):
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
    code = code % (10 ** digits)
    return '{:0{width}d}'.format(code, width=digits)

def get_totp_token(secret, period=30, digits=6):
    """Generate TOTP token"""
    intervals_no = int(time.time()) // period
    return get_hotp_token(secret, intervals_no, digits)

def parse_args():
    parser = argparse.ArgumentParser(description='Secure TOTP generator')
    # Required arguments
    parser.add_argument('nickname', help='Nickname for the TOTP token')
    parser.add_argument('-s', '--secret', 
                       help='Secret token to store (if registering)')
    
    # Optional arguments
    parser.add_argument('-i', '--issuer', help='Token issuer name')
    parser.add_argument('-c', '--comments', help='Additional comments or notes for the token')
    parser.add_argument('-t', '--type', default='TOTP', 
                       help='Token type (default: TOTP)')
    parser.add_argument('-H', '--hash-function', default='SHA1', 
                       help='Hash function to use (default: SHA1)')
    parser.add_argument('-p', '--period', type=int, default=30, 
                       help='Token refresh period in seconds (default: 30)')
    parser.add_argument('-d', '--digits', type=int, default=6, 
                       help='Number of digits in generated token (default: 6)')
    parser.add_argument('-l','--list', action='store_true', help='List all stored tokens')
    parser.add_argument('-D','--delete', action='store_true', help='Delete the specified token')
    
    return parser.parse_args()

def main():
    args = parse_args()
    totp = SecureTotp()
    
    try:
        totp.initialize()
        
        if args.list:
            tokens = totp.list_tokens()
            if not tokens:
                print("No tokens stored.")
            for token in tokens:
                nickname, issuer, comments, token_type, last_used = token
                print(f"Nickname: {nickname}")
                print(f"Issuer: {issuer or 'N/A'}")
                print(f"Comments: {comments or 'N/A'}")
                print(f"Type: {token_type}")
                print(f"Last Used: {last_used}")
                print("-" * 30)
        elif args.delete:
            totp.delete_token(args.nickname)
            print(f"Successfully deleted token for {args.nickname}")
        elif args.secret:
            # Register new token
            totp.store_token(
                args.nickname, 
                args.secret,
                issuer=args.issuer,
                comments=args.comments,
                type=args.type,
                hash_function=args.hash_function,
                period=args.period,
                digits=args.digits
            )
            print(f"Successfully stored token for {args.nickname}")
        else:
            # Generate token
            token = totp.get_token(args.nickname)
            print(token)
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
