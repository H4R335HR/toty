import argparse
from pathlib import Path
import hmac
import hashlib
import base64
import struct
import time

# Define config path
CONFIG_PATH = Path.home() / '.toty' / 'secrets'

def get_hotp_token(secret, intervals_no):
    """Generate HOTP token"""
    # Decode base32 secret
    try:
        key = base64.b32decode(secret.upper(), casefold=True)
    except Exception:
        raise ValueError("Invalid base32 secret format")
    
    # Pack intervals_no into 8-byte string
    msg = struct.pack(">Q", intervals_no)
    
    # Calculate HMAC-SHA1
    h = hmac.new(key, msg, hashlib.sha1).digest()
    
    # Get offset
    offset = h[-1] & 0xf
    
    # Generate 4-byte code
    code = ((h[offset] & 0x7f) << 24 |
            (h[offset + 1] & 0xff) << 16 |
            (h[offset + 2] & 0xff) << 8 |
            (h[offset + 3] & 0xff))
    
    # Modulus to get 6 digits
    code = code % 1000000
    
    # Zero-pad if necessary
    return '{:06d}'.format(code)

def get_totp_token(secret):
    """Generate TOTP token"""
    # Get current timestamp and calculate number of 30-second intervals
    intervals_no = int(time.time()) // 30
    return get_hotp_token(secret, intervals_no)

def setup_config():
    """Ensure config directory exists"""
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.touch(mode=0o600)  # Create file with restricted permissions

def parse_args():
    parser = argparse.ArgumentParser(description='TOTP generator')
    subparsers = parser.add_subparsers(dest='command')

    # Register command
    register_parser = subparsers.add_parser('register', help='Register a new secret token')
    register_parser.add_argument('-n', '--nickname', required=True, help='Nickname to store the secret token')
    register_parser.add_argument('-s', '--secret-token', required=True, help='Secret token to store')

    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate TOTP token for a registered nickname')
    generate_parser.add_argument('-n', '--nickname', required=True, help='Nickname to retrieve the secret token from')

    parser.set_defaults(command=None)
    return parser.parse_args()

def register(nickname, secret_token):
    """Register a new secret token"""
    try:
        # Validate the secret token by trying to generate a TOTP
        get_totp_token(secret_token)
        
        # Store the token
        with CONFIG_PATH.open('a') as f:
            f.write(f'{nickname}:{secret_token}\n')
        
        print(f'Secret token for {nickname} stored safely.')
    except Exception as e:
        print(f'Error: Invalid secret token format - {str(e)}')

def generate(nickname):
    """Generate TOTP token for a registered nickname"""
    try:
        with CONFIG_PATH.open('r') as f:
            for line in f.readlines():
                stored_nickname, stored_token = line.strip().split(':')
                if stored_nickname == nickname:
                    return get_totp_token(stored_token)
    except FileNotFoundError:
        print('No registered nicknames found.')
        return None
    except Exception as e:
        print(f'Error generating token: {str(e)}')
        return None

    print(f'Nickname "{nickname}" not found. Please register it first using the register command.')
    return None

def main():
    # Ensure config directory exists
    setup_config()
    
    args = parse_args()

    if args.command == 'register':
        register(args.nickname, args.secret_token)
    elif args.command == 'generate':
        token = generate(args.nickname)
        if token:
            print(token)
    else:
        print("Please specify a command. Use -h for help.")

if __name__ == "__main__":
    main()
