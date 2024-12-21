

# Toty - Secure TOTP Generator

Toty is a secure command-line TOTP (Time-based One-Time Password) generator and manager that safely stores your TOTP secrets using encryption.

## Features
- Secure storage of TOTP secrets using encryption
- Master password protection
- Configurable token parameters (period, digits, hash function)
- Support for multiple TOTP tokens
- User-friendly command-line interface

## Installation

```bash
pip install git+https://github.com/yourusername/toty.git
```

## Configuration

The master password can be set up in two ways:

1. **Environment Variable** (recommended for personal use):
```bash
export TOTY_MASTER='your_master_password'
```

2. **Interactive Prompt**:
If no environment variable is set, you'll be prompted to enter the master password each time.

## Usage

### Basic Commands

```bash
# Store a new TOTP token
toty nickname -s YOUR_SECRET

# Additional optional parameters
toty nickname -s YOUR_SECRET -i "Issuer Name" -c "Comments" -t TOTP -H SHA1 -p 30 -d 6

# Get a TOTP code
toty nickname
```

### Parameters

- `nickname`: Required. Name to identify your TOTP token
- `-s, --secret`: Secret token to store (required when registering)
- `-i, --issuer`: Token issuer name
- `-c, --comments`: Additional notes for the token
- `-t, --type`: Token type (default: TOTP)
- `-H, --hash-function`: Hash function to use (default: SHA1)
- `-p, --period`: Token refresh period in seconds (default: 30)
- `-d, --digits`: Number of digits in generated token (default: 6)

## Security

- All secrets are encrypted using Fernet (symmetric encryption)
- Master password is never stored, only used for key derivation
- Database is stored in `~/.config/toty/main.db` with appropriate permissions
- Uses secure password entry for master password input

## Data Storage

The application stores its encrypted database in:
```
~/.config/toty/main.db
```

## Dependencies

- cryptography
- rich
- sqlite3 (built-in)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT
