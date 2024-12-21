import argparse
import os
import subprocess

def parse_args():
    parser = argparse.ArgumentParser(description='TOTP generator')
    subparsers = parser.add_subparsers(dest='command')

    register_parser = subparsers.add_parser('register', help='Register a new secret token')
    register_parser.add_argument('-n', '--nickname', required=True, help='Nickname to store the secret token')
    register_parser.add_argument('-s', '--secret-token', required=True, help='Secret token to store')

    generate_parser = subparsers.add_parser('generate', help='Generate TOTP token for a registered nickname')
    generate_parser.add_argument('-n', '--nickname', required=True, help='Nickname to retrieve the secret token from')

    parser.set_defaults(command=None)
    return parser.parse_args()

def register(nickname, secret_token):
    """Register a new secret token"""
    with open(os.path.join(os.path.expanduser('~'), '.totp Secrets'), 'a') as f:
        f.write(f'{nickname}:{secret_token}\n')
    
    print(f'Secret token for {nickname} stored safely.')

def generate(nickname):
    """Generate TOTP token for a registered nickname"""
    try:
        with open(os.path.join(os.path.expanduser('~'), '.totp Secrets'), 'r') as f:
            for line in f.readlines():
                lNickname, lSecretToken = line.strip().split(':')
                if lNickname == nickname:
                    return subprocess.check_output(['oathtool', '-b', '--totp', lSecretToken]).decode().strip()
    except FileNotFoundError:
        print('No registered nicknames found.')
        return None

    print(f'Nickname "{nickname}" not found. Please register it first using toty -r.')

def main():
    args = parse_args()

    if args.command == 'register':
        nickname = args.nickname
        secret_token = args.secret_token
        register(nickname, secret_token)
    elif args.command == 'generate':
        nickname = args.nickname
        token = generate(nickname)
        print(token)
    else:
        parser = argparse.ArgumentParser(description='TOTP generator')
        subparsers = parser.add_subparsers(dest='command')

        register_parser = subparsers.add_parser('register', help='Register a new secret token')
        register_parser.add_argument('-n', '--nickname', required=True, help='Nickname to store the secret token')
        register_parser.add_argument('-s', '--secret-token', required=True, help='Secret token to store')

        generate_parser = subparsers.add_parser('generate', help='Generate TOTP token for a registered nickname')
        generate_parser.add_argument('-n', '--nickname', required=True, help='Nickname to retrieve the secret token from')

        parser.print_help()

if __name__ == '__main__':
    main()
