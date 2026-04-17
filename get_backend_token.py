#!/usr/bin/env python3
"""
get_backend_token.py — CLI utility for testing the full OAuth jwt-bearer token exchange.

Calls get_backend_token() from auth.py and prints the resulting IAM access token.

Usage:
    python get_backend_token.py --pem-file key.pem --username user@example.com \
        --issuer <client_id> --iam-base-url <iam_url> --kid <key_id>
"""

import argparse
import getpass
import sys

from auth import get_backend_token, load_private_key


def _load_pem(path: str) -> str:
    with open(path) as f:
        return f.read()


def _resolve_password(pem: str) -> str:
    try:
        load_private_key(pem, "")
        return ""
    except (ValueError, TypeError):
        return getpass.getpass("Private key passphrase: ")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Obtain an IAM backend access token via the OAuth jwt-bearer grant."
    )
    parser.add_argument("--pem-file", "-k", required=True, metavar="PATH",
                        help="Path to the RSA private key PEM file")
    parser.add_argument("--username", "-u", required=True, metavar="PRINCIPAL",
                        help="End-user principal (JWT sub claim)")
    parser.add_argument("--client-id", required=True, metavar="CLIENT_ID",
                        help="Confidential app client ID for HTTP Basic Auth (JWT_CLIENT_ID)")
    parser.add_argument("--issuer", required=True, metavar="ISSUER",
                        help="JWT iss claim value (JWT_ISSUER), e.g. https://identity.oraclecloud.com/")
    parser.add_argument("--iam-base-url", required=True, metavar="URL",
                        help="OCI IAM base URL (OCI_IAM_BASE_URL), e.g. https://idcs-<guid>.identity.oraclecloud.com:443")
    parser.add_argument("--kid", required=True, metavar="KEY_ID",
                        help="Key ID for the JWT header")
    parser.add_argument("--scope", default="/", metavar="SCOPE",
                        help="OAuth scope (default: /)")

    args = parser.parse_args()

    try:
        pem = _load_pem(args.pem_file)
    except OSError as e:
        print(f"Error reading PEM file: {e}", file=sys.stderr)
        sys.exit(1)

    key_password = _resolve_password(pem)
    client_secret = getpass.getpass("Client secret: ")

    try:
        token = get_backend_token(
            iam_base_url=args.iam_base_url,
            client_id=args.client_id,
            client_secret=client_secret,
            scope=args.scope,
            private_key_pem=pem,
            key_password=key_password,
            user_principal=args.username,
            kid=args.kid,
            issuer=args.issuer,
        )
    except Exception as e:
        print(f"Error obtaining backend token: {e}", file=sys.stderr)
        sys.exit(1)

    print(token)


if __name__ == "__main__":
    main()
