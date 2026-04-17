#!/usr/bin/env python3
"""
generate_token.py — CLI utility for generating JWT user-assertion tokens from a PEM file.

Usage:
    python generate_token.py --pem-file key.pem --username user@example.com \
        --issuer <client_id> --audience <fusion_base_url> --kid <key_id>
"""

import argparse
import getpass
import sys

from auth import create_jwt_token, load_private_key


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
        description="Generate a JWT user-assertion token from a PEM private key."
    )
    parser.add_argument("--pem-file", "-k", required=True, metavar="PATH",
                        help="Path to the RSA private key PEM file")
    parser.add_argument("--username", "-u", required=True, metavar="PRINCIPAL",
                        help="End-user principal (JWT sub claim)")
    parser.add_argument("--issuer", required=True, metavar="ISSUER",
                        help="JWT iss claim value (JWT_ISSUER), e.g. https://identity.oraclecloud.com/")
    parser.add_argument("--audience", required=True, metavar="URL",
                        help="JWT audience — Fusion tenant base URL (JWT_AUDIENCE)")
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

    password = _resolve_password(pem)

    try:
        token = create_jwt_token(
            private_key_pem=pem,
            key_password=password,
            issuer=args.issuer,
            principal=args.username,
            audience=args.audience,
            scope=args.scope,
            kid=args.kid,
        )
    except Exception as e:
        print(f"Error generating token: {e}", file=sys.stderr)
        sys.exit(1)

    print(token)


if __name__ == "__main__":
    main()
