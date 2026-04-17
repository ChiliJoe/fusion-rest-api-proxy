"""
auth.py — JWT user-assertion creation and OCI IAM backend token exchange.
"""

import calendar
import json
import logging
import uuid
from datetime import datetime, timedelta

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


def load_private_key(private_key_pem: str, password: str) -> bytes:
    """
    Load a password-protected PEM private key and re-serialize it without encryption.

    Decrypts the key in-memory and returns unencrypted PKCS8 PEM bytes, which
    is the format PyJWT expects for RS256 signing.

    Args:
        private_key_pem (str): PEM-encoded private key (may be passphrase-protected).
        password (str): Passphrase protecting the private key.

    Returns:
        bytes: Unencrypted PKCS8 PEM bytes suitable for jwt.encode().

    Raises:
        ValueError: If the key or passphrase is invalid.
    """
    if isinstance(password, str):
        password = password.encode()

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=password,
    )

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _get_unix_timestamp(dt: datetime) -> int:
    """
    Convert a UTC datetime to a Unix timestamp integer.

    Uses calendar.timegm to avoid local-timezone conversion side-effects.

    Args:
        dt (datetime): A UTC datetime object.

    Returns:
        int: Unix timestamp in seconds.
    """
    return calendar.timegm(dt.utctimetuple())


def create_jwt_token(
    private_key_pem: str,
    key_password: str,
    issuer: str,
    principal: str,
    audience: str,
    kid: str,
    expiry_minutes: int = 60,
) -> str:
    """
    Create and sign a JWT user-assertion token for the OCI IAM jwt-bearer grant.

    Payload claims:
        sub   — end-user principal (x-username header value)
        iss   — confidential app client_id (JWT_ISSUER config)
        aud   — JWT audience (JWT_AUDIENCE config)
        jti   — unique UUID4 to prevent token replay
        iat   — issued-at Unix timestamp
        exp   — expiry Unix timestamp

    JWT header:
        alg   — RS256
        typ   — JWT
        kid   — key identifier (set to issuer / JWT_ISSUER per OCI IAM convention)

    Args:
        private_key_pem (str): PEM-encoded private key string from Vault.
        key_password (str): Passphrase for the private key from Vault.
        issuer (str): JWT_ISSUER config value (also used as kid).
        principal (str): Subject claim — the value of the x-username header.
        audience (str): JWT_AUDIENCE config value.
        kid (str): Key ID for the JWT header — should equal issuer.
        expiry_minutes (int): Token lifetime in minutes (default 60).

    Returns:
        str: Encoded and signed JWT string.

    Raises:
        ValueError: If the private key cannot be loaded.
        Exception: If JWT encoding fails.
    """
    private_key = load_private_key(private_key_pem, key_password)

    current_time = datetime.utcnow()
    expiry_time = current_time + timedelta(minutes=expiry_minutes)

    payload = {
        "sub": principal,
        "jti": str(uuid.uuid4()),
        "iat": _get_unix_timestamp(current_time),
        "exp": _get_unix_timestamp(expiry_time),
        "iss": issuer,
        "aud": audience
    }

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    }

    logger.debug("JWT payload claims: %s", payload)
    logger.debug("JWT header: %s", headers)

    token = jwt.encode(
        payload=payload,
        key=private_key,
        algorithm="RS256",
        headers=headers,
    )

    logger.info("JWT user-assertion created for principal: %s", principal)
    logger.debug("JWT user-assertion token: %s", token)
    return token


def get_backend_token(
    iam_base_url: str,
    client_id: str,
    client_secret: str,
    scope: str,
    private_key_pem: str,
    key_password: str,
    user_principal: str,
    kid: str,
    issuer: str,
) -> str:
    """
    Obtain a backend OAuth access token from OCI IAM via the JWT bearer grant.

    Flow:
      1. Build a signed JWT user-assertion with create_jwt_token().
      2. POST to {iam_base_url}/oauth2/v1/token with grant_type
         urn:ietf:params:oauth:grant-type:jwt-bearer, using HTTP Basic Auth
         (client_id / client_secret).
      3. Return the access_token from the JSON response.

    Args:
        iam_base_url (str): OCI_IAM_BASE_URL config value, e.g.
            "https://idcs-GUID.identity.oraclecloud.com:443".
        client_id (str): JWT_CLIENT_ID config — the confidential app client ID used
            for HTTP Basic Auth against the token endpoint.
        client_secret (str): JWT_CLIENT_SECRET config.
        scope (str): TARGET_SCOPE config.
        private_key_pem (str): PEM private key retrieved from Vault.
        key_password (str): Key passphrase retrieved from Vault.
        user_principal (str): Username from the x-username request header.
        kid (str): Key ID for the JWT header (JWT_KID config).
        issuer (str): JWT_ISSUER config — the iss claim in the user-assertion JWT.

    Returns:
        str: The access_token string from the IAM token response.

    Raises:
        requests.HTTPError: If the IAM endpoint returns a non-2xx status.
        ValueError: If the token response does not contain an access_token.
        Exception: On any other network or parsing failure.
    """
    logger.info("Retrieving IAM backend token for principal: %s", user_principal)

    user_assertion = create_jwt_token(
        private_key_pem=private_key_pem,
        key_password=key_password,
        issuer=issuer,
        principal=user_principal,
        audience=iam_base_url,
        kid=kid,
    )

    token_endpoint = f"{iam_base_url.rstrip('/')}/oauth2/v1/token"
    logger.debug("IAM token endpoint: %s", token_endpoint)

    resp = requests.post(
        url=token_endpoint,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": user_assertion,
            "scope": scope,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"},
        auth=HTTPBasicAuth(client_id, client_secret),
        timeout=30,
    )

    logger.debug("IAM token response: HTTP %d", resp.status_code)
    resp.raise_for_status()

    token_data = resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise ValueError(
            f"IAM token response missing access_token. Response: {resp.text}"
        )

    logger.debug(
        "IAM token retrieved: token_type=%s  expires_in=%s",
        token_data.get("token_type"), token_data.get("expires_in"),
    )
    return access_token
