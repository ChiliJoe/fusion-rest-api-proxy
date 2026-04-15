"""
vault.py — OCI Vault secret retrieval using Resource Principal authentication.
"""

import base64
import logging

import oci
import oci.auth.signers
import oci.secrets

logger = logging.getLogger(__name__)


def get_secret(secret_ocid: str) -> str:
    """
    Retrieve the plaintext value of an OCI Vault secret using Resource Principal auth.

    The signer is created on every call (not at module level) to avoid RPST
    token race conditions at cold start.

    The Vault API returns secret content as a base64-encoded string; this
    function decodes it and returns the raw string value.

    Args:
        secret_ocid (str): The full OCID of the Vault secret to retrieve.

    Returns:
        str: The decoded plaintext secret content.

    Raises:
        ValueError: If secret_ocid is empty or None.
        oci.exceptions.ServiceError: If the Vault API call fails (e.g. not
            found, permission denied).
    """
    if not secret_ocid:
        raise ValueError("secret_ocid must not be empty")

    logger.info("Retrieving Vault secret: %s", secret_ocid)

    # Signer created here (not at module level) to avoid RPST token expiry
    # race conditions at cold start — same pattern as existing OCI SDK calls.
    signer = oci.auth.signers.get_resource_principals_signer()

    # SecretsClient is the read-plane client for secret content retrieval.
    # (oci.vault manages lifecycle; oci.secrets retrieves content.)
    client = oci.secrets.SecretsClient({}, signer=signer)

    bundle = client.get_secret_bundle(secret_id=secret_ocid)

    # bundle.data.secret_bundle_content.content is the base64-encoded secret value
    # for the default BASE64_SECRET_BUNDLE content type.
    encoded_content = bundle.data.secret_bundle_content.content
    return base64.b64decode(encoded_content).decode("utf-8")
