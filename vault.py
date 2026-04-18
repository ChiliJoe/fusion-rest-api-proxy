"""
vault.py — OCI Vault secret retrieval using Resource Principal authentication.
"""


import base64
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import oci
import oci.auth.signers
import oci.secrets

logger = logging.getLogger(__name__)

_CACHE_TTL = 300  # seconds — refresh secrets every 5 minutes on warm starts
_SECRET_CACHE: dict[str, tuple[str, float]] = {}  # ocid -> (value, expiry_monotonic)


def _cache_get(secret_ocid: str) -> str | None:
    entry = _SECRET_CACHE.get(secret_ocid)
    if entry and time.monotonic() < entry[1]:
        return entry[0]
    return None


def _cache_set(secret_ocid: str, value: str) -> None:
    _SECRET_CACHE[secret_ocid] = (value, time.monotonic() + _CACHE_TTL)


def get_secret(secret_ocid: str, signer=None) -> str:
    """
    Retrieve the plaintext value of an OCI Vault secret using Resource Principal auth.

    Results are cached at module level for _CACHE_TTL seconds so that warm-start
    invocations avoid redundant network round-trips to the Vault API.

    Args:
        secret_ocid (str): The full OCID of the Vault secret to retrieve.
        signer: Optional pre-built Resource Principal signer. Created on demand
            if not provided (cold-start or cache-miss path).

    Returns:
        str: The decoded plaintext secret content.

    Raises:
        ValueError: If secret_ocid is empty or None.
        oci.exceptions.ServiceError: If the Vault API call fails.
    """
    if not secret_ocid:
        raise ValueError("secret_ocid must not be empty")

    cached = _cache_get(secret_ocid)
    if cached is not None:
        logger.debug("Vault secret cache hit: %s", secret_ocid)
        return cached

    logger.info("Retrieving Vault secret: %s", secret_ocid)

    if signer is None:
        signer = oci.auth.signers.get_resource_principals_signer()

    client = oci.secrets.SecretsClient({}, signer=signer)
    bundle = client.get_secret_bundle(secret_id=secret_ocid)

    encoded_content = bundle.data.secret_bundle_content.content
    secret_value = base64.b64decode(encoded_content).decode("utf-8")

    logger.debug(
        "Vault secret retrieved: ocid=%s  version=%s  length=%d",
        secret_ocid,
        bundle.data.version_number,
        len(secret_value),
    )

    _cache_set(secret_ocid, secret_value)
    return secret_value


def get_secrets_concurrent(ocids: list[str]) -> list[str]:
    """
    Fetch multiple Vault secrets in parallel, reusing a single Resource Principal signer.

    All cache-hit secrets are returned immediately without network I/O.
    Only cache-miss OCIDs are fetched; a single signer is created and shared
    across all concurrent workers.

    Args:
        ocids (list[str]): Ordered list of secret OCIDs to retrieve.

    Returns:
        list[str]: Secret values in the same order as ocids.
    """
    results: list[str | None] = [None] * len(ocids)

    # Resolve cache hits without touching the network
    miss_indices = []
    for i, ocid in enumerate(ocids):
        cached = _cache_get(ocid)
        if cached is not None:
            logger.debug("Vault secret cache hit: %s", ocid)
            results[i] = cached
        else:
            miss_indices.append(i)

    if not miss_indices:
        return results  # type: ignore[return-value]

    # Create signer once for all cache-miss fetches
    signer = oci.auth.signers.get_resource_principals_signer()

    with ThreadPoolExecutor(max_workers=len(miss_indices)) as executor:
        future_to_index = {
            executor.submit(get_secret, ocids[i], signer): i
            for i in miss_indices
        }
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            results[idx] = future.result()

    return results  # type: ignore[return-value]
