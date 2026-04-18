# Performance TODO

## High Impact

### 1. Cache Vault secrets across warm starts
**File:** `func.py` (lines 101–103), `vault.py`

Every invocation makes 3 sequential Vault HTTP round-trips (`PRIVATE_KEY_OCID`,
`PRIVATE_KEY_PP_OCID`, `JWT_CLIENT_SECRET_OCID`). Each call also instantiates a
new Resource Principal signer and `SecretsClient`.

- [ ] Cache secrets at module level with a TTL (e.g. 5–10 minutes)
- [ ] Fetch all 3 concurrently with `concurrent.futures.ThreadPoolExecutor`

### 2. Cache deserialized private key
**File:** `auth.py` — `load_private_key()`

PEM decryption and PKCS8 re-serialization (CPU-intensive) runs on every request
even though the key and passphrase don't change between warm starts.

- [ ] Cache the deserialized key bytes alongside the Vault secret cache

## Medium Impact

### 3. Cache IAM backend tokens per user
**File:** `auth.py` — `get_backend_token()`

Full JWT sign + HTTP POST to the IAM token endpoint on every request. Redundant
when the same `x-username` makes multiple requests within the token's
`expires_in` window.

- [ ] Add an LRU cache keyed on `user_principal` with expiry from `expires_in`

### 4. Remove redundant full-body scan for debug logging
**File:** `func.py` (lines 152–153)

`.count()` scans the entire response body for a debug log, then `rewrite_urls()`
scans it again — doubling string traversal cost on large responses.

- [ ] Remove the `.count()` call or derive the count from the rewrite result

## Low Impact

### 5. Reuse OCI signer within a single invocation
**File:** `vault.py`

`get_resource_principals_signer()` is called 3 times per invocation. Safe to
reuse within a single synchronous handler call.

- [ ] Create the signer once in `handler()` and pass it to all `get_secret()` calls

### 6. Consider increasing memory limit
**File:** `func.yaml`

`memory: 256` may be tight when proxying large Fusion REST responses (full body
held in memory twice during URL rewriting).

- [ ] Monitor peak memory; bump to 512 MB if needed
