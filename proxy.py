"""
proxy.py — HTTP proxying to backend Fusion REST API and response URL rewriting.
"""

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)

# Headers that must not be forwarded to the backend.
# Includes hop-by-hop headers, FDK-internal headers, and OCI-internal headers.
_STRIP_HEADERS = frozenset([
    "transfer-encoding",
    "connection",
    "host",
    "content-length",           # requests recalculates this automatically
    "x-target-endpoint",
    "x-username",
    "x-content-sha256",
    "x-real-ip",
    "x-forwarded-for",
    "forwarded",
    "cdn-loop",
])

# Prefixes for FDK-internal and OCI-internal headers to strip
_STRIP_PREFIXES = ("fn-", "oci-")

# Content-Type values for which URL rewriting applies
_TEXT_CONTENT_TYPES = (
    "application/json",
    "application/",     # catches application/*+json, application/xml, etc.
    "text/",
)


def build_target_url(target_endpoint: str, request_url: str) -> str:
    """
    Append query parameters from the FDK request URL to the target endpoint URL.

    Only the query string from request_url is used; the path from request_url
    is ignored because the target_endpoint already contains the full backend path
    (supplied by the API Gateway via the x-target-endpoint header).

    Existing query parameters on target_endpoint are preserved; incoming
    parameters are merged on top.

    Args:
        target_endpoint (str): Full URL from the x-target-endpoint header,
            e.g. "https://oracle.com/test/123".
        request_url (str): ctx.RequestURL() value, e.g. "/dep1/test/123?query=Y".

    Returns:
        str: Target URL with query parameters appended,
            e.g. "https://oracle.com/test/123?query=Y".
    """
    parsed_target = urlparse(target_endpoint)
    parsed_request = urlparse(request_url)

    # Merge query params: target params first, incoming params override
    target_params = parse_qs(parsed_target.query, keep_blank_values=True)
    incoming_params = parse_qs(parsed_request.query, keep_blank_values=True)
    merged_params = {**target_params, **incoming_params}

    merged_query = urlencode(merged_params, doseq=True) if merged_params else ""

    final = urlunparse((
        parsed_target.scheme,
        parsed_target.netloc,
        parsed_target.path,
        parsed_target.params,
        merged_query,
        "",  # strip any fragment
    ))

    logger.debug("Target URL: %s", final)
    return final


def proxy_request(
    method: str,
    target_url: str,
    headers: dict,
    body: bytes,
    access_token: str,
) -> requests.Response:
    """
    Forward the incoming request to the target URL and return the raw response.

    Header handling:
      - FDK delivers multi-value headers as lists; the last element of each
        list is used (the outermost client-supplied value).
      - Hop-by-hop, FDK-internal (fn-*), OCI-internal (oci-*), and proxy
        metadata headers are stripped before forwarding.
      - Authorization is replaced with "Bearer {access_token}".
      - Accept is set to "application/json" for Fusion REST compatibility.
      - Content-Type is preserved if present in the original headers.

    Args:
        method (str): HTTP method from ctx.Method() (GET, POST, PATCH, etc.).
        target_url (str): Fully-qualified URL produced by build_target_url().
        headers (dict): ctx.Headers() dict — values may be lists (FDK format).
        body (bytes): Raw request body bytes (data.read() from handler).
        access_token (str): Bearer token from get_backend_token().

    Returns:
        requests.Response: The unmodified response from the backend.

    Raises:
        requests.exceptions.RequestException: On any network-level failure.
    """
    forward_headers = {}

    for key, value in headers.items():
        key_lower = key.lower()

        # Strip hop-by-hop, FDK-internal, and OCI-internal headers
        if key_lower in _STRIP_HEADERS:
            continue
        if any(key_lower.startswith(prefix) for prefix in _STRIP_PREFIXES):
            continue

        # FDK wraps multi-value headers as lists; take the last element
        # (the outermost value, i.e. the one the original client supplied)
        if isinstance(value, list):
            value = value[-1]

        forward_headers[key] = value

    # Always override Authorization and Accept for Fusion REST compatibility
    forward_headers["Authorization"] = f"Bearer {access_token}"
    forward_headers["Accept"] = "application/json"

    logger.info("Proxying %s %s", method.upper(), target_url)

    return requests.request(
        method=method.upper(),
        url=target_url,
        headers=forward_headers,
        data=body or None,
        timeout=270,    # leaves ~30 s headroom within the 300 s function timeout
        allow_redirects=True,
    )


def rewrite_urls(body: str, backend_base_url: str, frontend_base_url: str) -> str:
    """
    Replace all occurrences of backend_base_url in the response body with
    frontend_base_url.

    A fixed-string replacement is used because only the base URL (scheme +
    host) changes; the path structure remains identical. This handles JSON,
    XML, and HTML response bodies uniformly.

    Args:
        body (str): Response body text from the backend (UTF-8 decoded).
        backend_base_url (str): Scheme + host of the backend to replace,
            e.g. "https://oracle.com".
        frontend_base_url (str): Replacement scheme + host + path prefix,
            e.g. "https://apigw-test.com/dep1".

    Returns:
        str: Body with all backend base URLs replaced by the frontend URL.
    """
    return body.replace(backend_base_url, frontend_base_url)


def compute_url_rewrite_params(
    target_endpoint: str,
    request_url: str,
    host_header,
) -> tuple[str, str] | tuple[None, None]:
    """
    Derive the backend_base_url and frontend_base_url needed for URL rewriting.

    Algorithm:
      1. backend_base_url = scheme + "://" + netloc  of target_endpoint
      2. frontend_host    = first entry in host_header that is not "localhost"
      3. prefix           = leading portion of the frontend path that precedes
                            the backend path (their common suffix)
      4. frontend_base_url = scheme + "://" + frontend_host + prefix

    Example:
      target_endpoint = "https://oracle.com/test/123"
      request_url     = "/dep1/test/123?query=Y"
      host_header     = ["localhost", "apigw-test.com"]

      => backend_base_url  = "https://oracle.com"
      => frontend_base_url = "https://apigw-test.com/dep1"

    Args:
        target_endpoint (str): x-target-endpoint header value.
        request_url (str): ctx.RequestURL() value.
        host_header: "host" header value — may be a str or a list of str.

    Returns:
        tuple[str, str]: (backend_base_url, frontend_base_url), or
        tuple[None, None]: if no usable frontend host is found (rewriting skipped).
    """
    parsed_target = urlparse(target_endpoint)
    backend_base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
    backend_path = parsed_target.path

    # Normalise host header to a list
    if isinstance(host_header, str):
        hosts = [host_header]
    else:
        hosts = list(host_header)

    frontend_host = next(
        (h for h in hosts if h.lower() != "localhost"), None
    )
    if not frontend_host:
        logger.warning("No non-localhost host found in host header; skipping URL rewrite")
        return None, None

    # Determine the path prefix that exists in the frontend URL but not in the
    # backend URL. Both paths share a common suffix; the prefix is what's left.
    frontend_path = urlparse(request_url).path  # strip query string

    if backend_path and frontend_path.endswith(backend_path):
        prefix = frontend_path[: len(frontend_path) - len(backend_path)]
    else:
        logger.warning(
            "Backend path %r is not a suffix of frontend path %r; "
            "URL rewrite will use empty prefix",
            backend_path,
            frontend_path,
        )
        prefix = ""

    frontend_base_url = f"{parsed_target.scheme}://{frontend_host}{prefix}"
    logger.debug("URL rewrite: %s -> %s", backend_base_url, frontend_base_url)
    return backend_base_url, frontend_base_url


def is_text_response(content_type: str) -> bool:
    """
    Return True if the response Content-Type warrants URL rewriting.

    Covers application/json, application/*+json, application/xml, text/*.

    Args:
        content_type (str): Value of the Content-Type response header.

    Returns:
        bool: True if the body should be decoded and rewritten.
    """
    ct_lower = (content_type or "").lower()
    return any(ct_lower.startswith(prefix) for prefix in _TEXT_CONTENT_TYPES)
