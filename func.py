"""
func.py — OCI Function entry point for the Fusion REST API proxy.

Orchestrates the full proxy pipeline:
  1. Read config and request context.
  2. Retrieve the private key and passphrase from OCI Vault.
  3. Exchange a signed JWT user-assertion for a backend access token via OCI IAM.
  4. Proxy the upstream request to the Fusion target endpoint.
  5. Rewrite backend URLs in the response body to the API Gateway frontend URL.
  6. Return the transformed response to the API Gateway caller.
"""

import io
import json
import logging
import traceback

from fdk import response

from auth import get_backend_token
from proxy import (
    build_target_url,
    compute_url_rewrite_params,
    is_text_response,
    proxy_request,
    rewrite_urls,
)
from vault import get_secret

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Config keys that must be present and non-empty at startup
_REQUIRED_CONFIG = (
    "JWT_CLIENT_ID",
    "JWT_KID",
    "TARGET_SCOPE",
    "JWT_CLIENT_SECRET_OCID",
    "OCI_IAM_BASE_URL",
    "PRIVATE_KEY_OCID",
    "PRIVATE_KEY_PP_OCID",
)

_DEFAULT_JWT_ISSUER = "https://identity.oraclecloud.com/"
_DEFAULT_JWT_AUDIENCE = "https://identity.oraclecloud.com/"

# Request headers that must be present
_REQUIRED_HEADERS = ("x-username", "x-target-endpoint")


def handler(ctx, data: io.BytesIO = None) -> response.Response:
    """
    OCI Function handler invoked by the API Gateway.

    Reads configuration from ctx.Config() and request metadata from ctx.Headers().
    Returns an HTTP 400 for missing inputs, HTTP 502 for backend/auth failures,
    and HTTP 500 for unexpected internal errors.

    Args:
        ctx: FDK context object providing config, headers, method, and URL.
        data (io.BytesIO): Raw request body forwarded by the API Gateway.

    Returns:
        response.Response: FDK response with status code, headers, and body.
    """
    try:
        cfg = dict(ctx.Config())
        log_level = getattr(logging, cfg.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
        logging.getLogger().setLevel(log_level)
        logger.debug("Config parameters: %s", cfg)
        headers = dict(ctx.Headers())

        # --- Input validation ---
        missing_cfg = [k for k in _REQUIRED_CONFIG if not cfg.get(k, "").strip()]
        if missing_cfg:
            return _error_response(
                ctx, 400,
                f"Missing or empty config parameters: {', '.join(missing_cfg)}",
            )

        # Normalise header values: FDK may deliver them as lists
        def _header(name: str) -> str:
            val = headers.get(name, "")
            return (val[-1] if isinstance(val, list) else val).strip()

        missing_hdrs = [h for h in _REQUIRED_HEADERS if not _header(h)]
        if missing_hdrs:
            return _error_response(
                ctx, 400,
                f"Missing required request headers: {', '.join(missing_hdrs)}",
            )

        user_principal = _header("x-username")
        target_endpoint = _header("x-target-endpoint")
        host_header = headers.get("host", [])

        logger.debug("Request: %s %s", ctx.Method(), ctx.RequestURL())
        logger.debug("Request header keys: %s", sorted(headers.keys()))
        logger.debug("user_principal=%s  target_endpoint=%s", user_principal, target_endpoint)

        # --- Retrieve secrets from OCI Vault ---
        private_key_pem = get_secret(cfg["PRIVATE_KEY_OCID"])
        key_passphrase = get_secret(cfg["PRIVATE_KEY_PP_OCID"])
        client_secret = get_secret(cfg["JWT_CLIENT_SECRET_OCID"])

        jwt_issuer = cfg.get("JWT_ISSUER", "").strip() or _DEFAULT_JWT_ISSUER
        jwt_audience = cfg.get("JWT_AUDIENCE", "").strip() or _DEFAULT_JWT_AUDIENCE
        logger.debug("Resolved jwt_issuer=%s  jwt_audience=%s", jwt_issuer, jwt_audience)

        # --- Exchange JWT user-assertion for backend access token ---
        access_token = get_backend_token(
            iam_base_url=cfg["OCI_IAM_BASE_URL"],
            client_id=cfg["JWT_CLIENT_ID"],
            client_secret=client_secret,
            scope=cfg["TARGET_SCOPE"],
            audience=jwt_audience,
            private_key_pem=private_key_pem,
            key_password=key_passphrase,
            user_principal=user_principal,
            kid=cfg["JWT_KID"],
            issuer=jwt_issuer,
        )

        # --- Build the final backend URL (merge query params) ---
        target_url = build_target_url(target_endpoint, ctx.RequestURL())

        # --- Proxy the request ---
        body_bytes = data.read() if data is not None else b""
        backend_resp = proxy_request(
            method=ctx.Method(),
            target_url=target_url,
            headers=headers,
            body=body_bytes,
            access_token=access_token,
        )

        # --- Rewrite URLs in the response body ---
        resp_content_type = backend_resp.headers.get("Content-Type", "")
        logger.debug(
            "Backend response: HTTP %d  Content-Type=%s  body=%d bytes",
            backend_resp.status_code, resp_content_type, len(backend_resp.content),
        )
        if is_text_response(resp_content_type):
            backend_base_url, frontend_base_url = compute_url_rewrite_params(
                target_endpoint=target_endpoint,
                request_url=ctx.RequestURL(),
                host_header=host_header,
            )
            if backend_base_url and frontend_base_url:
                rewrite_count = backend_resp.text.count(backend_base_url)
                logger.debug("URL rewrite applied: %d occurrence(s) replaced", rewrite_count)
                resp_body = rewrite_urls(
                    backend_resp.text,
                    backend_base_url,
                    frontend_base_url,
                )
            else:
                logger.debug("URL rewrite skipped: no usable frontend host")
                resp_body = backend_resp.text
        else:
            logger.debug("URL rewrite skipped: binary Content-Type")
            resp_body = backend_resp.content

        # --- Forward the response back to the API Gateway ---
        # Strip hop-by-hop headers from the backend response before forwarding
        resp_headers = {
            k: v for k, v in backend_resp.headers.items()
            if k.lower() not in ("transfer-encoding", "connection", "content-encoding")
        }

        logger.info(
            "Proxy complete: %s %s -> HTTP %d",
            ctx.Method(), target_url, backend_resp.status_code,
        )

        return response.Response(
            ctx,
            response_data=resp_body,
            headers=resp_headers,
            status_code=backend_resp.status_code,
        )

    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        # Errors that indicate a misconfiguration or bad upstream response
        logger.error("Proxy error: %s", traceback.format_exc())
        return _error_response(ctx, 502, str(exc))

    except Exception as exc:
        logger.error("Unexpected handler error: %s", traceback.format_exc())
        return _error_response(ctx, 500, str(exc))


def _error_response(ctx, status_code: int, message: str) -> response.Response:
    """
    Build a structured JSON error response.

    Args:
        ctx: FDK context object.
        status_code (int): HTTP status code to return.
        message (str): Human-readable error description.

    Returns:
        response.Response: FDK JSON error response.
    """
    return response.Response(
        ctx,
        response_data=json.dumps({"status": "error", "message": message}),
        headers={"Content-Type": "application/json"},
        status_code=status_code,
    )
