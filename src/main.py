import time
import logging
import json
import os
from pathlib import Path
from typing import Optional, Dict, Union, Tuple
from functools import lru_cache
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
try:
    from . import core
    from . import config
    from . import firewalld
    from .models import KnockRequest, KnockResponse, HealthResponse, ErrorResponse
except ImportError:  # pragma: no cover - fallback for direct module execution
    import core
    import config
    import firewalld
    from models import KnockRequest, KnockResponse, HealthResponse, ErrorResponse

@lru_cache()
def get_settings() -> Dict:
    """
    Loads settings from the YAML file and caches the result.
    The path is relative to the project root where the app is run from.
    """
    settings = config.load_config()
    config.setup_logging(settings)
    core.ensure_runtime_state(settings)
    return settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    On startup, it performs cleanup of expired IPs and initializes firewalld.
    """
    logging.info("Knocker service starting up...")
    
    settings = get_settings()
    runtime_state = core.start_runtime_state(settings)
    runtime_state.whitelist.compact_expired()
    
    # Generate and persist OpenAPI schema
    await generate_and_persist_openapi(app, settings)
    
    # Initialize firewalld integration
    firewalld_integration = firewalld.initialize_firewalld(settings)
    if firewalld_integration and firewalld_integration.is_enabled():
        logging.info("Firewalld integration is enabled")
        
        # Setup firewalld zone
        if firewalld_integration.setup_knocker_zone():
            logging.info("Firewalld zone setup completed successfully")
            
            # Restore missing rules from whitelist
            whitelist = runtime_state.whitelist.active_snapshot()
            if firewalld_integration.restore_missing_rules(whitelist):
                logging.info("Firewalld rule restoration completed successfully")
            else:
                logging.warning("Some firewalld rules could not be restored")
        else:
            logging.error("Failed to setup firewalld zone - firewalld integration may not work properly")
    else:
        logging.info("Firewalld integration is disabled")
    
    yield
    core.stop_runtime_state(settings)
    logging.info("Knocker service shutting down.")


def _remove_documentation_routes(app: FastAPI) -> None:
    """Remove existing documentation-related routes from the app router."""
    doc_paths = {
        getattr(app, "docs_url", None),
        getattr(app, "redoc_url", None),
        getattr(app, "openapi_url", None),
        getattr(app, "swagger_ui_oauth2_redirect_url", None),
    }
    doc_paths.discard(None)
    if not doc_paths:
        return

    router = app.router
    router.routes = [
        route for route in router.routes
        if getattr(route, "path", None) not in doc_paths
    ]

    routes_by_name = getattr(router, "routes_by_name", None)
    if isinstance(routes_by_name, dict):
        for name, route in list(routes_by_name.items()):
            if getattr(route, "path", None) in doc_paths:
                routes_by_name.pop(name, None)


def _configure_documentation_routes(app: FastAPI, enabled: bool) -> None:
    """Apply FastAPI documentation URL configuration."""
    if enabled:
        app.docs_url = "/docs"
        app.redoc_url = "/redoc"
        app.openapi_url = "/openapi.json"
        app.swagger_ui_oauth2_redirect_url = f"{app.docs_url}/oauth2-redirect"

        _remove_documentation_routes(app)

        async def openapi_json(_: Request):
            return JSONResponse(app.openapi())

        async def swagger_ui_html(_: Request):
            return get_swagger_ui_html(
                openapi_url=app.openapi_url,
                title=f"{app.title} - Swagger UI",
            )

        async def swagger_ui_redirect(_: Request):
            return get_swagger_ui_oauth2_redirect_html()

        async def redoc_html(_: Request):
            return get_redoc_html(
                openapi_url=app.openapi_url,
                title=f"{app.title} - ReDoc",
            )

        app.add_route(app.openapi_url, openapi_json, include_in_schema=False)
        app.add_route(app.docs_url, swagger_ui_html, include_in_schema=False)
        app.add_route(
            app.swagger_ui_oauth2_redirect_url,
            swagger_ui_redirect,
            include_in_schema=False,
        )
        app.add_route(app.redoc_url, redoc_html, include_in_schema=False)
    else:
        _remove_documentation_routes(app)
        app.docs_url = None
        app.redoc_url = None
        app.openapi_url = None
        app.swagger_ui_oauth2_redirect_url = None


async def generate_and_persist_openapi(app: FastAPI, settings: Dict):
    """Generate OpenAPI schema and persist it to disk."""
    docs_config = settings.get("documentation") or {}
    docs_enabled = bool(docs_config.get("enabled", False))
    output_path_str = docs_config.get("openapi_output_path", "openapi.json")
    output_path = Path(output_path_str)

    _configure_documentation_routes(app, docs_enabled)

    if not docs_enabled:
        logging.info("OpenAPI documentation generation is disabled")
        try:
            if output_path.exists():
                output_path.unlink()
                logging.info(f"OpenAPI schema removed because documentation is disabled: {output_path}")
        except Exception as exc:
            logging.warning(f"Failed to remove OpenAPI schema file at {output_path}: {exc}")
        return

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logging.error(f"Failed to prepare directory for OpenAPI schema at {output_path}: {exc}")
        return

    app.openapi_schema = None
    try:
        openapi_schema = app.openapi()
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(openapi_schema, f, indent=2)
        logging.info(f"OpenAPI schema generated and saved to {output_path}")
    except Exception as exc:
        logging.error(f"Failed to generate or persist OpenAPI schema: {exc}")
        try:
            if output_path.exists():
                output_path.unlink()
        except Exception:
            pass


# Configure FastAPI app with proper metadata
# Documentation URLs will be configured dynamically during lifespan based on settings
app_config = {
    "lifespan": lifespan,
    "title": "Knocker API",
    "description": """
A dynamic IP whitelisting service that works with reverse proxy authorization.

## Features

* **API Key Authentication**: Secure your knock endpoint with configurable API keys
* **Configurable TTL**: Each API key can have its own Time-To-Live (TTL)
* **Remote Whitelisting**: Admin keys can whitelist any IP or CIDR range
* **Path-Based Exclusion**: Exclude specific URL paths from authentication
* **IPv6 Support**: Full support for IPv6 and IPv4 addresses
* **Firewall Integration**: Optional firewalld integration for advanced security

## Usage

1. Use the `/knock` endpoint to add IPs to the whitelist
2. Reverse proxies can use `/verify` to check if an IP is authorized
3. Monitor service health with the `/health` endpoint
""",
    "version": "1.0.0",
    "openapi_tags": [
        {
            "name": "Authentication", 
            "description": "Endpoints for IP whitelisting and verification"
        },
        {
            "name": "System", 
            "description": "Health monitoring and system status"
        }
    ]
}
app = FastAPI(**app_config)


# Custom exception handler to maintain backward compatibility
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Convert Pydantic validation errors to 400 Bad Request for backward compatibility."""
    settings_provider = app.dependency_overrides.get(get_settings, get_settings)
    settings = settings_provider()
    allowed_origin = settings.get("cors", {}).get("allowed_origin", "*")
    
    # Extract a user-friendly error message
    error_msg = "Invalid request data."
    if exc.errors():
        first_error = exc.errors()[0]
        if first_error.get("type") == "value_error":
            error_msg = str(first_error.get("msg", "Invalid request data."))
        elif "ttl" in str(first_error.get("loc", [])):
            error_msg = "Invalid TTL specified. Must be a positive integer."
        elif "ip_address" in str(first_error.get("loc", [])):
            error_msg = "Invalid IP address or CIDR notation in request body."
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": error_msg},
        headers={"Access-Control-Allow-Origin": allowed_origin}
    )

# --- Dependency for getting the real client IP ---
def _resolve_request_context(request: Request, settings: dict) -> Tuple[Optional[str], bool, Optional[str], str]:
    """Resolve client IP and forwarded request metadata from trusted proxies only."""
    direct_ip = request.client.host if request.client else None

    # Starlette's TestClient uses a synthetic peer name. Keep the override scoped
    # to that sentinel value so production traffic cannot influence the direct IP.
    if direct_ip == "testclient":
        direct_ip = request.headers.get("x-knocker-test-direct-ip", "127.0.0.1")

    runtime_state = core.ensure_runtime_state(settings)
    client_ip, forwarded_headers_trusted = core.resolve_client_ip(
        direct_ip,
        request.headers.get("x-forwarded-for"),
        runtime_state.trusted_proxies,
    )
    request_host = core.resolve_request_host(
        request.headers.get("host"),
        request.headers.get("x-forwarded-host"),
        forwarded_headers_trusted,
    )
    request_path = core.resolve_request_path(
        request.url.path,
        request.headers.get("x-forwarded-uri"),
        forwarded_headers_trusted,
    )
    return client_ip, forwarded_headers_trusted, request_host, request_path


def get_client_ip(request: Request, settings: Optional[dict] = None) -> Optional[str]:
    """
    Returns the client's real IP address with trusted proxy validation.
    Only trusts X-Forwarded-For header if the request comes from a trusted proxy.
    """
    if settings:
        client_ip, _, _, _ = _resolve_request_context(request, settings)
        return client_ip

    direct_ip = request.client.host if request.client else None
    if direct_ip == "testclient":
        direct_ip = request.headers.get("x-knocker-test-direct-ip", "127.0.0.1")
    return direct_ip

def get_client_ip_dependency(request: Request, settings: dict = Depends(get_settings)) -> Optional[str]:
    """Dependency wrapper for get_client_ip that includes settings."""
    return get_client_ip(request, settings)


def get_request_context_dependency(
    request: Request,
    settings: dict = Depends(get_settings),
) -> Tuple[Optional[str], bool, Optional[str], str]:
    """Dependency wrapper for trusted proxy metadata resolution."""
    return _resolve_request_context(request, settings)


def _build_verified_forwarded_headers(
    client_ip: Optional[str],
    forwarded_headers_trusted: bool,
    request_host: Optional[str],
    request_path: str,
) -> Dict[str, str]:
    """Headers returned to Caddy for copy_headers on successful verify responses."""
    headers: Dict[str, str] = {}
    if client_ip:
        headers["X-Forwarded-For"] = client_ip
    if forwarded_headers_trusted:
        if request_host:
            headers["X-Forwarded-Host"] = request_host
        headers["X-Forwarded-Uri"] = request_path
    return headers

# --- API Endpoints ---

@app.options(
    "/knock", 
    tags=["Authentication"],
    summary="CORS Preflight",
    description="Handles OPTIONS requests for CORS preflight checks.",
    status_code=204
)
async def knock_options(settings: dict = Depends(get_settings)):
    """
    Handles OPTIONS requests for CORS preflight.
    """
    allowed_origin = settings.get("cors", {}).get("allowed_origin", "*")
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "X-Api-Key, X-Key-Id, Content-Type",
        }
    )

@app.post(
    "/knock", 
    response_model=KnockResponse,
    responses={
        200: {"model": KnockResponse, "description": "Successfully whitelisted the IP"},
        400: {"model": ErrorResponse, "description": "Bad request - invalid parameters"},
        401: {"model": ErrorResponse, "description": "Unauthorized - invalid or missing API key"},
        403: {"model": ErrorResponse, "description": "Forbidden - insufficient permissions"},
        500: {"model": ErrorResponse, "description": "Internal server error - failed to persist whitelist or create firewall rules"}
    },
    tags=["Authentication"],
    summary="Whitelist IP Address",
    description="""
    Add an IP address or CIDR range to the whitelist.
    
    * Requires a valid API key in the `X-Api-Key` header
    * By default whitelists the client's IP address
    * Can whitelist a different IP/CIDR if the API key has remote whitelist permission
    * TTL can be specified but will be capped by the API key's maximum TTL
    """,
    status_code=status.HTTP_200_OK
)
async def knock(
    request: Request,
    response: Response,
    body: Optional[Union[KnockRequest, Dict]] = None,
    client_ip: str = Depends(get_client_ip_dependency),
    settings: dict = Depends(get_settings)
):
    api_key = request.headers.get("X-Api-Key")
    api_key_id = request.headers.get("X-Key-Id")
    allowed_origin = settings.get("cors", {}).get("allowed_origin", "*")
    direct_ip = request.client.host if request.client else None
    if direct_ip == "testclient":
        direct_ip = request.headers.get("x-knocker-test-direct-ip", "127.0.0.1")
    rate_limit_actor = client_ip or direct_ip or "unknown"

    if not client_ip:
        logging.warning("Could not determine client IP.")
        core.record_knock_attempt(settings, rate_limit_actor, "failure")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Could not determine client IP."},
            headers={"Access-Control-Allow-Origin": allowed_origin}
        )

    api_key_record = core.get_api_key_record(api_key, settings, api_key_id)
    if not api_key_record:
        if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Too many knock attempts."},
                headers={"Access-Control-Allow-Origin": allowed_origin},
            )
        logging.warning(f"Invalid or missing API key provided by {client_ip}.")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Invalid or missing API key."},
            headers={"Access-Control-Allow-Origin": allowed_origin}
        )

    ip_to_whitelist = client_ip
    if body:
        # Handle both KnockRequest objects and raw dicts for backward compatibility
        ip_address = getattr(body, 'ip_address', None) if hasattr(body, 'ip_address') else body.get('ip_address')
        if ip_address:
            # Security: Validate input size to prevent DoS
            if not isinstance(ip_address, str):
                logging.warning(f"Invalid IP address type from {client_ip}.")
                if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"error": "Too many knock attempts."},
                        headers={"Access-Control-Allow-Origin": allowed_origin},
                    )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "IP address must be a string."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            if len(ip_address) > 100:  # Max length for IPv6 with CIDR
                logging.warning(f"IP address too long ({len(ip_address)} chars) from {client_ip}.")
                if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"error": "Too many knock attempts."},
                        headers={"Access-Control-Allow-Origin": allowed_origin},
                    )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "IP address or CIDR notation too long."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            if not api_key_record.allow_remote_whitelist:
                logging.warning(f"API key used by {client_ip} lacks remote whitelist permission.")
                if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"error": "Too many knock attempts."},
                        headers={"Access-Control-Allow-Origin": allowed_origin},
                    )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "API key lacks remote whitelist permission."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            if not core.is_valid_ip_or_cidr(ip_address):
                logging.warning(f"Invalid IP address or CIDR notation '{ip_address}' in request body from {client_ip}.")
                if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"error": "Too many knock attempts."},
                        headers={"Access-Control-Allow-Origin": allowed_origin},
                    )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid IP address or CIDR notation in request body."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            # Security check: prevent overly broad CIDR ranges
            if not core.is_safe_cidr_range(ip_address):
                logging.warning(f"Unsafe CIDR range '{ip_address}' rejected from {client_ip}.")
                if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"error": "Too many knock attempts."},
                        headers={"Access-Control-Allow-Origin": allowed_origin},
                    )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "CIDR range too broad. Maximum 65536 addresses allowed."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            ip_to_whitelist = ip_address

    max_ttl = api_key_record.max_ttl
    requested_ttl = getattr(body, 'ttl', None) if hasattr(body, 'ttl') else (body.get('ttl') if body else None)
    
    effective_ttl = max_ttl

    if requested_ttl is not None:
        # Comprehensive TTL validation
        if not isinstance(requested_ttl, int):
            logging.warning(f"Invalid TTL type '{type(requested_ttl).__name__}' specified by {client_ip}.")
            if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"error": "Too many knock attempts."},
                    headers={"Access-Control-Allow-Origin": allowed_origin},
                )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid TTL specified. Must be a positive integer."},
                headers={"Access-Control-Allow-Origin": allowed_origin}
            )
        
        # Check for edge cases: 0, negative, and excessively large values
        if requested_ttl <= 0:
            logging.warning(f"Invalid TTL '{requested_ttl}' (must be positive) specified by {client_ip}.")
            if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"error": "Too many knock attempts."},
                    headers={"Access-Control-Allow-Origin": allowed_origin},
                )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid TTL specified. Must be a positive integer."},
                headers={"Access-Control-Allow-Origin": allowed_origin}
            )
        
        # Prevent extremely large TTL values (max 10 years = 315360000 seconds)
        MAX_TTL = 315360000
        if requested_ttl > MAX_TTL:
            logging.warning(f"TTL {requested_ttl} exceeds maximum allowed ({MAX_TTL}) from {client_ip}.")
            if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"error": "Too many knock attempts."},
                    headers={"Access-Control-Allow-Origin": allowed_origin},
                )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": f"TTL too large. Maximum allowed is {MAX_TTL} seconds (10 years)."},
                headers={"Access-Control-Allow-Origin": allowed_origin}
            )
        
        effective_ttl = min(requested_ttl, max_ttl)

    expiry_time = int(time.time()) + effective_ttl

    success_reservation = core.reserve_knock_attempt(settings, rate_limit_actor, "success")
    if success_reservation is None:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": "Too many knock attempts."},
            headers={"Access-Control-Allow-Origin": allowed_origin},
        )
    
    # Add to whitelist with firewalld integration
    # This will add firewalld rules BEFORE updating whitelist.json if firewalld is enabled
    error_content = ErrorResponse(
        error="Internal server error: whitelist persistence or firewall configuration failed."
    ).model_dump()
    try:
        whitelisted = core.add_ip_to_whitelist_with_firewalld(ip_to_whitelist, expiry_time, settings)
    except Exception:
        core.release_knock_attempt(settings, rate_limit_actor, "success", success_reservation)
        logging.exception("Failed to whitelist %s. Request from %s rejected.", ip_to_whitelist, client_ip)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_content,
            headers={"Access-Control-Allow-Origin": allowed_origin},
        )

    if not whitelisted:
        core.release_knock_attempt(settings, rate_limit_actor, "success", success_reservation)
        if not core.record_knock_attempt(settings, rate_limit_actor, "failure"):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Too many knock attempts."},
                headers={"Access-Control-Allow-Origin": allowed_origin},
            )
        logging.error(f"Failed to whitelist {ip_to_whitelist}. Request from {client_ip} rejected.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_content,
            headers={"Access-Control-Allow-Origin": allowed_origin}
        )
    
    # Log with limited information; avoid logging API key names at INFO level.
    # API key name is available at DEBUG level for troubleshooting only.
    api_key_name = api_key_record.name
    logger = logging.getLogger("uvicorn.error")
    # Reduce logging to DEBUG only to avoid information disclosure in INFO-level logs.
    logger.debug("Successfully whitelisted %s for %d seconds. Requested by %s.", ip_to_whitelist, effective_ttl, client_ip)
    if api_key_name:
        logger.debug("API key used: %s", api_key_name)

    # Ensure CORS and response_model validation
    response.headers["Access-Control-Allow-Origin"] = allowed_origin
    return KnockResponse(
        whitelisted_entry=ip_to_whitelist,
        expires_at=expiry_time,
        expires_in_seconds=effective_ttl,
    )

@app.get(
    "/health", 
    response_model=HealthResponse,
    tags=["System"],
    summary="Health Check",
    description="Verify that the Knocker service is running and operational.",
    status_code=status.HTTP_200_OK
)
async def health_check(settings: dict = Depends(get_settings)):
    """
    Health check endpoint with dependency verification.
    Validates that critical configuration and dependencies are available.
    """
    try:
        runtime_state = core.ensure_runtime_state(settings)
        if not runtime_state.api_keys.records:
            logging.error("Health check failed: No API keys configured")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "error": "No API keys configured"}
            )

        whitelist_path = runtime_state.whitelist.storage_path
        storage_probe_path = whitelist_path.parent / ".knocker-healthcheck"
        if whitelist_path.exists() and not os.access(whitelist_path, os.R_OK | os.W_OK):
            logging.error("Health check failed: Whitelist storage is not readable and writable")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "error": "Whitelist storage not accessible"}
            )

        if not os.access(whitelist_path.parent, os.R_OK | os.W_OK | os.X_OK):
            logging.error("Health check failed: Whitelist storage directory is not accessible")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "error": "Whitelist storage not accessible"}
            )

        try:
            storage_probe_path.write_text("ok", encoding="utf-8")
            storage_probe_path.unlink(missing_ok=True)
        except OSError as exc:
            logging.error(f"Health check failed: Whitelist storage probe failed: {exc}")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "error": "Whitelist storage not accessible"}
            )

        return HealthResponse(status="ok")
    except Exception as e:
        logging.error(f"Health check failed with unexpected error: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Internal error"}
        )

@app.get(
    "/verify",
    responses={
        200: {
            "description": "IP is authorized - access granted",
            "headers": {
                "X-Forwarded-For": {"schema": {"type": "string"}, "description": "Verified client IP"},
                "X-Forwarded-Host": {"schema": {"type": "string"}, "description": "Verified forwarded host"},
                "X-Forwarded-Uri": {"schema": {"type": "string"}, "description": "Verified forwarded URI"},
            },
        },
        401: {"description": "IP is not authorized - access denied"}
    },
    tags=["Authentication"],
    summary="Verify IP Authorization",
    description="""
    Verify if a client IP is currently whitelisted and authorized.
    
    This endpoint is typically used by reverse proxies (like Caddy's forward_auth)
    to check if a request should be allowed through.
    
    * Returns 200 if the IP is whitelisted or in always-allowed list
    * Returns 200 if the request path is in the excluded paths list  
    * Returns 401 if the IP is not authorized
    * Uses X-Forwarded-For header when coming from trusted proxies
    * Uses X-Forwarded-Uri header to check excluded paths
    * Returns verified X-Forwarded-* headers on 200 responses for Caddy copy_headers
    """,
    status_code=status.HTTP_200_OK
)
async def verify(
    request: Request,
    request_context: Tuple[Optional[str], bool, Optional[str], str] = Depends(get_request_context_dependency),
    settings: dict = Depends(get_settings)
):
    client_ip, forwarded_headers_trusted, request_host, request_path = request_context
    runtime_state = core.ensure_runtime_state(settings)
    exclusion_host = request_host if forwarded_headers_trusted else None
    verified_headers = _build_verified_forwarded_headers(
        client_ip,
        forwarded_headers_trusted,
        request_host,
        request_path,
    )

    # 1. Check if the path is excluded from authentication.
    if runtime_state.path_exclusions.matches(exclusion_host, request_path):
        return Response(status_code=status.HTTP_200_OK, headers=verified_headers)

    # 2. Proceed with standard IP check.
    if not client_ip:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    # 3. Check if the resolved client IP is authorized.
    if not runtime_state.is_authorized_ip(client_ip):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    return Response(status_code=status.HTTP_200_OK, headers=verified_headers)
