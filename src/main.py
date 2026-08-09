import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional, Tuple, cast, override
from functools import lru_cache
from contextlib import asynccontextmanager
from fastapi import APIRouter, Depends, FastAPI, Request, Response, status
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

try:
    from . import core
    from . import config
    from . import firewalld
    from .config import Settings, SettingsLike
    from .models import KnockRequest, KnockResponse, HealthResponse, ErrorResponse
    from .version import __version__
except ImportError:  # pragma: no cover - fallback for direct module execution
    import core
    import config
    import firewalld
    from config import Settings, SettingsLike
    from models import KnockRequest, KnockResponse, HealthResponse, ErrorResponse
    from version import __version__


MAX_TTL = config.MAX_TTL


@lru_cache()
def get_settings() -> Settings:
    """
    Loads settings from the YAML file and caches the result.
    The path is relative to the project root where the app is run from.
    """
    settings = config.load_config()
    config.setup_logging(settings)
    return settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    On startup, it performs cleanup of expired IPs and initializes firewalld.
    """
    logging.info("Knocker service starting up...")

    settings_provider = app.dependency_overrides.get(get_settings, get_settings)
    settings = config.validate_settings(settings_provider())
    runtime_state = core.start_runtime_state(settings)
    runtime_state.whitelist.compact_expired()
    firewalld.initialize_mutation_executor(settings)

    try:
        await generate_and_persist_openapi(app, settings)

        # Initialize firewalld integration
        firewalld_integration = firewalld.initialize_firewalld(settings)
        if firewalld_integration and firewalld_integration.is_enabled():
            logging.info("Firewalld integration is enabled")

            setup_ok = await firewalld.run_mutation(
                firewalld_integration.setup_knocker_zone, settings
            )
            if not setup_ok:
                raise RuntimeError("Firewalld protection setup failed; refusing readiness")

            whitelist = runtime_state.whitelist.active_snapshot()
            restored_ok = await firewalld.run_mutation(
                lambda: firewalld_integration.restore_missing_rules(whitelist), settings
            )
            if not restored_ok:
                raise RuntimeError("Active whitelist rules could not be restored")

            ready = await asyncio.to_thread(firewalld_integration.verify_protection)
            if not ready:
                raise RuntimeError("Firewalld protection verification failed; refusing readiness")
            logging.info("Firewalld protection is ready")
        else:
            logging.info("Firewalld integration is disabled")

        yield
    finally:
        core.stop_runtime_state(settings)
        firewalld.shutdown_mutation_executor()
        logging.info("Knocker service shutting down.")


async def generate_and_persist_openapi(app: FastAPI, settings: SettingsLike) -> None:
    """Explicitly export the already-configured app schema when documentation is enabled."""
    resolved = config.validate_settings(settings)
    output_path = Path(resolved.documentation.openapi_output_path)
    if not resolved.documentation.enabled:
        logging.info("OpenAPI documentation generation is disabled")
        try:
            output_path.unlink(missing_ok=True)
        except OSError as exc:
            logging.warning("Failed to remove OpenAPI schema file at %s: %s", output_path, exc)
        return

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(app.openapi(), handle, indent=2)
        logging.info("OpenAPI schema generated and saved to %s", output_path)
    except OSError as exc:
        logging.error("Failed to generate or persist OpenAPI schema: %s", exc)


APP_DESCRIPTION = """
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
"""
OPENAPI_TAGS = [
    {"name": "Authentication", "description": "Endpoints for IP whitelisting and verification"},
    {"name": "System", "description": "Health monitoring and system status"},
]
router = APIRouter()


# Custom exception handler to maintain backward compatibility
async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Convert Pydantic validation errors to 400 Bad Request for backward compatibility."""
    validation_error = cast(RequestValidationError, exc)
    settings_provider = request.app.dependency_overrides.get(get_settings, get_settings)
    settings = config.validate_settings(settings_provider())
    allowed_origin = settings.cors.allowed_origin

    # Extract a user-friendly error message
    error_msg = "Invalid request data."
    if validation_error.errors():
        first_error = validation_error.errors()[0]
        if first_error.get("type") == "value_error":
            error_msg = str(first_error.get("msg", "Invalid request data."))
        elif "ttl" in str(first_error.get("loc", [])):
            error_msg = "Invalid TTL specified. Must be a positive integer."
        elif "ip_address" in str(first_error.get("loc", [])):
            error_msg = "Invalid IP address or CIDR notation in request body."

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": error_msg},
        headers={"Access-Control-Allow-Origin": allowed_origin},
    )


# --- Dependency for getting the real client IP ---
def _resolve_request_context(
    request: Request, settings: SettingsLike
) -> Tuple[Optional[str], bool, Optional[str], str]:
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


def get_client_ip(request: Request, settings: Optional[SettingsLike] = None) -> Optional[str]:
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


def get_client_ip_dependency(
    request: Request, settings: SettingsLike = Depends(get_settings)
) -> Optional[str]:
    """Dependency wrapper for get_client_ip that includes settings."""
    return get_client_ip(request, settings)


def get_request_context_dependency(
    request: Request,
    settings: SettingsLike = Depends(get_settings),
) -> Tuple[Optional[str], bool, Optional[str], str]:
    """Dependency wrapper for trusted proxy metadata resolution."""
    return _resolve_request_context(request, settings)


MAX_KNOCK_BODY_BYTES = 4096


async def _read_knock_body(
    request: Request,
) -> Tuple[Optional[KnockRequest], Optional[Tuple[int, str]]]:
    """Read and validate the optional knock body after authentication."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_KNOCK_BODY_BYTES:
                return None, (status.HTTP_413_CONTENT_TOO_LARGE, "Request body too large.")
        except ValueError:
            # A malformed Content-Length is not trusted; the bounded stream below
            # remains the authoritative limit.
            pass

    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_KNOCK_BODY_BYTES:
                return None, (status.HTTP_413_CONTENT_TOO_LARGE, "Request body too large.")
            chunks.append(chunk)
    except Exception:
        return None, (status.HTTP_400_BAD_REQUEST, "Malformed JSON request body.")

    raw_body = b"".join(chunks)
    if not raw_body:
        return None, None

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return None, (status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Request body must be JSON.")

    try:
        decoded = json.loads(raw_body)
    except json.JSONDecodeError:
        return None, (status.HTTP_400_BAD_REQUEST, "Malformed JSON request body.")

    if not isinstance(decoded, dict):
        return None, (status.HTTP_400_BAD_REQUEST, "Request body must be a JSON object.")

    try:
        return KnockRequest.model_validate(decoded), None
    except ValidationError as exc:
        if any("ttl" in str(error.get("loc", ())) for error in exc.errors()):
            return None, (
                status.HTTP_400_BAD_REQUEST,
                "Invalid TTL specified. Must be a positive integer.",
            )
        if any("ip_address" in str(error.get("loc", ())) for error in exc.errors()):
            if any(
                error.get("type") == "string_too_long"
                for error in exc.errors()
                if "ip_address" in str(error.get("loc", ()))
            ):
                return None, (status.HTTP_400_BAD_REQUEST, "IP address or CIDR notation too long.")
            return None, (
                status.HTTP_400_BAD_REQUEST,
                "Invalid IP address or CIDR notation in request body.",
            )
        return None, (status.HTTP_400_BAD_REQUEST, "Invalid request data.")


def _knock_failure(
    settings: SettingsLike,
    actor: str,
    allowed_origin: str,
    status_code: int,
    message: str,
) -> JSONResponse:
    if not core.record_knock_attempt(settings, actor, "failure"):
        status_code = status.HTTP_429_TOO_MANY_REQUESTS
        message = "Too many knock attempts."
    return JSONResponse(
        status_code=status_code,
        content={"error": message},
        headers={"Access-Control-Allow-Origin": allowed_origin},
    )


# --- API Endpoints ---


@router.options(
    "/knock",
    tags=["Authentication"],
    summary="CORS Preflight",
    description="Handles OPTIONS requests for CORS preflight checks.",
    status_code=204,
)
async def knock_options(settings: SettingsLike = Depends(get_settings)):
    """
    Handles OPTIONS requests for CORS preflight.
    """
    allowed_origin = config.validate_settings(settings).cors.allowed_origin
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "X-Api-Key, Content-Type",
        },
    )


@router.post(
    "/knock",
    response_model=KnockResponse,
    responses={
        200: {"model": KnockResponse, "description": "Successfully whitelisted the IP"},
        400: {"model": ErrorResponse, "description": "Bad request - invalid parameters"},
        401: {"model": ErrorResponse, "description": "Unauthorized - invalid or missing API key"},
        403: {"model": ErrorResponse, "description": "Forbidden - insufficient permissions"},
        413: {"model": ErrorResponse, "description": "Request body exceeds 4096 bytes"},
        415: {"model": ErrorResponse, "description": "Request body is not JSON"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        503: {"model": ErrorResponse, "description": "Firewall mutation capacity is unavailable"},
        500: {
            "model": ErrorResponse,
            "description": "Internal server error - failed to persist whitelist or create firewall rules",
        },
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
    status_code=status.HTTP_200_OK,
)
async def knock(
    request: Request,
    response: Response,
    client_ip: Optional[str] = Depends(get_client_ip_dependency),
    settings: SettingsLike = Depends(get_settings),
):
    api_key = request.headers.get("X-Api-Key")
    allowed_origin = config.validate_settings(settings).cors.allowed_origin
    direct_ip = request.client.host if request.client else None
    if direct_ip == "testclient":
        direct_ip = request.headers.get("x-knocker-test-direct-ip", "127.0.0.1")
    rate_limit_actor = client_ip or direct_ip or "unknown"

    if not client_ip:
        logging.warning("Could not determine client IP.")
        return _knock_failure(
            settings,
            rate_limit_actor,
            allowed_origin,
            status.HTTP_400_BAD_REQUEST,
            "Could not determine client IP.",
        )

    api_key_record = core.get_api_key_record(api_key, settings)
    if not api_key_record:
        logging.warning(f"Invalid or missing API key provided by {client_ip}.")
        return _knock_failure(
            settings,
            rate_limit_actor,
            allowed_origin,
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or missing API key.",
        )

    # Authentication and the failure limiter intentionally happen before any
    # request-body read. This keeps unauthenticated streams out of the parser.
    body, body_error = await _read_knock_body(request)
    if body_error:
        body_status, body_message = body_error
        return _knock_failure(settings, rate_limit_actor, allowed_origin, body_status, body_message)

    ip_to_whitelist = client_ip
    requested_ttl = body.ttl if body is not None else None
    ip_address = body.ip_address if body is not None else None
    if ip_address is not None:
        if not api_key_record.allow_remote_whitelist:
            logging.warning(f"API key used by {client_ip} lacks remote whitelist permission.")
            return _knock_failure(
                settings,
                rate_limit_actor,
                allowed_origin,
                status.HTTP_403_FORBIDDEN,
                "API key lacks remote whitelist permission.",
            )
        if not core.is_safe_cidr_range(ip_address):
            logging.warning(f"Unsafe CIDR range '{ip_address}' rejected from {client_ip}.")
            return _knock_failure(
                settings,
                rate_limit_actor,
                allowed_origin,
                status.HTTP_400_BAD_REQUEST,
                "CIDR range too broad. Maximum 65536 addresses allowed.",
            )
        ip_to_whitelist = ip_address

    if requested_ttl is not None and requested_ttl > MAX_TTL:
        logging.warning(
            "TTL %d exceeds maximum allowed (%d) from %s.", requested_ttl, MAX_TTL, client_ip
        )
        return _knock_failure(
            settings,
            rate_limit_actor,
            allowed_origin,
            status.HTTP_400_BAD_REQUEST,
            f"TTL too large. Maximum allowed is {MAX_TTL} seconds (10 years).",
        )

    effective_ttl = min(requested_ttl or MAX_TTL, api_key_record.max_ttl, MAX_TTL)

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
        whitelisted = await firewalld.run_mutation(
            lambda: core.add_ip_to_whitelist_with_firewalld(ip_to_whitelist, expiry_time, settings),
            settings,
        )
    except firewalld.MutationQueueUnavailable:
        core.release_knock_attempt(settings, rate_limit_actor, "success", success_reservation)
        return _knock_failure(
            settings,
            rate_limit_actor,
            allowed_origin,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Firewall mutation capacity is unavailable.",
        )
    except Exception:
        core.release_knock_attempt(settings, rate_limit_actor, "success", success_reservation)
        logging.exception(
            "Failed to whitelist %s. Request from %s rejected.", ip_to_whitelist, client_ip
        )
        return _knock_failure(
            settings,
            rate_limit_actor,
            allowed_origin,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_content["error"],
        )

    if not whitelisted:
        core.release_knock_attempt(settings, rate_limit_actor, "success", success_reservation)
        logging.error(f"Failed to whitelist {ip_to_whitelist}. Request from {client_ip} rejected.")
        return _knock_failure(
            settings,
            rate_limit_actor,
            allowed_origin,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_content["error"],
        )

    # Log with limited information; avoid logging API key names at INFO level.
    # API key name is available at DEBUG level for troubleshooting only.
    api_key_name = api_key_record.name
    logger = logging.getLogger("uvicorn.error")
    # Reduce logging to DEBUG only to avoid information disclosure in INFO-level logs.
    logger.debug(
        "Successfully whitelisted %s for %d seconds. Requested by %s.",
        ip_to_whitelist,
        effective_ttl,
        client_ip,
    )
    if api_key_name:
        logger.debug("API key used: %s", api_key_name)

    # Ensure CORS and response_model validation
    response.headers["Access-Control-Allow-Origin"] = allowed_origin
    return KnockResponse(
        whitelisted_entry=ip_to_whitelist,
        expires_at=expiry_time,
        expires_in_seconds=effective_ttl,
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Liveness Check",
    description="Verify that the Knocker process and initialized runtime are alive.",
    status_code=status.HTTP_200_OK,
)
async def health_check(settings: SettingsLike = Depends(get_settings)):
    """Return quickly without probing external services or firewalld."""
    try:
        runtime_state = core.ensure_runtime_state(settings)
        if not runtime_state.api_keys.records:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "error": "No API keys configured"},
            )
        return HealthResponse(status="ok")
    except Exception as e:
        logging.error(f"Health check failed with unexpected error: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Internal error"},
        )


async def _full_readiness_check(settings: SettingsLike) -> Optional[JSONResponse]:
    """Run the dependency checks reserved for the readiness endpoint."""
    runtime_state = core.ensure_runtime_state(settings)
    if not runtime_state.api_keys.records:
        logging.error("Readiness check failed: No API keys configured")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "No API keys configured"},
        )

    whitelist_path = runtime_state.whitelist.storage_path
    if whitelist_path.exists() and not os.access(whitelist_path, os.R_OK | os.W_OK):
        logging.error("Readiness check failed: Whitelist storage is not readable and writable")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Whitelist storage not accessible"},
        )

    if not os.access(whitelist_path.parent, os.R_OK | os.W_OK | os.X_OK):
        logging.error("Readiness check failed: Whitelist storage directory is not accessible")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Whitelist storage not accessible"},
        )

    try:
        whitelist_path.parent.stat()
        if whitelist_path.exists():
            whitelist_path.stat()
    except OSError as exc:
        logging.error(f"Readiness check failed: Whitelist storage stat failed: {exc}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Whitelist storage not accessible"},
        )

    firewalld_enabled = config.validate_settings(settings).firewalld.enabled
    firewalld_integration = firewalld.get_firewalld_integration()
    if firewalld_enabled and (
        firewalld_integration is None or not firewalld_integration.is_enabled()
    ):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Firewalld protection not ready"},
        )
    if firewalld_enabled and firewalld_integration:
        ready = await asyncio.to_thread(firewalld_integration.verify_protection)
        if not ready:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unhealthy", "error": "Firewalld protection not ready"},
            )

    return None


@router.get(
    "/ready",
    response_model=HealthResponse,
    tags=["System"],
    summary="Readiness Check",
    description="Verify storage and enabled firewalld protection are ready.",
    status_code=status.HTTP_200_OK,
)
async def readiness_check(settings: SettingsLike = Depends(get_settings)):
    """Run the full read-only readiness check."""
    try:
        failure = await _full_readiness_check(settings)
        if failure is not None:
            return failure
        return HealthResponse(status="ok")
    except Exception as e:
        logging.error(f"Readiness check failed with unexpected error: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": "Internal error"},
        )


@router.get(
    "/verify",
    responses={
        200: {"description": "IP is authorized - access granted"},
        401: {"description": "IP is not authorized - access denied"},
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
    """,
    status_code=status.HTTP_200_OK,
)
async def verify(
    request: Request,
    request_context: Tuple[Optional[str], bool, Optional[str], str] = Depends(
        get_request_context_dependency
    ),
    settings: SettingsLike = Depends(get_settings),
):
    client_ip, forwarded_headers_trusted, request_host, request_path = request_context
    runtime_state = core.ensure_runtime_state(settings)
    exclusion_host = request_host if forwarded_headers_trusted else None

    # 1. Check if the path is excluded from authentication.
    if runtime_state.path_exclusions.matches(exclusion_host, request_path):
        return Response(status_code=status.HTTP_200_OK)

    # 2. Proceed with standard IP check.
    if not client_ip:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    # 3. Check if the resolved client IP is authorized.
    if not runtime_state.is_authorized_ip(client_ip):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    return Response(status_code=status.HTTP_200_OK)


class KnockerFastAPI(FastAPI):
    """FastAPI app with the knock request schema exported without binding a body."""

    @override
    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is None:
            self.openapi_schema = get_openapi(
                title=self.title,
                version=self.version,
                description=self.description,
                routes=self.routes,
                tags=self.openapi_tags,
            )
            schemas = self.openapi_schema.setdefault("components", {}).setdefault("schemas", {})
            schemas.setdefault("KnockRequest", KnockRequest.model_json_schema())
            operation = self.openapi_schema.get("paths", {}).get("/knock", {}).get("post")
            if isinstance(operation, dict):
                operation["requestBody"] = {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/KnockRequest"}
                        }
                    },
                }
        return self.openapi_schema


def _build_app(docs_enabled: bool, settings: Optional[Settings] = None) -> KnockerFastAPI:
    app = KnockerFastAPI(
        lifespan=lifespan,
        title="Knocker API",
        description=APP_DESCRIPTION,
        version=__version__,
        openapi_tags=OPENAPI_TAGS,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.include_router(router)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    if settings is not None:
        app.dependency_overrides[get_settings] = lambda: settings
    return app


def create_app(settings: SettingsLike | None = None) -> KnockerFastAPI:
    """Create an app whose documentation routes are fixed by validated settings."""
    resolved = get_settings() if settings is None else config.validate_settings(settings)
    return _build_app(resolved.documentation.enabled, resolved)


# Tests and library users can import a route-complete app without loading the
# mandatory deployment configuration. Production uses create_app as a Uvicorn
# factory so its documentation setting is applied before routes are registered.
app = _build_app(docs_enabled=True)
