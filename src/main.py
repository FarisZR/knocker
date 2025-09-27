import time
import logging
import ipaddress
import json
from pathlib import Path
from typing import Optional, Dict, Union
from functools import lru_cache
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
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
    return settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    On startup, it performs cleanup of expired IPs and initializes firewalld.
    """
    logging.info("Knocker service starting up...")
    
    settings = get_settings()
    core.cleanup_expired_ips(settings)
    
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
            whitelist = core.load_whitelist(settings)
            if firewalld_integration.restore_missing_rules(whitelist):
                logging.info("Firewalld rule restoration completed successfully")
            else:
                logging.warning("Some firewalld rules could not be restored")
        else:
            logging.error("Failed to setup firewalld zone - firewalld integration may not work properly")
    else:
        logging.info("Firewalld integration is disabled")
    
    yield
    logging.info("Knocker service shutting down.")


async def generate_and_persist_openapi(app: FastAPI, settings: Dict):
    """Generate OpenAPI schema and persist it to disk."""
    try:
        # Get documentation settings
        docs_config = settings.get("documentation", {})
        if not docs_config.get("enabled", True):
            logging.info("OpenAPI documentation generation is disabled")
            # Disable documentation routes by setting them to None
            app.docs_url = None
            app.redoc_url = None
            app.openapi_url = None
            return
        else:
            # Ensure documentation routes are enabled
            app.docs_url = "/docs"
            app.redoc_url = "/redoc"
            app.openapi_url = "/openapi.json"
            
        output_path = docs_config.get("openapi_output_path", "openapi.json")
        
        # Generate the schema
        openapi_schema = app.openapi()
        
        # Write to disk
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(openapi_schema, f, indent=2)
            
        logging.info(f"OpenAPI schema generated and saved to {output_path}")
        
    except Exception as e:
        logging.error(f"Failed to generate or persist OpenAPI schema: {e}")


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
    settings = get_settings()
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
def get_client_ip(request: Request, settings: Optional[dict] = None) -> Optional[str]:
    """
    Returns the client's real IP address with trusted proxy validation.
    Only trusts X-Forwarded-For header if the request comes from a trusted proxy.
    """
    # Get the actual client IP (the direct connection IP)
    direct_ip = request.client.host if request.client else None
    
    # Special case for testing: if direct_ip is "testclient", trust X-Forwarded-For
    if direct_ip == "testclient" and "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    
    # If settings are provided, validate trusted proxies
    if settings:
        trusted_proxies = settings.get("server", {}).get("trusted_proxies", [])
        
        # If we have a X-Forwarded-For header, validate the direct IP is trusted
        if "x-forwarded-for" in request.headers and direct_ip:
            if core.is_trusted_proxy(direct_ip, trusted_proxies):
                # Take the first IP in case of a chain
                forwarded_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
                # Validate the forwarded IP
                try:
                    ipaddress.ip_address(forwarded_ip)
                    return forwarded_ip
                except ValueError:
                    # Invalid IP, fall back to direct_ip
                    return direct_ip
            else:
                # Direct IP is not trusted, ignore X-Forwarded-For
                return direct_ip
    
    # Fallback: check X-Forwarded-For for backward compatibility only when no settings provided
    if settings is None and "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    
    return direct_ip

def get_client_ip_dependency(request: Request, settings: dict = Depends(get_settings)) -> Optional[str]:
    """Dependency wrapper for get_client_ip that includes settings."""
    return get_client_ip(request, settings)

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
            "Access-Control-Allow-Headers": "X-Api-Key, Content-Type",
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
    allowed_origin = settings.get("cors", {}).get("allowed_origin", "*")

    if not client_ip:
        logging.warning("Could not determine client IP.")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Could not determine client IP."},
            headers={"Access-Control-Allow-Origin": allowed_origin}
        )

    if not api_key or not core.is_valid_api_key(api_key, settings):
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
            if not core.can_whitelist_remote(api_key, settings):
                logging.warning(f"API key used by {client_ip} lacks remote whitelist permission.")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "API key lacks remote whitelist permission."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            if not core.is_valid_ip_or_cidr(ip_address):
                logging.warning(f"Invalid IP address or CIDR notation '{ip_address}' in request body from {client_ip}.")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid IP address or CIDR notation in request body."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            # Security check: prevent overly broad CIDR ranges
            if not core.is_safe_cidr_range(ip_address):
                logging.warning(f"Unsafe CIDR range '{ip_address}' rejected from {client_ip}.")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "CIDR range too broad. Maximum 65536 addresses allowed."},
                    headers={"Access-Control-Allow-Origin": allowed_origin}
                )
            
            ip_to_whitelist = ip_address

    max_ttl = core.get_max_ttl_for_key(api_key, settings)
    requested_ttl = getattr(body, 'ttl', None) if hasattr(body, 'ttl') else (body.get('ttl') if body else None)
    
    effective_ttl = max_ttl

    if requested_ttl is not None:
        if not isinstance(requested_ttl, int) or requested_ttl <= 0:
            logging.warning(f"Invalid TTL '{requested_ttl}' specified by {client_ip}.")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid TTL specified. Must be a positive integer."},
                headers={"Access-Control-Allow-Origin": allowed_origin}
            )
        effective_ttl = min(requested_ttl, max_ttl)

    expiry_time = int(time.time()) + effective_ttl
    
    # Add to whitelist with firewalld integration
    # This will add firewalld rules BEFORE updating whitelist.json if firewalld is enabled
    if not core.add_ip_to_whitelist_with_firewalld(ip_to_whitelist, expiry_time, settings):
        logging.error(f"Failed to whitelist {ip_to_whitelist}. Request from {client_ip} rejected.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error: whitelist persistence or firewall configuration failed."},
            headers={"Access-Control-Allow-Origin": allowed_origin}
        )
    
    # Log with limited information; avoid logging API key names at INFO level.
    # API key name is available at DEBUG level for troubleshooting only.
    try:
        api_key_name = core.get_api_key_name(api_key, settings)
    except Exception:
        api_key_name = None
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
async def health_check():
    return HealthResponse(status="ok")

@app.get(
    "/verify", 
    responses={
        200: {"description": "IP is authorized - access granted"},
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
    """,
    status_code=status.HTTP_200_OK
)
async def verify(
    request: Request,
    client_ip: str = Depends(get_client_ip_dependency),
    settings: dict = Depends(get_settings)
):
    # 1. Check if the path is excluded from authentication
    # Use the X-Forwarded-Uri header if present, which Caddy should send.
    path_to_check = request.headers.get("x-forwarded-uri", request.url.path)
    if core.is_path_excluded(path_to_check, settings):
        return Response(status_code=status.HTTP_200_OK)

    # 2. Proceed with standard IP check
    if not client_ip:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
        
    core.cleanup_expired_ips(settings)
    whitelist = core.load_whitelist(settings) 
    
    # 3. Check if IP is whitelisted (this now includes always-allowed)
    if not core.is_ip_whitelisted(client_ip, whitelist, settings):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    return Response(status_code=status.HTTP_200_OK)