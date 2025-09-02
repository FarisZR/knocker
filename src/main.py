import time
import logging
from typing import Optional, Dict
from functools import lru_cache
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.responses import JSONResponse
import core
import config

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
    On startup, it performs a cleanup of any expired IPs.
    """
    logging.info("Knocker service starting up...")
    core.cleanup_expired_ips(get_settings())
    yield
    logging.info("Knocker service shutting down.")

app = FastAPI(lifespan=lifespan)

# --- Dependency for getting the real client IP ---
def get_client_ip(request: Request) -> Optional[str]:
    """
    Returns the client's real IP address.
    Uvicorn must be run with --forwarded-allow-ips to trust the X-Forwarded-For header.
    This function also manually checks the header to support the TestClient.
    """
    if "x-forwarded-for" in request.headers:
        # Take the first IP in case of a chain
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else None

# --- API Endpoints ---

@app.options("/knock")
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

@app.post("/knock", status_code=status.HTTP_200_OK)
async def knock(
    request: Request,
    body: Optional[Dict] = None,
    client_ip: str = Depends(get_client_ip),
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
    if body and "ip_address" in body:
        if not core.can_whitelist_remote(api_key, settings):
            logging.warning(f"API key used by {client_ip} lacks remote whitelist permission.")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "API key lacks remote whitelist permission."},
                headers={"Access-Control-Allow-Origin": allowed_origin}
            )
        
        target_ip = body["ip_address"]
        if not core.is_valid_ip_or_cidr(target_ip):
            logging.warning(f"Invalid IP address or CIDR notation '{target_ip}' in request body from {client_ip}.")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid IP address or CIDR notation in request body."},
                headers={"Access-Control-Allow-Origin": allowed_origin}
            )
        ip_to_whitelist = target_ip

    max_ttl = core.get_max_ttl_for_key(api_key, settings)
    requested_ttl = body.get("ttl") if body else None
    
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
    
    core.add_ip_to_whitelist(ip_to_whitelist, expiry_time, settings)
    
    token_name = core.get_api_key_name(api_key, settings)
    logging.getLogger("uvicorn.error").info(
        f"Successfully whitelisted {ip_to_whitelist} for {effective_ttl} seconds using token '{token_name}'. Requested by {client_ip}."
    )

    return JSONResponse(
        content={
            "whitelisted_entry": ip_to_whitelist,
            "expires_at": expiry_time,
            "expires_in_seconds": effective_ttl,
        },
        headers={"Access-Control-Allow-Origin": allowed_origin}
    )

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "ok"}

@app.get("/verify", status_code=status.HTTP_200_OK)
async def verify(
    request: Request,
    client_ip: str = Depends(get_client_ip),
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