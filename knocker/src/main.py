import time
from typing import Optional, Dict
from functools import lru_cache
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.responses import JSONResponse
from . import core, config

@lru_cache()
def get_settings() -> Dict:
    """
    Loads settings from the YAML file and caches the result.
    The path is relative to the project root where the app is run from.
    """
    return config.load_config("knocker/knocker.yaml")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    On startup, it performs a cleanup of any expired IPs.
    """
    print("Knocker service starting up...")
    core.cleanup_expired_ips(get_settings())
    yield
    print("Knocker service shutting down.")

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

@app.post("/knock")
async def knock(
    request: Request,
    body: Optional[Dict] = None,
    client_ip: str = Depends(get_client_ip),
    settings: dict = Depends(get_settings)
):
    api_key = request.headers.get("X-Api-Key")

    if not client_ip:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Could not determine client IP."}
        )

    if not api_key or not core.is_valid_api_key(api_key, settings):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Invalid or missing API key."}
        )

    ip_to_whitelist = client_ip
    if body and "ip_address" in body:
        if not core.can_whitelist_remote(api_key, settings):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "API key lacks remote whitelist permission."}
            )
        
        target_ip = body["ip_address"]
        if not core.is_valid_ip_or_cidr(target_ip):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid IP address or CIDR notation in request body."}
            )
        ip_to_whitelist = target_ip

    ttl = core.get_ttl_for_key(api_key, settings)
    expiry_time = int(time.time()) + ttl
    
    core.add_ip_to_whitelist(ip_to_whitelist, expiry_time, settings)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "whitelisted_entry": ip_to_whitelist,
            "expires_at": expiry_time,
            "expires_in_seconds": ttl,
        },
    )

@app.get("/check")
async def check(
    client_ip: str = Depends(get_client_ip),
    settings: dict = Depends(get_settings)
):
    if not client_ip:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
        
    core.cleanup_expired_ips(settings)
    whitelist = core.load_whitelist(settings) 
    
    if not core.is_ip_whitelisted(client_ip, whitelist):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    return Response(status_code=status.HTTP_200_OK)