import ipaddress
import json
import time
import fcntl
import threading
from pathlib import Path
from typing import Dict, Any, Optional

# Thread lock for whitelist operations
_whitelist_lock = threading.Lock()

# --- IP/CIDR Validation ---

def is_valid_ip_or_cidr(address: str) -> bool:
    """Validates if a string is a valid IPv4/IPv6 address or CIDR network."""
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False

def is_safe_cidr_range(cidr: str, max_host_count: int = 65536) -> bool:
    """
    Validates that a CIDR range doesn't exceed a maximum number of host addresses.
    This prevents abuse via overly broad ranges like 0.0.0.0/0.
    For IPv6, uses different limits due to the address space size.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Special handling for IPv6 due to massive address space
        if isinstance(network, ipaddress.IPv6Network):
            # For IPv6, use prefix length as a safety check instead of address count
            # /64 is very common for home networks and should be allowed
            if network.prefixlen < 64:  # Less than /64 is too broad
                return False
            # For /64 and higher, allow based on prefix length (no need to count addresses)
            return True
        else:
            # For IPv4, check actual address count
            return network.num_addresses <= max_host_count
    except ValueError:
        return False

def is_trusted_proxy(client_ip: str, trusted_proxies: list) -> bool:
    """
    Checks if the client IP is in the trusted proxies list.
    This is used to validate X-Forwarded-For headers.
    """
    if not client_ip or not trusted_proxies:
        return False
    
    try:
        client_ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    
    for proxy in trusted_proxies:
        try:
            proxy_network = ipaddress.ip_network(proxy, strict=False)
            if client_ip_obj in proxy_network:
                return True
        except ValueError:
            continue
    
    return False

# --- Whitelist Management ---

def is_ip_whitelisted(ip: str, whitelist: Dict[str, int], settings: Dict[str, Any]) -> bool:
    """
    Checks if a given IP is contained within the dynamic whitelist or the
    always-allowed list from settings.
    """
    try:
        client_ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        # The IP to check was invalid
        return False

    # 1. Check always-allowed list first
    always_allowed_ips = settings.get("security", {}).get("always_allowed_ips", [])
    for entry in always_allowed_ips:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if client_ip_obj in network:
                return True
        except ValueError:
            continue # Ignore invalid entries

    # 2. Check dynamic whitelist
    now = int(time.time())
    for entry, expiry in whitelist.items():
        if expiry > now:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if client_ip_obj in network:
                    return True
            except ValueError:
                continue # Ignore invalid entries

    return False

def is_path_excluded(path: str, settings: Dict[str, Any]) -> bool:
    """
    Checks if the request path matches any of the excluded paths.
    Uses exact matching and normalized paths to prevent traversal attacks.
    """
    excluded_paths = settings.get("security", {}).get("excluded_paths", [])
    
    # Normalize the path to prevent traversal attacks
    normalized_path = normalize_path(path)
    
    for excluded_path in excluded_paths:
        normalized_excluded = normalize_path(excluded_path)
        if normalized_path.startswith(normalized_excluded):
            # Additional check: ensure it's a proper path prefix, not just string prefix
            if normalized_path == normalized_excluded or normalized_path.startswith(normalized_excluded + "/"):
                return True
    return False

def normalize_path(path: str) -> str:
    """
    Normalizes a URL path to prevent path traversal attacks.
    Resolves . and .. components and removes duplicate slashes.
    """
    if not path:
        return "/"
    
    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path
    
    # Split into components and resolve . and ..
    parts = []
    for part in path.split("/"):
        if part == "" or part == ".":
            continue
        elif part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    
    # Reconstruct the path
    return "/" + "/".join(parts)

def load_whitelist(settings: Dict[str, Any]) -> Dict[str, int]:
    """Loads the whitelist from the JSON file with thread safety."""
    with _whitelist_lock:
        path = Path(settings.get("whitelist", {}).get("storage_path", "whitelist.json"))
        if not path.exists():
            return {}
        
        try:
            with open(path, 'r') as f:
                # Use file locking to prevent race conditions
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return {}
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (OSError, IOError):
            return {}

def save_whitelist(whitelist: Dict[str, int], settings: Dict[str, Any]):
    """Saves the whitelist to the JSON file with thread safety and size limits."""
    with _whitelist_lock:
        path = Path(settings.get("whitelist", {}).get("storage_path", "whitelist.json"))
        
        # Security check: limit whitelist size to prevent DoS
        max_entries = settings.get("security", {}).get("max_whitelist_entries", 10000)
        if len(whitelist) > max_entries:
            # Remove oldest entries if limit exceeded
            sorted_items = sorted(whitelist.items(), key=lambda x: x[1])
            whitelist = dict(sorted_items[-max_entries:])
        
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temporary file first, then atomically rename
        temp_path = path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(whitelist, f, indent=2)
                    f.flush()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomic rename
            temp_path.rename(path)
        except (OSError, IOError) as e:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise

def add_ip_to_whitelist(ip_or_cidr: str, expiry_time: int, settings: Dict[str, Any]):
    """Adds an IP or CIDR to the whitelist and saves it."""
    whitelist = load_whitelist(settings)
    whitelist[ip_or_cidr] = expiry_time
    save_whitelist(whitelist, settings)

def cleanup_expired_ips(settings: Dict[str, Any]):
    """Removes expired entries from the whitelist file."""
    whitelist = load_whitelist(settings)
    now = int(time.time())
    
    # Create a new dict with only the non-expired entries
    fresh_whitelist = {entry: expiry for entry, expiry in whitelist.items() if expiry > now}
    
    if len(fresh_whitelist) < len(whitelist):
        save_whitelist(fresh_whitelist, settings)

# --- Permissions & Key Helpers ---

def can_whitelist_remote(api_key: str, settings: Dict[str, Any]) -> bool:
    """Checks if the given API key has permission to whitelist remote IPs."""
    for key_info in settings.get('api_keys', []):
        if key_info.get('key') == api_key:
            return key_info.get('allow_remote_whitelist', False)
    return False

def get_max_ttl_for_key(api_key: str, settings: Dict[str, Any]) -> int:
    """Finds the maximum TTL for a given API key."""
    for key_info in settings.get('api_keys', []):
        if key_info.get('key') == api_key:
            return key_info.get('max_ttl', 0)
    return 0

def is_valid_api_key(api_key: str, settings: Dict[str, Any]) -> bool:
    """Checks if an API key exists in the configuration."""
    if not api_key:
        return False
    return any(key_info.get('key') == api_key for key_info in settings.get('api_keys', []))


def get_api_key_name(api_key: str, settings: Dict[str, Any]) -> str:
    """
    Returns the configured name for an API key, falling back to the key string
    if no explicit name is provided. Returns an empty string if api_key is falsy.
    """
    if not api_key:
        return ""
    for key_info in settings.get('api_keys', []):
        if key_info.get('key') == api_key:
            return key_info.get('name') or key_info.get('key')
    return api_key