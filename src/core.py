import ipaddress
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional

# --- IP/CIDR Validation ---

def is_valid_ip_or_cidr(address: str) -> bool:
    """Validates if a string is a valid IPv4/IPv6 address or CIDR network."""
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False


def is_trusted_proxy(client_ip: str, settings: Dict[str, Any]) -> bool:
    """
    Checks if the given client IP is in the trusted_proxies list.
    
    Args:
        client_ip: The IP address to check
        settings: Configuration settings containing trusted_proxies
        
    Returns:
        True if the IP is from a trusted proxy, False otherwise
    """
    if not client_ip:
        return False
        
    try:
        client_ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    
    trusted_proxies = settings.get("server", {}).get("trusted_proxies", [])
    
    for proxy_entry in trusted_proxies:
        if not proxy_entry:  # Skip empty/None entries
            continue
        try:
            proxy_network = ipaddress.ip_network(proxy_entry, strict=False)
            if client_ip_obj in proxy_network:
                return True
        except ValueError:
            # Skip invalid proxy entries but don't fail completely
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
    Uses secure path comparison to prevent traversal attacks.
    """
    if not path:
        return False
        
    # Normalize the path to prevent traversal attacks
    import os.path
    try:
        # Normalize path separators and resolve . and .. components
        normalized_path = os.path.normpath(path)
        
        # Ensure path starts with / and doesn't contain backwards traversal
        if not normalized_path.startswith('/'):
            normalized_path = '/' + normalized_path
            
        # Additional security: reject paths that try to escape the root
        if '..' in normalized_path:
            return False
            
    except (ValueError, TypeError):
        return False
    
    excluded_paths = settings.get("security", {}).get("excluded_paths", [])
    
    for excluded_path in excluded_paths:
        if not excluded_path or not isinstance(excluded_path, str):
            continue
            
        # Normalize the excluded path too
        try:
            normalized_excluded = os.path.normpath(excluded_path)
            if not normalized_excluded.startswith('/'):
                normalized_excluded = '/' + normalized_excluded
                
            # Use exact match or proper prefix match
            if normalized_path == normalized_excluded or normalized_path.startswith(normalized_excluded + '/'):
                return True
        except (ValueError, TypeError):
            continue
            
    return False

def load_whitelist(settings: Dict[str, Any]) -> Dict[str, int]:
    """Loads the whitelist from the JSON file."""
    path = Path(settings.get("whitelist", {}).get("storage_path", "whitelist.json"))
    if not path.exists():
        return {}
    with open(path, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_whitelist(whitelist: Dict[str, int], settings: Dict[str, Any]):
    """Saves the whitelist to the JSON file."""
    path = Path(settings.get("whitelist", {}).get("storage_path", "whitelist.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(whitelist, f, indent=2)

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