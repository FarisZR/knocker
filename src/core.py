import ipaddress
import json
import time
from pathlib import Path
from typing import Dict, Any

# --- IP/CIDR Validation ---

def is_valid_ip_or_cidr(address: str) -> bool:
    """Validates if a string is a valid IPv4/IPv6 address or CIDR network."""
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False

# --- Whitelist Management ---

def is_ip_whitelisted(ip: str, whitelist: Dict[str, int]) -> bool:
    """Checks if a given IP is contained within any of the whitelisted networks."""
    try:
        client_ip_obj = ipaddress.ip_address(ip)
        now = int(time.time())
        
        for entry, expiry in whitelist.items():
            if expiry > now:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if client_ip_obj in network:
                        return True
                except ValueError:
                    # Ignore invalid entries in the whitelist file
                    continue
    except ValueError:
        # The IP to check was invalid
        return False
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

def get_ttl_for_key(api_key: str, settings: Dict[str, Any]) -> int:
    """Finds the TTL for a given API key."""
    for key_info in settings.get('api_keys', []):
        if key_info.get('key') == api_key:
            return key_info.get('ttl', 0)
    return 0

def is_valid_api_key(api_key: str, settings: Dict[str, Any]) -> bool:
    """Checks if an API key exists in the configuration."""
    if not api_key:
        return False
    return any(key_info.get('key') == api_key for key_info in settings.get('api_keys', []))