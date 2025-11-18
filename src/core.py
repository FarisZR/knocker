import ipaddress
import json
import time
import fcntl
import threading
import logging
import hmac
from pathlib import Path
from typing import Dict, Any, Optional, Union
from contextlib import contextmanager

# Thread lock for whitelist operations
# Using RLock (reentrant lock) to allow nested lock acquisition
# in read-modify-write sequences
_whitelist_lock = threading.RLock()


@contextmanager
def _interprocess_whitelist_lock(whitelist_path: Path):
    """
    Cross-process file lock for whitelist operations.

    Prevents race conditions when multiple processes modify the whitelist
    simultaneously (e.g., multiple Knocker instances or external scripts).

    Args:
        whitelist_path: Path to the whitelist JSON file

    Yields:
        None (lock is held for the duration of the context)
    """
    # Ensure lock file directory exists
    lock_file_path = whitelist_path.with_suffix(".lock")
    lock_file_path.parent.mkdir(parents=True, exist_ok=True)

    # Acquire exclusive file lock
    with open(lock_file_path, "w") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


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


def is_ip_whitelisted(
    ip: str, whitelist: Dict[str, Union[int, Dict[str, Any]]], settings: Dict[str, Any]
) -> bool:
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
            continue  # Ignore invalid entries

    # 2. Check dynamic whitelist
    now = int(time.time())
    for entry, value in whitelist.items():
        if isinstance(value, dict):
            expiry = value.get("expiry", 0)
        else:
            expiry = value

        if expiry > now:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if client_ip_obj in network:
                    return True
            except ValueError:
                continue  # Ignore invalid entries

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
            if normalized_path == normalized_excluded or normalized_path.startswith(
                normalized_excluded + "/"
            ):
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


def load_whitelist(settings: Dict[str, Any]) -> Dict[str, Union[int, Dict[str, Any]]]:
    """Loads the whitelist from the JSON file with thread safety."""
    with _whitelist_lock:
        path = Path(settings.get("whitelist", {}).get("storage_path", "whitelist.json"))
        if not path.exists():
            return {}

        try:
            with open(path, "r") as f:
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


def save_whitelist(
    whitelist: Dict[str, Union[int, Dict[str, Any]]], settings: Dict[str, Any]
):
    """Saves the whitelist to the JSON file with thread safety and size limits."""
    with _whitelist_lock:
        path = Path(settings.get("whitelist", {}).get("storage_path", "whitelist.json"))

        # Security check: limit whitelist size to prevent DoS
        max_entries = settings.get("security", {}).get("max_whitelist_entries", 10000)
        if len(whitelist) > max_entries:
            # Helper to extract expiry for sorting
            def get_expiry(item):
                val = item[1]
                if isinstance(val, dict):
                    return val.get("expiry", 0)
                return val

            # Remove oldest entries if limit exceeded
            sorted_items = sorted(whitelist.items(), key=get_expiry)
            whitelist = dict(sorted_items[-max_entries:])

        path.parent.mkdir(parents=True, exist_ok=True)

        # Write to temporary file first, then atomically rename
        temp_path = path.with_suffix(".tmp")
        try:
            with open(temp_path, "w") as f:
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


def add_ip_to_whitelist(
    ip_or_cidr: str,
    expiry_time: int,
    settings: Dict[str, Any],
    token_id: Optional[str] = None,
) -> Optional[str]:
    """
    Adds an IP or CIDR to the whitelist and saves it.

    The entire read-modify-write sequence is protected by both in-process and
    cross-process locks to prevent race conditions from concurrent updates.

    Args:
        ip_or_cidr: IP address or CIDR range to whitelist
        expiry_time: Unix timestamp when the entry expires
        settings: Application settings
        token_id: Optional unique identifier for the token used. If provided,
                  ensures only one IP is whitelisted for this token.

    Returns:
        The IP address that was removed (replaced) if any, otherwise None.

    Raises:
        ValueError: If ip_or_cidr is invalid or expiry_time is in the past
    """
    # Input validation: verify IP/CIDR format
    if not is_valid_ip_or_cidr(ip_or_cidr):
        raise ValueError(f"Invalid IP address or CIDR notation: {ip_or_cidr}")

    # Input validation: verify expiry time is in the future
    now = int(time.time())
    if expiry_time <= now:
        raise ValueError(
            f"Expiry time {expiry_time} is not in the future (current time: {now})"
        )

    # Get whitelist path for cross-process locking
    whitelist_path = Path(
        settings.get("whitelist", {}).get("storage_path", "whitelist.json")
    )

    # Use both in-process and cross-process locks
    with _whitelist_lock:
        with _interprocess_whitelist_lock(whitelist_path):
            whitelist = load_whitelist(settings)

            old_ip = None
            if token_id:
                # Find and remove old entry for this token
                for ip, value in list(whitelist.items()):
                    existing_token_id = None
                    if isinstance(value, dict):
                        existing_token_id = value.get("token_id")

                    if existing_token_id == token_id:
                        if ip != ip_or_cidr:
                            old_ip = ip
                            del whitelist[ip]
                            # Assuming one entry per token, we can break.
                            break
                        # If same IP, we just update TTL below.

            # Add new entry
            if token_id:
                whitelist[ip_or_cidr] = {"expiry": expiry_time, "token_id": token_id}
            else:
                # Backward compatibility / no token
                whitelist[ip_or_cidr] = expiry_time

            save_whitelist(whitelist, settings)
            return old_ip


def add_ip_to_whitelist_with_firewalld(
    ip_or_cidr: str,
    expiry_time: int,
    settings: Dict[str, Any],
    token_id: Optional[str] = None,
) -> bool:
    """
    Adds an IP or CIDR to the whitelist with firewalld integration.

    Firewalld rules are added BEFORE updating whitelist.json to ensure
    security. If firewalld fails, whitelist.json is not updated.

    Args:
        ip_or_cidr: IP address or CIDR to whitelist
        expiry_time: Unix timestamp when entry should expire
        settings: Application settings
        token_id: Optional unique identifier for the token used.

    Returns:
        True if successful, False if firewalld integration failed
    """
    # Import here to avoid circular imports - use try/except for different import contexts
    try:
        from . import firewalld
    except ImportError:
        import firewalld

    # Get firewalld integration instance
    firewalld_integration = firewalld.get_firewalld_integration()

    if firewalld_integration and firewalld_integration.is_enabled():
        # First, add firewalld rules
        if not firewalld_integration.add_whitelist_rule(ip_or_cidr, expiry_time):
            # Firewalld failed - do NOT update whitelist.json
            return False

    # Firewalld succeeded (or is disabled), now update whitelist.json
    # Wrap in try/except to handle rollback if whitelist.json update fails
    try:
        old_ip = add_ip_to_whitelist(
            ip_or_cidr, expiry_time, settings, token_id=token_id
        )

        # If an old IP was replaced, remove its firewalld rule
        if old_ip and firewalld_integration and firewalld_integration.is_enabled():
            try:
                firewalld_integration.remove_whitelist_rule(old_ip)
                logging.info(
                    f"Removed old firewall rule for {old_ip} (replaced by {ip_or_cidr})"
                )
            except Exception as e:
                logging.error(f"Failed to remove old firewall rule for {old_ip}: {e}")

        return True
    except Exception as e:
        # Rollback firewalld rules if whitelist.json update fails
        if firewalld_integration and firewalld_integration.is_enabled():
            try:
                firewalld_integration.remove_whitelist_rule(ip_or_cidr)
                logging.error(
                    f"Rolled back firewalld rules for {ip_or_cidr} due to whitelist persistence failure: {e}"
                )
            except Exception as rollback_error:
                logging.error(
                    f"Failed to rollback firewalld rules for {ip_or_cidr}: {rollback_error}"
                )

        logging.error(f"Failed to persist whitelist entry for {ip_or_cidr}: {e}")
        return False


def cleanup_expired_ips(settings: Dict[str, Any]):
    """
    Removes expired entries from the whitelist file.

    The entire read-modify-write sequence is protected by both in-process and
    cross-process locks to prevent race conditions from concurrent updates.
    """
    # Get whitelist path for cross-process locking
    whitelist_path = Path(
        settings.get("whitelist", {}).get("storage_path", "whitelist.json")
    )

    # Use both in-process and cross-process locks
    with _whitelist_lock:
        with _interprocess_whitelist_lock(whitelist_path):
            whitelist = load_whitelist(settings)
            now = int(time.time())

            # Create a new dict with only the non-expired entries
            fresh_whitelist = {}
            for entry, value in whitelist.items():
                if isinstance(value, dict):
                    expiry = value.get("expiry", 0)
                else:
                    expiry = value

                if expiry > now:
                    fresh_whitelist[entry] = value

            # Only save if the whitelist actually changed
            if fresh_whitelist != whitelist:
                save_whitelist(fresh_whitelist, settings)


# --- Permissions & Key Helpers ---


def can_whitelist_remote(api_key: str, settings: Dict[str, Any]) -> bool:
    """Checks if the given API key has permission to whitelist remote IPs."""
    for key_info in settings.get("api_keys", []):
        if key_info.get("key") == api_key:
            return key_info.get("allow_remote_whitelist", False)
    return False


def get_max_ttl_for_key(api_key: str, settings: Dict[str, Any]) -> int:
    """Finds the maximum TTL for a given API key."""
    for key_info in settings.get("api_keys", []):
        if key_info.get("key") == api_key:
            return key_info.get("max_ttl", 0)
    return 0


def is_valid_api_key(api_key: str, settings: Dict[str, Any]) -> bool:
    """
    Checks if an API key exists in the configuration.
    Uses constant-time comparison to prevent timing attacks.

    Important: This function iterates through ALL keys regardless of match
    to maintain constant time operation and prevent timing attack vectors.
    """
    if not api_key:
        return False

    api_keys_list = settings.get("api_keys", [])
    if not api_keys_list:
        logging.warning("No API keys configured in settings")
        return False

    # Use constant-time comparison to prevent timing attacks
    # IMPORTANT: We must check ALL keys, not return early on first match
    # We use bitwise OR to avoid short-circuit evaluation
    found = False
    for key_info in api_keys_list:
        stored_key = key_info.get("key", "")
        # Pad empty keys to ensure we always compare strings of similar length
        # This prevents timing differences from empty vs non-empty keys
        if not stored_key:
            # Use a dummy key of similar length to avoid empty string comparison
            stored_key = " " * len(api_key) if api_key else " "
        # Always call compare_digest for every key to maintain constant time
        # Use bitwise OR (|) instead of logical OR (or) to prevent short-circuiting
        found = found | hmac.compare_digest(stored_key, api_key)
    return found


def get_api_key_name(api_key: str, settings: Dict[str, Any]) -> str:
    """
    Returns the configured name for an API key, falling back to the key string
    if no explicit name is provided. Returns an empty string if api_key is falsy.
    """
    if not api_key:
        return ""
    for key_info in settings.get("api_keys", []):
        if key_info.get("key") == api_key:
            return key_info.get("name") or key_info.get("key")
    return api_key
