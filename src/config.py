import yaml
import sys
import os
import logging
import ipaddress
from typing import Dict, Any

def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validates the configuration for security issues.
    
    Args:
        config: The loaded configuration dictionary
        
    Returns:
        True if configuration is valid, False otherwise
        
    Raises:
        ValueError: If critical security configuration is invalid
    """
    # Validate trusted_proxies
    trusted_proxies = config.get("server", {}).get("trusted_proxies", [])
    if not isinstance(trusted_proxies, list):
        raise ValueError("trusted_proxies must be a list")
    
    for proxy in trusted_proxies:
        if proxy is None or proxy == "":
            continue  # Skip empty entries but warn
        if not isinstance(proxy, str):
            raise ValueError(f"trusted_proxies entry must be string, got {type(proxy)}")
        try:
            ipaddress.ip_network(proxy, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid trusted_proxies entry '{proxy}': {e}")
    
    # Validate always_allowed_ips
    always_allowed = config.get("security", {}).get("always_allowed_ips", [])
    if not isinstance(always_allowed, list):
        raise ValueError("always_allowed_ips must be a list")
        
    for ip_entry in always_allowed:
        if ip_entry is None or ip_entry == "":
            continue
        if not isinstance(ip_entry, str):
            raise ValueError(f"always_allowed_ips entry must be string, got {type(ip_entry)}")
        try:
            ipaddress.ip_network(ip_entry, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid always_allowed_ips entry '{ip_entry}': {e}")
    
    # Validate excluded_paths
    excluded_paths = config.get("security", {}).get("excluded_paths", [])
    if not isinstance(excluded_paths, list):
        raise ValueError("excluded_paths must be a list")
        
    for path in excluded_paths:
        if path is None:
            continue
        if not isinstance(path, str):
            raise ValueError(f"excluded_paths entry must be string, got {type(path)}")
        # Warn about suspicious paths
        if '..' in path:
            logging.warning(f"Suspicious path in excluded_paths: '{path}' contains '..'")
        if path == "":
            logging.warning("Empty string in excluded_paths could match all paths")
    
    # Validate API keys
    api_keys = config.get("api_keys", [])
    if not isinstance(api_keys, list):
        raise ValueError("api_keys must be a list")
        
    if len(api_keys) == 0:
        logging.warning("No API keys configured - service will reject all requests")
        
    for i, key_config in enumerate(api_keys):
        if not isinstance(key_config, dict):
            raise ValueError(f"api_keys[{i}] must be a dictionary")
            
        key_value = key_config.get("key")
        if not key_value or not isinstance(key_value, str):
            raise ValueError(f"api_keys[{i}] missing or invalid 'key' field")
            
        if len(key_value) < 16:
            logging.warning(f"API key {i} is very short ({len(key_value)} chars) - consider using longer keys")
            
        max_ttl = key_config.get("max_ttl")
        if max_ttl is not None and (not isinstance(max_ttl, int) or max_ttl <= 0):
            raise ValueError(f"api_keys[{i}] max_ttl must be positive integer")
            
        allow_remote = key_config.get("allow_remote_whitelist")
        if allow_remote is not None and not isinstance(allow_remote, bool):
            raise ValueError(f"api_keys[{i}] allow_remote_whitelist must be boolean")
    
    return True


def setup_logging(settings: Dict[str, Any]):
    """
    Configures logging for the application.
    """
    log_level = settings.get("logging", {}).get("level", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout
    )


def load_config() -> Dict[str, Any]:
    """
    Loads the YAML configuration file from the path specified
    by the KNOCKER_CONFIG_PATH environment variable and validates it.
    """
    path = os.getenv("KNOCKER_CONFIG_PATH")
    if not path:
        logging.critical("KNOCKER_CONFIG_PATH environment variable not set.")
        sys.exit(1)

    try:
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logging.critical(f"Configuration file not found at {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.critical(f"Error parsing YAML file: {e}")
        sys.exit(1)
    
    # Validate the configuration for security issues
    try:
        validate_config(config)
        logging.info("Configuration validation passed")
    except ValueError as e:
        logging.critical(f"Configuration validation failed: {e}")
        sys.exit(1)
        
    return config