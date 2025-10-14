import yaml
import sys
import os
import logging
from typing import Dict, Any

def setup_logging(settings: Dict[str, Any]):
    """
    Configures logging for the application.
    Ensures existing handlers (e.g., uvicorn's) are updated so DEBUG-level
    logs from modules like src.firewalld are emitted when requested.
    """
    log_level = settings.get("logging", {}).get("level", "INFO").upper()

    # Update basic config and force reconfiguration of existing handlers so that
    # running under uvicorn or other servers respects the requested level.
    # `force=True` requires Python 3.8+ and will replace existing handlers.
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        force=True
    )

    # Ensure the root logger and common framework loggers follow the configured level.
    logging.getLogger().setLevel(log_level)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(logger_name).setLevel(log_level)

def load_config() -> Dict[str, Any]:
    """
    Loads the YAML configuration file from the path specified
    by the KNOCKER_CONFIG_PATH environment variable.
    """
    path = os.getenv("KNOCKER_CONFIG_PATH")
    if not path:
        logging.critical("KNOCKER_CONFIG_PATH environment variable not set.")
        sys.exit(1)

    # Security: Validate path to prevent directory traversal and ensure it's absolute
    try:
        resolved_path = os.path.realpath(path)
        # Ensure the path doesn't contain suspicious patterns
        if '..' in path or not os.path.isabs(resolved_path):
            logging.critical(f"Invalid configuration path: {path}")
            sys.exit(1)
    except (OSError, ValueError) as e:
        logging.critical(f"Error validating configuration path {path}: {e}")
        sys.exit(1)

    try:
        with open(resolved_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # Validate configuration structure
        if not isinstance(config, dict):
            logging.critical("Configuration file must contain a valid YAML dictionary")
            sys.exit(1)
            
        # Validate critical configuration sections
        if not config.get('api_keys'):
            logging.critical("Configuration must contain at least one API key in 'api_keys' section")
            sys.exit(1)
            
        if not isinstance(config.get('api_keys'), list) or len(config['api_keys']) == 0:
            logging.critical("'api_keys' must be a non-empty list")
            sys.exit(1)
        
        # Check for duplicate API keys
        seen_keys = set()
        for idx, key_info in enumerate(config['api_keys']):
            if not isinstance(key_info, dict):
                logging.critical(f"API key at index {idx} must be a dictionary")
                sys.exit(1)
            key = key_info.get('key')
            if not key:
                logging.critical(f"API key at index {idx} is missing 'key' field")
                sys.exit(1)
            if key in seen_keys:
                logging.critical(f"Duplicate API key detected: {key[:8]}... (showing first 8 chars)")
                sys.exit(1)
            seen_keys.add(key)
            
        return config
    except FileNotFoundError:
        logging.critical(f"Configuration file not found at {resolved_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.critical(f"Error parsing YAML file: {e}")
        sys.exit(1)