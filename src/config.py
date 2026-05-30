import yaml
import sys
import os
import logging
from typing import Dict, Any

try:
    from . import core
except ImportError:  # pragma: no cover - fallback for direct module execution
    import core

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
            config = yaml.safe_load(f) or {}
            
        # Validate configuration structure
        if not isinstance(config, dict):
            logging.critical("Configuration file must contain a valid YAML dictionary")
            sys.exit(1)

        try:
            core.ensure_runtime_state(config)
        except ValueError as exc:
            logging.critical(f"Invalid configuration: {exc}")
            sys.exit(1)
            
        return config
    except FileNotFoundError:
        logging.critical(f"Configuration file not found at {resolved_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.critical(f"Error parsing YAML file: {e}")
        sys.exit(1)
    except OSError as e:
        logging.critical(f"Error loading configuration file {resolved_path}: {e}")
        sys.exit(1)
