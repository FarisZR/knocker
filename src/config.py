import yaml
import sys
import os
import logging
from typing import Dict, Any

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
    by the KNOCKER_CONFIG_PATH environment variable.
    """
    path = os.getenv("KNOCKER_CONFIG_PATH")
    if not path:
        logging.critical("KNOCKER_CONFIG_PATH environment variable not set.")
        sys.exit(1)

    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.critical(f"Configuration file not found at {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.critical(f"Error parsing YAML file: {e}")
        sys.exit(1)