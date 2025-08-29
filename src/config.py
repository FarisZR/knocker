import yaml
import sys
import os
from typing import Dict, Any

def load_config() -> Dict[str, Any]:
    """
    Loads the YAML configuration file from the path specified
    by the KNOCKER_CONFIG_PATH environment variable.
    """
    path = os.getenv("KNOCKER_CONFIG_PATH")
    if not path:
        print("Error: KNOCKER_CONFIG_PATH environment variable not set.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {path}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}", file=sys.stderr)
        sys.exit(1)