import yaml
from typing import Dict, Any

def load_config(path: str = "knocker.yaml") -> Dict[str, Any]:
    """Loads the YAML configuration file."""
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # In a real application, you might have better error handling
        # or default values. For this service, we expect the file to exist.
        print(f"Error: Configuration file not found at {path}")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return {}