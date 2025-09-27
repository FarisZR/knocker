import json
import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI


DEFAULT_OPENAPI_PATH = "docs/openapi.json"
DOCUMENTATION_SETTINGS_KEY = "documentation"
OPENAPI_PATH_KEY = "openapi_output_path"


def _normalize_path(raw_path: str) -> Path:
    """Resolve a potentially relative path to an absolute filesystem path."""
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def resolve_openapi_output_path(settings: Dict[str, Any]) -> Path:
    """Return the path where the generated OpenAPI document should be stored."""
    documentation_settings = settings.get(DOCUMENTATION_SETTINGS_KEY, {}) if settings else {}
    raw_path = documentation_settings.get(OPENAPI_PATH_KEY, DEFAULT_OPENAPI_PATH)
    return _normalize_path(raw_path)


def generate_openapi_document(app: FastAPI, settings: Dict[str, Any]) -> Path:
    """Generate the OpenAPI schema for the application and persist it to disk."""
    openapi_schema = app.openapi()
    output_path = resolve_openapi_output_path(settings)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file_handle:
        json.dump(openapi_schema, file_handle, indent=2)

    logging.getLogger("uvicorn.error").info(
        "OpenAPI schema written to %s", output_path
    )
    app.state.openapi_output_path = str(output_path)
    return output_path


def ensure_openapi_document(app: FastAPI, settings: Dict[str, Any]) -> Path:
    """Guarantee the OpenAPI document exists; regenerate it if it's missing."""
    output_path = resolve_openapi_output_path(settings)
    if not output_path.exists():
        return generate_openapi_document(app, settings)
    app.state.openapi_output_path = str(output_path)
    return output_path
