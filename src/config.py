import ipaddress
import logging
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)


MAX_TTL = 315360000
_ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _allowed_whitelist_storage_roots() -> tuple[str, ...]:
    roots: list[str] = []
    seen: set[str] = set()
    for candidate in (os.getcwd(), "/data", "/tmp"):
        resolved = os.path.realpath(candidate)
        if resolved == os.sep or resolved in seen:
            continue
        roots.append(resolved)
        seen.add(resolved)
    return tuple(roots)


def validate_whitelist_storage_path(
    path_value: str | os.PathLike[str],
    *,
    allowed_suffixes: tuple[str, ...] = (".json",),
) -> Path:
    """Restrict whitelist storage to known-safe roots and file types."""
    try:
        raw_path = os.fspath(path_value)
    except TypeError as exc:
        raise ValueError("whitelist.storage_path must be a non-empty string") from exc

    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("whitelist.storage_path must be a non-empty string")
    if "\x00" in raw_path:
        raise ValueError("whitelist.storage_path contains invalid characters")
    if not any(raw_path.endswith(suffix) for suffix in allowed_suffixes):
        allowed = ", ".join(allowed_suffixes)
        raise ValueError(f"whitelist.storage_path must use one of these suffixes: {allowed}")

    joined_path = raw_path if os.path.isabs(raw_path) else os.path.join(os.getcwd(), raw_path)
    resolved_path = os.path.realpath(joined_path)
    allowed_roots = _allowed_whitelist_storage_roots()
    if not any(
        resolved_path == root or resolved_path.startswith(f"{root}{os.sep}")
        for root in allowed_roots
    ):
        allowed = ", ".join(allowed_roots)
        raise ValueError(f"whitelist.storage_path must stay within one of these roots: {allowed}")

    return Path(resolved_path)


def _validate_network_entries(entries: Sequence[str], label: str) -> list[str]:
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid {label} entry '{entry}': {exc}") from exc
    return list(entries)


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    trusted_proxies: list[StrictStr] = Field(default_factory=list)

    @field_validator("trusted_proxies")
    @classmethod
    def validate_trusted_proxies(cls, value: list[str]) -> list[str]:
        return _validate_network_entries(value, "trusted_proxies")


class CorsSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    allowed_origin: StrictStr = "*"


class KnockRateLimitSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    window_seconds: StrictInt = 60
    successful_requests: StrictInt = 20
    failed_requests: StrictInt = 30

    @model_validator(mode="after")
    def validate_limits(self) -> "KnockRateLimitSettings":
        if self.window_seconds <= 0:
            raise ValueError("security.knock_rate_limit.window_seconds must be positive")
        if self.successful_requests < 0 or self.failed_requests < 0:
            raise ValueError("security.knock_rate_limit limits must be zero or greater")
        return self


class SecuritySettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    always_allowed_ips: list[StrictStr] = Field(default_factory=list)
    excluded_paths: list[StrictStr] = Field(default_factory=list)
    excluded_paths_by_host: dict[StrictStr, list[StrictStr]] = Field(default_factory=dict)
    max_whitelist_entries: StrictInt = 10000
    knock_rate_limit: KnockRateLimitSettings = Field(default_factory=KnockRateLimitSettings)

    @field_validator("always_allowed_ips")
    @classmethod
    def validate_always_allowed_ips(cls, value: list[str]) -> list[str]:
        return _validate_network_entries(value, "always_allowed_ips")

    @field_validator("excluded_paths_by_host", mode="before")
    @classmethod
    def normalize_host_exclusions(cls, value: Any) -> Any:
        return {} if value is None else value

    @model_validator(mode="after")
    def validate_security(self) -> "SecuritySettings":
        if self.max_whitelist_entries <= 0:
            raise ValueError("security.max_whitelist_entries must be positive")
        for host in self.excluded_paths_by_host:
            if not host.strip():
                raise ValueError("Invalid excluded_paths_by_host host")
        return self


class WhitelistSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    storage_path: StrictStr = "whitelist.json"
    cleanup_interval_seconds: StrictInt = 60

    @field_validator("storage_path")
    @classmethod
    def validate_storage_path(cls, value: str) -> str:
        return str(validate_whitelist_storage_path(value))

    @model_validator(mode="after")
    def validate_cleanup_interval(self) -> "WhitelistSettings":
        if self.cleanup_interval_seconds <= 0:
            raise ValueError("whitelist.cleanup_interval_seconds must be positive")
        return self


class FirewalldPortSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    port: StrictInt
    protocol: StrictStr = "tcp"


class FirewalldSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: StrictBool = False
    zone_name: StrictStr = "knocker"
    zone_priority: StrictInt = -100
    default_action: StrictStr = "drop"
    zone_target: StrictStr | None = None
    monitored_ports: list[FirewalldPortSettings] = Field(default_factory=list)
    monitored_ips: list[StrictStr] = Field(default_factory=list)
    mutation_queue_capacity: StrictInt = 32

    @model_validator(mode="after")
    def validate_enabled_configuration(self) -> "FirewalldSettings":
        if self.mutation_queue_capacity <= 0:
            raise ValueError("firewalld.mutation_queue_capacity must be a positive integer")
        if not self.enabled:
            return self

        if not _ZONE_NAME_RE.fullmatch(self.zone_name):
            raise ValueError(
                "Invalid zone_name. Use only letters, numbers, dots, underscores, colons, and hyphens"
            )
        if self.default_action not in {"drop", "reject"}:
            raise ValueError(
                f"Invalid default_action '{self.default_action}'. Must be 'drop' or 'reject'"
            )
        if self.zone_target not in {None, "default", "ACCEPT", "REJECT", "DROP"}:
            raise ValueError(
                f"Invalid zone_target '{self.zone_target}'. Must be one of: default, ACCEPT, REJECT, DROP"
            )

        for index, port_config in enumerate(self.monitored_ports):
            if not 1 <= port_config.port <= 65535:
                raise ValueError(
                    f"firewalld.monitored_ports[{index}].port must be an integer between 1 and 65535"
                )
            if port_config.protocol not in {"tcp", "udp"}:
                raise ValueError(
                    f"firewalld.monitored_ports[{index}].protocol must be 'tcp' or 'udp'"
                )

        for monitored_ip in self.monitored_ips:
            if "/" not in monitored_ip:
                raise ValueError(
                    "Invalid monitored IP configuration: Entries must include an explicit network mask"
                )
            try:
                ipaddress.ip_network(monitored_ip, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid monitored IP configuration: {exc}") from exc
        return self


class APIKeySettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: StrictStr | None = None
    key: StrictStr
    max_ttl: StrictInt
    allow_remote_whitelist: StrictBool = False

    @field_validator("allow_remote_whitelist", mode="before")
    @classmethod
    def validate_remote_permission(cls, value: Any) -> Any:
        if not isinstance(value, bool):
            raise ValueError("API key must define boolean allow_remote_whitelist")
        return value


def validate_api_key_records(
    api_keys: Sequence[APIKeySettings | Mapping[str, Any]],
) -> tuple[APIKeySettings, ...]:
    """Validate API-key policy once and return typed records."""
    if not api_keys:
        raise ValueError("Configuration must contain at least one API key")

    records: list[APIKeySettings] = []
    seen_keys: set[str] = set()
    for index, key_info in enumerate(api_keys):
        try:
            record = (
                key_info
                if isinstance(key_info, APIKeySettings)
                else APIKeySettings.model_validate(key_info)
            )
        except ValidationError as exc:
            raise ValueError(f"Invalid API key configuration at index {index}: {exc}") from exc

        if not record.key:
            raise ValueError(f"API key at index {index} must define a non-empty string key")
        normalized_key = record.key.upper()
        if "CHANGE_ME" in normalized_key or "REPLACE_WITH" in normalized_key:
            raise ValueError(
                f"API key at index {index} uses a published or placeholder secret; generate a unique random API key"
            )
        if record.key in seen_keys:
            raise ValueError(f"Duplicate API key material detected at index {index}")
        seen_keys.add(record.key)
        if record.max_ttl <= 0:
            raise ValueError(f"API key at index {index} must define a positive integer max_ttl")
        records.append(record)
    return tuple(records)


class DocumentationSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: StrictBool = False
    openapi_output_path: StrictStr = "openapi.json"


class LoggingSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    level: StrictStr = "INFO"


class Settings(BaseModel):
    """Validated application configuration shared by all runtime services."""

    model_config = ConfigDict(extra="ignore")

    server: ServerSettings = Field(default_factory=ServerSettings)
    cors: CorsSettings = Field(default_factory=CorsSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    whitelist: WhitelistSettings = Field(default_factory=WhitelistSettings)
    firewalld: FirewalldSettings = Field(default_factory=FirewalldSettings)
    api_keys: list[APIKeySettings] = Field(default_factory=list)
    documentation: DocumentationSettings = Field(default_factory=DocumentationSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    _runtime_state: Any = PrivateAttr(default=None)

    @model_validator(mode="after")
    def validate_api_keys(self) -> "Settings":
        validate_api_key_records(self.api_keys)
        return self


SettingsLike = Settings | Mapping[str, Any]


def validate_settings(settings: SettingsLike) -> Settings:
    """Convert an external mapping to the one typed settings object."""
    if isinstance(settings, Settings):
        return settings
    return Settings.model_validate(settings)


def setup_logging(settings: SettingsLike) -> None:
    """Configure application and common server loggers from validated settings."""
    resolved = validate_settings(settings)
    log_level = resolved.logging.level.upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        force=True,
    )
    logging.getLogger().setLevel(log_level)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(logger_name).setLevel(log_level)


def load_config() -> Settings:
    """Load and validate YAML configuration from ``KNOCKER_CONFIG_PATH``."""
    path = os.getenv("KNOCKER_CONFIG_PATH")
    if not path:
        logging.critical("KNOCKER_CONFIG_PATH environment variable not set.")
        sys.exit(1)

    try:
        if ".." in path or not os.path.isabs(path):
            logging.critical(f"Invalid configuration path: {path}")
            sys.exit(1)
        resolved_path = os.path.realpath(path)
    except (OSError, ValueError) as exc:
        logging.critical(f"Error validating configuration path {path}: {exc}")
        sys.exit(1)

    try:
        with open(resolved_path, "r") as handle:
            raw_config = yaml.safe_load(handle) or {}
        if not isinstance(raw_config, dict):
            logging.critical("Configuration file must contain a valid YAML dictionary")
            sys.exit(1)
        try:
            return Settings.model_validate(raw_config)
        except (ValidationError, ValueError) as exc:
            logging.critical(f"Invalid configuration: {exc}")
            sys.exit(1)
    except FileNotFoundError:
        logging.critical(f"Configuration file not found at {resolved_path}")
        sys.exit(1)
    except yaml.YAMLError as exc:
        logging.critical(f"Error parsing YAML file: {exc}")
        sys.exit(1)
    except OSError as exc:
        logging.critical(f"Error loading configuration file {resolved_path}: {exc}")
        sys.exit(1)
