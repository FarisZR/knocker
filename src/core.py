from __future__ import annotations

import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, Optional, Sequence, Tuple, Union
from urllib.parse import unquote, urlsplit

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_whitelist_lock = threading.RLock()
_RUNTIME_STATE_KEY = "_knocker_runtime_state"
_API_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _allowed_whitelist_storage_roots() -> Tuple[str, ...]:
    roots: list[str] = []
    seen: set[str] = set()
    for candidate in (os.getcwd(), "/data", "/tmp"):
        resolved = os.path.realpath(candidate)
        if resolved in seen:
            continue
        roots.append(resolved)
        seen.add(resolved)
    return tuple(roots)


def validate_whitelist_storage_path(
    path_value: Union[str, os.PathLike[str]],
    *,
    allowed_suffixes: Tuple[str, ...] = (".json",),
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
        raise ValueError(
            f"whitelist.storage_path must stay within one of these roots: {allowed}"
        )

    return Path(resolved_path)


def get_whitelist_storage_path(settings: Dict[str, Any]) -> Path:
    whitelist_settings = settings.setdefault("whitelist", {})
    if not isinstance(whitelist_settings, dict):
        raise ValueError("whitelist configuration must be a mapping")

    storage_path = validate_whitelist_storage_path(whitelist_settings.get("storage_path", "whitelist.json"))
    whitelist_settings["storage_path"] = str(storage_path)
    return storage_path


@contextmanager
def _interprocess_whitelist_lock(whitelist_path: Path):
    """Hold a cross-process lock for whitelist mutations."""
    whitelist_path = validate_whitelist_storage_path(whitelist_path)
    lock_file_path = validate_whitelist_storage_path(
        whitelist_path.with_suffix(".lock"),
        allowed_suffixes=(".lock",),
    )
    lock_file_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_file_path.open("w", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def is_valid_ip_or_cidr(address: str) -> bool:
    """Validate IPv4/IPv6 addresses and CIDR ranges."""
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False


def is_safe_cidr_range(cidr: str, max_host_count: int = 65536) -> bool:
    """Reject overly broad CIDR ranges."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False

    if isinstance(network, ipaddress.IPv6Network):
        return network.prefixlen >= 64
    return network.num_addresses <= max_host_count


def _canonical_network(value: str) -> Tuple[str, IPNetwork]:
    network = ipaddress.ip_network(value, strict=False)
    if network.num_addresses == 1:
        return str(network.network_address), network
    return str(network), network


def _parse_entry_list(entries: Iterable[str], label: str) -> Tuple[Tuple[IPAddress, ...], Tuple[IPNetwork, ...]]:
    exact: list[IPAddress] = []
    networks: list[IPNetwork] = []
    for entry in entries:
        try:
            _, network = _canonical_network(entry)
        except ValueError as exc:
            raise ValueError(f"Invalid {label} entry '{entry}': {exc}") from exc

        if network.num_addresses == 1:
            exact.append(network.network_address)
        else:
            networks.append(network)

    return tuple(exact), tuple(networks)


@dataclass(frozen=True)
class ParsedNetworkSet:
    exact_v4: frozenset[ipaddress.IPv4Address] = frozenset()
    exact_v6: frozenset[ipaddress.IPv6Address] = frozenset()
    networks_v4: Tuple[ipaddress.IPv4Network, ...] = ()
    networks_v6: Tuple[ipaddress.IPv6Network, ...] = ()

    @classmethod
    def from_entries(cls, entries: Iterable[str], label: str) -> "ParsedNetworkSet":
        exact, networks = _parse_entry_list(entries, label)
        return cls(
            exact_v4=frozenset(addr for addr in exact if isinstance(addr, ipaddress.IPv4Address)),
            exact_v6=frozenset(addr for addr in exact if isinstance(addr, ipaddress.IPv6Address)),
            networks_v4=tuple(net for net in networks if isinstance(net, ipaddress.IPv4Network)),
            networks_v6=tuple(net for net in networks if isinstance(net, ipaddress.IPv6Network)),
        )

    def contains(self, address: IPAddress) -> bool:
        if isinstance(address, ipaddress.IPv4Address):
            if address in self.exact_v4:
                return True
            return any(address in network for network in self.networks_v4)

        if address in self.exact_v6:
            return True
        return any(address in network for network in self.networks_v6)


@dataclass
class DynamicWhitelistIndex:
    exact_v4: Dict[ipaddress.IPv4Address, int] = field(default_factory=dict)
    exact_v6: Dict[ipaddress.IPv6Address, int] = field(default_factory=dict)
    networks_v4: Dict[ipaddress.IPv4Network, int] = field(default_factory=dict)
    networks_v6: Dict[ipaddress.IPv6Network, int] = field(default_factory=dict)

    @classmethod
    def from_serialized(cls, whitelist: Dict[str, int]) -> "DynamicWhitelistIndex":
        index = cls()
        for entry, expiry in whitelist.items():
            canonical, network = _canonical_network(entry)
            expiry_int = int(expiry)
            if network.num_addresses == 1:
                if isinstance(network, ipaddress.IPv4Network):
                    index.exact_v4[ipaddress.IPv4Address(canonical)] = expiry_int
                else:
                    index.exact_v6[ipaddress.IPv6Address(canonical)] = expiry_int
            elif isinstance(network, ipaddress.IPv4Network):
                index.networks_v4[ipaddress.IPv4Network(canonical)] = expiry_int
            else:
                index.networks_v6[ipaddress.IPv6Network(canonical)] = expiry_int
        return index

    def contains(self, address: IPAddress, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        if isinstance(address, ipaddress.IPv4Address):
            expiry = self.exact_v4.get(address)
            if expiry and expiry > now:
                return True
            return any(expiry_time > now and address in network for network, expiry_time in self.networks_v4.items())

        expiry = self.exact_v6.get(address)
        if expiry and expiry > now:
            return True
        return any(expiry_time > now and address in network for network, expiry_time in self.networks_v6.items())

    def to_serialized(self, now: Optional[int] = None, include_expired: bool = True) -> Dict[str, int]:
        serialized: Dict[str, int] = {}
        cutoff = int(time.time()) if now is None else now

        for address, expiry in self.exact_v4.items():
            if include_expired or expiry > cutoff:
                serialized[str(address)] = expiry
        for address, expiry in self.exact_v6.items():
            if include_expired or expiry > cutoff:
                serialized[str(address)] = expiry
        for network, expiry in self.networks_v4.items():
            if include_expired or expiry > cutoff:
                serialized[str(network)] = expiry
        for network, expiry in self.networks_v6.items():
            if include_expired or expiry > cutoff:
                serialized[str(network)] = expiry

        return serialized


def _normalize_serialized_whitelist(
    whitelist: Dict[str, Any],
    *,
    drop_expired: bool,
    now: Optional[int] = None,
) -> Tuple[Dict[str, int], bool]:
    normalized: Dict[str, int] = {}
    changed = False
    cutoff = int(time.time()) if now is None else now

    for entry, expiry in whitelist.items():
        try:
            canonical, _ = _canonical_network(entry)
            expiry_int = int(expiry)
        except (ValueError, TypeError):
            changed = True
            continue

        if drop_expired and expiry_int <= cutoff:
            changed = True
            continue

        if canonical != entry:
            changed = True

        normalized[canonical] = expiry_int

    return normalized, changed


def _limit_whitelist_entries(whitelist: Dict[str, int], max_entries: int) -> Dict[str, int]:
    if max_entries <= 0 or len(whitelist) <= max_entries:
        return whitelist
    sorted_items = sorted(whitelist.items(), key=lambda item: item[1])
    return dict(sorted_items[-max_entries:])


def _read_whitelist_file(whitelist_path: Path) -> Dict[str, int]:
    whitelist_path = validate_whitelist_storage_path(whitelist_path)
    if not whitelist_path.exists():
        return {}

    try:
        with whitelist_path.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            try:
                data = json.load(handle)
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except (OSError, IOError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    raw: Dict[str, int] = {}
    for entry, expiry in data.items():
        if isinstance(entry, str):
            raw[entry] = expiry
    return raw


def _write_whitelist_file(whitelist_path: Path, whitelist: Dict[str, int]) -> None:
    whitelist_path = validate_whitelist_storage_path(whitelist_path)
    whitelist_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = validate_whitelist_storage_path(
        whitelist_path.with_suffix(".tmp"),
        allowed_suffixes=(".tmp",),
    )
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                json.dump(whitelist, handle, indent=2, sort_keys=True)
                handle.flush()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        temp_path.replace(whitelist_path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


@dataclass
class WhitelistStore:
    storage_path: Path
    max_entries: int
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger(__name__))
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _index: DynamicWhitelistIndex = field(default_factory=DynamicWhitelistIndex, init=False)
    _pending_compaction: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.storage_path = validate_whitelist_storage_path(self.storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        if self.storage_path.exists():
            if not os.access(self.storage_path, os.R_OK | os.W_OK):
                raise ValueError(f"Whitelist storage path is not readable and writable: {self.storage_path}")
        elif not os.access(self.storage_path.parent, os.R_OK | os.W_OK | os.X_OK):
            raise ValueError(f"Whitelist storage directory is not accessible: {self.storage_path.parent}")
        self.reload_from_disk()

    def reload_from_disk(self) -> None:
        raw = _read_whitelist_file(self.storage_path)
        normalized, changed = _normalize_serialized_whitelist(raw, drop_expired=True)
        with self._lock:
            self._index = DynamicWhitelistIndex.from_serialized(normalized)
            self._pending_compaction = changed

    def contains(self, address: IPAddress, now: Optional[int] = None) -> bool:
        with self._lock:
            return self._index.contains(address, now)

    def add(self, ip_or_cidr: str, expiry_time: int) -> None:
        if not is_valid_ip_or_cidr(ip_or_cidr):
            raise ValueError(f"Invalid IP address or CIDR notation: {ip_or_cidr}")

        now = int(time.time())
        if expiry_time <= now:
            raise ValueError(f"Expiry time {expiry_time} is not in the future (current time: {now})")

        canonical, _ = _canonical_network(ip_or_cidr)
        with self._lock:
            with _interprocess_whitelist_lock(self.storage_path):
                persisted = _read_whitelist_file(self.storage_path)
                normalized, _ = _normalize_serialized_whitelist(persisted, drop_expired=True, now=now)
                normalized[canonical] = expiry_time
                normalized = _limit_whitelist_entries(normalized, self.max_entries)
                _write_whitelist_file(self.storage_path, normalized)
                self._index = DynamicWhitelistIndex.from_serialized(normalized)
                self._pending_compaction = False

    def replace(self, whitelist: Dict[str, Any]) -> Dict[str, int]:
        now = int(time.time())
        normalized, _ = _normalize_serialized_whitelist(whitelist, drop_expired=False, now=now)
        normalized = _limit_whitelist_entries(normalized, self.max_entries)
        with self._lock:
            with _interprocess_whitelist_lock(self.storage_path):
                _write_whitelist_file(self.storage_path, normalized)
                active, changed = _normalize_serialized_whitelist(normalized, drop_expired=True, now=now)
                self._index = DynamicWhitelistIndex.from_serialized(active)
                self._pending_compaction = changed
        return normalized

    def compact_expired(self, now: Optional[int] = None) -> bool:
        cutoff = int(time.time()) if now is None else now
        with self._lock:
            before = self._index.to_serialized(include_expired=True)
            after = _limit_whitelist_entries(self._index.to_serialized(now=cutoff, include_expired=False), self.max_entries)
            if not self._pending_compaction and before == after:
                return False

            with _interprocess_whitelist_lock(self.storage_path):
                _write_whitelist_file(self.storage_path, after)
            self._index = DynamicWhitelistIndex.from_serialized(after)
            self._pending_compaction = False
            return True

    def active_snapshot(self) -> Dict[str, int]:
        with self._lock:
            return self._index.to_serialized(now=int(time.time()), include_expired=False)


def load_whitelist(settings: Dict[str, Any]) -> Dict[str, int]:
    """Load the persisted whitelist from disk."""
    path = get_whitelist_storage_path(settings)
    with _whitelist_lock:
        return _read_whitelist_file(path)


def save_whitelist(whitelist: Dict[str, int], settings: Dict[str, Any]):
    """Persist the whitelist to disk and refresh in-memory state when available."""
    path = get_whitelist_storage_path(settings)
    max_entries = settings.get("security", {}).get("max_whitelist_entries", 10000)
    with _whitelist_lock:
        normalized, _ = _normalize_serialized_whitelist(whitelist, drop_expired=False)
        normalized = _limit_whitelist_entries(normalized, max_entries)
        with _interprocess_whitelist_lock(path):
            _write_whitelist_file(path, normalized)

        runtime_state = settings.get(_RUNTIME_STATE_KEY)
        if isinstance(runtime_state, RuntimeState):
            runtime_state.whitelist.reload_from_disk()


def add_ip_to_whitelist(ip_or_cidr: str, expiry_time: int, settings: Dict[str, Any]):
    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    if isinstance(runtime_state, RuntimeState):
        runtime_state.whitelist.add(ip_or_cidr, expiry_time)
        return

    path = get_whitelist_storage_path(settings)
    max_entries = settings.get("security", {}).get("max_whitelist_entries", 10000)
    if not is_valid_ip_or_cidr(ip_or_cidr):
        raise ValueError(f"Invalid IP address or CIDR notation: {ip_or_cidr}")

    now = int(time.time())
    if expiry_time <= now:
        raise ValueError(f"Expiry time {expiry_time} is not in the future (current time: {now})")

    canonical, _ = _canonical_network(ip_or_cidr)
    with _whitelist_lock:
        with _interprocess_whitelist_lock(path):
            persisted = _read_whitelist_file(path)
            normalized, _ = _normalize_serialized_whitelist(persisted, drop_expired=True, now=now)
            normalized[canonical] = expiry_time
            normalized = _limit_whitelist_entries(normalized, max_entries)
            _write_whitelist_file(path, normalized)


def cleanup_expired_ips(settings: Dict[str, Any]):
    """Remove expired whitelist entries from persistent storage."""
    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    if isinstance(runtime_state, RuntimeState):
        runtime_state.whitelist.compact_expired()
        return

    path = get_whitelist_storage_path(settings)
    with _whitelist_lock:
        with _interprocess_whitelist_lock(path):
            persisted = _read_whitelist_file(path)
            normalized, _ = _normalize_serialized_whitelist(persisted, drop_expired=False)
            active, changed = _normalize_serialized_whitelist(normalized, drop_expired=True)
            if changed or active != normalized:
                _write_whitelist_file(path, active)


def normalize_path(path: str) -> str:
    """Normalize request paths before exclusion checks."""
    if not path:
        return "/"

    if "://" in path:
        raw_path = urlsplit(path).path or "/"
    else:
        raw_path = path.split("#", 1)[0].split("?", 1)[0]
    decoded_path = unquote(raw_path)
    if not decoded_path.startswith("/"):
        decoded_path = f"/{decoded_path}"

    parts: list[str] = []
    for part in decoded_path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)

    normalized = "/" + "/".join(parts)
    return normalized or "/"


def normalize_host(host: Optional[str]) -> Optional[str]:
    """Normalize forwarded/request hosts for exclusion matching."""
    if not host:
        return None

    first = host.split(",", 1)[0].strip()
    if not first:
        return None

    parsed = urlsplit(f"//{first}")
    return parsed.hostname.lower() if parsed.hostname else first.lower()


def _is_path_prefix_match(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    return path == prefix or path.startswith(f"{prefix}/")


@dataclass(frozen=True)
class PathExclusions:
    global_paths: Tuple[str, ...] = ()
    host_paths: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, security_settings: Dict[str, Any]) -> "PathExclusions":
        excluded_paths = security_settings.get("excluded_paths", []) or []
        if not isinstance(excluded_paths, list):
            raise ValueError("security.excluded_paths must be a list of path prefixes")

        global_paths = tuple(normalize_path(path) for path in excluded_paths)

        host_paths_config = security_settings.get("excluded_paths_by_host", {}) or {}
        if not isinstance(host_paths_config, dict):
            raise ValueError("security.excluded_paths_by_host must be a mapping of host to paths")

        host_paths: Dict[str, Tuple[str, ...]] = {}
        for host, paths in host_paths_config.items():
            normalized_host = normalize_host(host)
            if not normalized_host:
                raise ValueError(f"Invalid excluded_paths_by_host host '{host}'")
            if not isinstance(paths, list):
                raise ValueError(f"security.excluded_paths_by_host['{host}'] must be a list")
            host_paths[normalized_host] = tuple(normalize_path(path) for path in paths)

        return cls(global_paths=global_paths, host_paths=host_paths)

    def matches(self, host: Optional[str], path: str) -> bool:
        normalized_host = normalize_host(host)
        normalized_path = normalize_path(path)

        if any(_is_path_prefix_match(normalized_path, prefix) for prefix in self.global_paths):
            return True

        if normalized_host is None:
            return False

        scoped_paths = self.host_paths.get(normalized_host, ())
        wildcard_paths = self.host_paths.get("*", ())
        return any(
            _is_path_prefix_match(normalized_path, prefix)
            for prefix in (*scoped_paths, *wildcard_paths)
        )


def is_path_excluded(path: str, settings: Dict[str, Any], host: Optional[str] = None) -> bool:
    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    if isinstance(runtime_state, RuntimeState):
        return runtime_state.path_exclusions.matches(host, path)

    path_exclusions = PathExclusions.from_settings(settings.get("security", {}) or {})
    return path_exclusions.matches(host, path)


def is_trusted_proxy(client_ip: str, trusted_proxies: Union[Sequence[str], ParsedNetworkSet]) -> bool:
    if not client_ip:
        return False

    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    if isinstance(trusted_proxies, ParsedNetworkSet):
        return trusted_proxies.contains(address)

    parsed = ParsedNetworkSet.from_entries(trusted_proxies, "trusted_proxies")
    return parsed.contains(address)


def resolve_client_ip(
    direct_ip: Optional[str],
    forwarded_for: Optional[str],
    trusted_proxies: ParsedNetworkSet,
) -> Tuple[Optional[str], bool]:
    """Resolve the effective client IP using only trusted proxy headers."""
    if not direct_ip:
        return None, False

    try:
        ipaddress.ip_address(direct_ip)
    except ValueError:
        return None, False

    trusted_proxy = trusted_proxies.contains(ipaddress.ip_address(direct_ip))
    if not forwarded_for or not trusted_proxy:
        return direct_ip, False

    entries = [entry.strip() for entry in forwarded_for.split(",") if entry.strip()]
    if not entries or len(entries) > 20:
        return direct_ip, True

    parsed_entries: list[IPAddress] = []
    for entry in entries:
        try:
            parsed_entries.append(ipaddress.ip_address(entry))
        except ValueError:
            return direct_ip, True

    for candidate in reversed(parsed_entries):
        if trusted_proxies.contains(candidate):
            continue
        return str(candidate), True

    return str(parsed_entries[0]), True


def resolve_request_host(
    request_host: Optional[str],
    forwarded_host: Optional[str],
    forwarded_header_is_trusted: bool,
) -> Optional[str]:
    if forwarded_header_is_trusted and forwarded_host:
        return normalize_host(forwarded_host)
    if forwarded_header_is_trusted:
        return None
    return normalize_host(request_host)


def resolve_request_path(
    request_path: str,
    forwarded_uri: Optional[str],
    forwarded_header_is_trusted: bool,
) -> str:
    if forwarded_header_is_trusted and forwarded_uri:
        return forwarded_uri
    return request_path


@dataclass(frozen=True)
class APIKeyRecord:
    identifier: Optional[str]
    name: str
    max_ttl: int
    allow_remote_whitelist: bool
    secret_kind: str
    secret_value: str
    cache_key: str

    def verify(self, presented_key: str) -> bool:
        if not isinstance(presented_key, str):
            return False
        if self.secret_kind == "sha256":
            presented_digest = hashlib.sha256(presented_key.encode("utf-8")).hexdigest()
            return hmac.compare_digest(self.secret_value, presented_digest)
        return hmac.compare_digest(self.secret_value, presented_key)


def hash_api_key(secret: str) -> str:
    return f"sha256:{hashlib.sha256(secret.encode('utf-8')).hexdigest()}"


def _parse_hashed_secret(value: str) -> str:
    candidate = value.strip().lower()
    if candidate.startswith("sha256:"):
        candidate = candidate.split(":", 1)[1]
    if len(candidate) != 64 or not all(char in "0123456789abcdef" for char in candidate):
        raise ValueError("API key hashes must use the format sha256:<64 lowercase hex chars>")
    return candidate


@dataclass
class APIKeyRegistry:
    records: Tuple[APIKeyRecord, ...]
    records_by_id: Dict[str, APIKeyRecord]

    @classmethod
    def from_settings(cls, api_keys: Sequence[Dict[str, Any]]) -> "APIKeyRegistry":
        records: list[APIKeyRecord] = []
        records_by_id: Dict[str, APIKeyRecord] = {}
        seen_secrets: set[str] = set()

        for index, key_info in enumerate(api_keys):
            if not isinstance(key_info, dict):
                raise ValueError(f"API key at index {index} must be a dictionary")

            identifier = key_info.get("id")
            if identifier is not None:
                if not isinstance(identifier, str) or not _API_KEY_ID_RE.fullmatch(identifier):
                    raise ValueError(f"API key at index {index} has invalid id '{identifier}'")
                if identifier in records_by_id:
                    raise ValueError(f"Duplicate API key id detected: {identifier}")

            plain_secret = key_info.get("key")
            hashed_secret = key_info.get("key_hash")
            if bool(plain_secret) == bool(hashed_secret):
                raise ValueError(
                    f"API key at index {index} must define exactly one of 'key' or 'key_hash'"
                )

            if plain_secret:
                if not isinstance(plain_secret, str):
                    raise ValueError(f"API key at index {index} has a non-string key value")
                secret_kind = "plaintext"
                secret_value = plain_secret
                secret_fingerprint = f"plaintext:{plain_secret}"
            else:
                if not isinstance(hashed_secret, str):
                    raise ValueError(f"API key at index {index} has a non-string key_hash value")
                secret_kind = "sha256"
                secret_value = _parse_hashed_secret(hashed_secret)
                secret_fingerprint = f"sha256:{secret_value}"

            if secret_fingerprint in seen_secrets:
                raise ValueError(f"Duplicate API key material detected at index {index}")
            seen_secrets.add(secret_fingerprint)

            max_ttl = key_info.get("max_ttl")
            if not isinstance(max_ttl, int) or max_ttl <= 0:
                raise ValueError(f"API key at index {index} must define a positive integer max_ttl")

            allow_remote_whitelist = bool(key_info.get("allow_remote_whitelist", False))
            name = str(key_info.get("name") or identifier or f"key-{index + 1}")
            cache_key = identifier or name or secret_fingerprint

            record = APIKeyRecord(
                identifier=identifier,
                name=name,
                max_ttl=max_ttl,
                allow_remote_whitelist=allow_remote_whitelist,
                secret_kind=secret_kind,
                secret_value=secret_value,
                cache_key=cache_key,
            )
            records.append(record)
            if identifier is not None:
                records_by_id[identifier] = record

        return cls(records=tuple(records), records_by_id=records_by_id)

    def _dummy_compare(self, candidate_key: str) -> None:
        if not self.records:
            return
        self.records[0].verify(candidate_key)

    def resolve(self, candidate_key: str, key_id: Optional[str] = None) -> Optional[APIKeyRecord]:
        if not candidate_key:
            return None

        if key_id:
            record = self.records_by_id.get(key_id)
            if record is None:
                self._dummy_compare(candidate_key)
                return None
            return record if record.verify(candidate_key) else None

        matched_record: Optional[APIKeyRecord] = None
        for record in self.records:
            if record.verify(candidate_key):
                matched_record = record
        return matched_record


@dataclass
class SlidingWindowRateLimiter:
    window_seconds: int
    successful_requests: int
    failed_requests: int
    _events: Dict[Tuple[str, str], Deque[int]] = field(default_factory=lambda: defaultdict(deque))
    _lock: threading.RLock = field(default_factory=threading.RLock)

    @classmethod
    def from_settings(cls, security_settings: Dict[str, Any]) -> "SlidingWindowRateLimiter":
        config = security_settings.get("knock_rate_limit", {}) or {}
        window_seconds = int(config.get("window_seconds", 60))
        successful_requests = int(config.get("successful_requests", 20))
        failed_requests = int(config.get("failed_requests", 30))
        if window_seconds <= 0:
            raise ValueError("security.knock_rate_limit.window_seconds must be positive")
        if successful_requests < 0 or failed_requests < 0:
            raise ValueError("security.knock_rate_limit limits must be zero or greater")
        return cls(
            window_seconds=window_seconds,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
        )

    def allow(self, actor: str, outcome: str, now: Optional[int] = None) -> bool:
        limit = self.successful_requests if outcome == "success" else self.failed_requests
        if limit == 0:
            return True

        timestamp = int(time.time()) if now is None else now
        cutoff = timestamp - self.window_seconds
        bucket_key = (outcome, actor)
        with self._lock:
            bucket = self._events[bucket_key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(timestamp)
            return True

    def can_allow(self, actor: str, outcome: str, now: Optional[int] = None) -> bool:
        limit = self.successful_requests if outcome == "success" else self.failed_requests
        if limit == 0:
            return True

        timestamp = int(time.time()) if now is None else now
        cutoff = timestamp - self.window_seconds
        bucket_key = (outcome, actor)
        with self._lock:
            bucket = self._events[bucket_key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            return len(bucket) < limit


@dataclass
class ReplayGuard:
    enabled: bool
    max_age_seconds: int
    _entries: Dict[Tuple[str, str], int] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    @classmethod
    def from_settings(cls, security_settings: Dict[str, Any]) -> "ReplayGuard":
        config = security_settings.get("replay_protection", {}) or {}
        enabled = bool(config.get("enabled", False))
        max_age_seconds = int(config.get("max_age_seconds", 300))
        if max_age_seconds <= 0:
            raise ValueError("security.replay_protection.max_age_seconds must be positive")
        return cls(enabled=enabled, max_age_seconds=max_age_seconds)

    def validate(
        self,
        actor: str,
        nonce: Optional[str],
        timestamp: Optional[str],
        now: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        if not self.enabled:
            return True, None

        if not nonce or not timestamp:
            return False, "Missing replay protection headers."

        if not _NONCE_RE.fullmatch(nonce):
            return False, "Invalid replay protection headers."

        try:
            timestamp_int = int(timestamp)
        except (TypeError, ValueError):
            return False, "Invalid replay protection headers."

        current_time = int(time.time()) if now is None else now
        if abs(current_time - timestamp_int) > self.max_age_seconds:
            return False, "Replay protection timestamp expired."

        key = (actor, nonce)
        cutoff = current_time - self.max_age_seconds
        with self._lock:
            expired_keys = [entry for entry, seen_at in self._entries.items() if seen_at <= cutoff]
            for entry in expired_keys:
                self._entries.pop(entry, None)

            if key in self._entries:
                return False, "Replay detected."

            self._entries[key] = timestamp_int
            return True, None


@dataclass
class RuntimeState:
    trusted_proxies: ParsedNetworkSet
    always_allowed_ips: ParsedNetworkSet
    path_exclusions: PathExclusions
    api_keys: APIKeyRegistry
    whitelist: WhitelistStore
    rate_limiter: SlidingWindowRateLimiter
    replay_guard: ReplayGuard
    cleanup_interval_seconds: int
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _cleanup_thread: Optional[threading.Thread] = field(default=None, init=False)

    def start(self) -> None:
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return

        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="knocker-whitelist-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1)
        self._cleanup_thread = None

    def _cleanup_loop(self) -> None:
        while not self._stop_event.wait(self.cleanup_interval_seconds):
            try:
                self.whitelist.compact_expired()
            except Exception:
                logging.getLogger(__name__).exception("Whitelist cleanup task failed")

    def is_authorized_ip(self, client_ip: str) -> bool:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False

        if self.always_allowed_ips.contains(address):
            return True
        return self.whitelist.contains(address, int(time.time()))


def _validate_firewalld_config(settings: Dict[str, Any]) -> None:
    firewalld_settings = settings.get("firewalld", {}) or {}
    if not firewalld_settings.get("enabled", False):
        return

    zone_name = firewalld_settings.get("zone_name", "knocker")
    if not isinstance(zone_name, str) or not _ZONE_NAME_RE.fullmatch(zone_name):
        raise ValueError(
            "firewalld.zone_name must only contain letters, numbers, dots, underscores, colons, and hyphens"
        )

    monitored_ports = firewalld_settings.get("monitored_ports", []) or []
    if not isinstance(monitored_ports, list):
        raise ValueError("firewalld.monitored_ports must be a list")

    for index, port_config in enumerate(monitored_ports):
        if not isinstance(port_config, dict):
            raise ValueError(f"firewalld.monitored_ports[{index}] must be a dictionary")
        port = port_config.get("port")
        protocol = port_config.get("protocol", "tcp")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError(f"firewalld.monitored_ports[{index}].port must be an integer between 1 and 65535")
        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"firewalld.monitored_ports[{index}].protocol must be 'tcp' or 'udp'")

    monitored_ips = firewalld_settings.get("monitored_ips", []) or []
    if not isinstance(monitored_ips, list):
        raise ValueError("firewalld.monitored_ips must be a list")
    for monitored_ip in monitored_ips:
        if not isinstance(monitored_ip, str):
            raise ValueError("firewalld.monitored_ips entries must be strings")
        if "/" not in monitored_ip:
            raise ValueError(
                f"firewalld.monitored_ips entry '{monitored_ip}' must include an explicit CIDR mask"
            )
        _canonical_network(monitored_ip)


def ensure_runtime_state(settings: Dict[str, Any]) -> RuntimeState:
    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    if isinstance(runtime_state, RuntimeState):
        return runtime_state

    server_settings = settings.get("server", {}) or {}
    security_settings = settings.get("security", {}) or {}
    whitelist_settings = settings.get("whitelist", {}) or {}

    trusted_proxies = ParsedNetworkSet.from_entries(server_settings.get("trusted_proxies", []) or [], "trusted_proxies")
    always_allowed = ParsedNetworkSet.from_entries(
        security_settings.get("always_allowed_ips", []) or [],
        "always_allowed_ips",
    )
    path_exclusions = PathExclusions.from_settings(security_settings)

    api_keys_config = settings.get("api_keys", []) or []
    if not api_keys_config:
        raise ValueError("Configuration must contain at least one API key")
    api_keys = APIKeyRegistry.from_settings(api_keys_config)

    _validate_firewalld_config(settings)

    storage_path = get_whitelist_storage_path(settings)
    max_entries = int(security_settings.get("max_whitelist_entries", 10000))
    if max_entries <= 0:
        raise ValueError("security.max_whitelist_entries must be positive")

    cleanup_interval_seconds = int(whitelist_settings.get("cleanup_interval_seconds", 60))
    if cleanup_interval_seconds <= 0:
        raise ValueError("whitelist.cleanup_interval_seconds must be positive")

    runtime_state = RuntimeState(
        trusted_proxies=trusted_proxies,
        always_allowed_ips=always_allowed,
        path_exclusions=path_exclusions,
        api_keys=api_keys,
        whitelist=WhitelistStore(storage_path=storage_path, max_entries=max_entries),
        rate_limiter=SlidingWindowRateLimiter.from_settings(security_settings),
        replay_guard=ReplayGuard.from_settings(security_settings),
        cleanup_interval_seconds=cleanup_interval_seconds,
    )

    settings[_RUNTIME_STATE_KEY] = runtime_state

    if any(record.secret_kind == "plaintext" for record in api_keys.records):
        logging.getLogger(__name__).warning(
            "Plaintext API keys are deprecated. Prefer api_keys[].key_hash with X-Key-Id."
        )

    return runtime_state


def start_runtime_state(settings: Dict[str, Any]) -> RuntimeState:
    runtime_state = ensure_runtime_state(settings)
    runtime_state.start()
    return runtime_state


def stop_runtime_state(settings: Dict[str, Any]) -> None:
    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    if isinstance(runtime_state, RuntimeState):
        runtime_state.stop()


def get_api_key_record(api_key: str, settings: Dict[str, Any], key_id: Optional[str] = None) -> Optional[APIKeyRecord]:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.api_keys.resolve(api_key, key_id)


def is_valid_api_key(api_key: str, settings: Dict[str, Any], key_id: Optional[str] = None) -> bool:
    try:
        return get_api_key_record(api_key, settings, key_id) is not None
    except ValueError:
        return False


def can_whitelist_remote(api_key: str, settings: Dict[str, Any], key_id: Optional[str] = None) -> bool:
    try:
        record = get_api_key_record(api_key, settings, key_id)
    except ValueError:
        return False
    return bool(record and record.allow_remote_whitelist)


def get_max_ttl_for_key(api_key: str, settings: Dict[str, Any], key_id: Optional[str] = None) -> int:
    try:
        record = get_api_key_record(api_key, settings, key_id)
    except ValueError:
        return 0
    return record.max_ttl if record else 0


def get_api_key_name(api_key: str, settings: Dict[str, Any], key_id: Optional[str] = None) -> str:
    try:
        record = get_api_key_record(api_key, settings, key_id)
    except ValueError:
        return ""
    return record.name if record else ""


def is_ip_whitelisted(ip: str, whitelist: Dict[str, int], settings: Dict[str, Any]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    if isinstance(runtime_state, RuntimeState) and runtime_state.always_allowed_ips.contains(address):
        return True

    if not isinstance(runtime_state, RuntimeState):
        always_allowed = ParsedNetworkSet.from_entries(
            settings.get("security", {}).get("always_allowed_ips", []) or [],
            "always_allowed_ips",
        )
        if always_allowed.contains(address):
            return True

    return DynamicWhitelistIndex.from_serialized(whitelist).contains(address, int(time.time()))


def record_knock_attempt(settings: Dict[str, Any], actor: str, outcome: str) -> bool:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.rate_limiter.allow(actor, outcome, int(time.time()))


def can_record_knock_attempt(settings: Dict[str, Any], actor: str, outcome: str) -> bool:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.rate_limiter.can_allow(actor, outcome, int(time.time()))


def validate_replay_protection(
    settings: Dict[str, Any],
    actor: str,
    nonce: Optional[str],
    timestamp: Optional[str],
) -> Tuple[bool, Optional[str]]:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.replay_guard.validate(actor, nonce, timestamp, int(time.time()))


def add_ip_to_whitelist_with_firewalld(ip_or_cidr: str, expiry_time: int, settings: Dict[str, Any]) -> bool:
    try:
        from . import firewalld
    except ImportError:
        import firewalld

    firewalld_integration = firewalld.get_firewalld_integration()
    if firewalld_integration and firewalld_integration.is_enabled():
        if not firewalld_integration.add_whitelist_rule(ip_or_cidr, expiry_time):
            return False

    try:
        add_ip_to_whitelist(ip_or_cidr, expiry_time, settings)
        return True
    except Exception as exc:
        if firewalld_integration and firewalld_integration.is_enabled():
            try:
                firewalld_integration.remove_whitelist_rule(ip_or_cidr)
                logging.error(
                    "Rolled back firewalld rules for %s due to whitelist persistence failure: %s",
                    ip_or_cidr,
                    exc,
                )
            except Exception as rollback_error:
                logging.error(
                    "Failed to rollback firewalld rules for %s: %s",
                    ip_or_cidr,
                    rollback_error,
                )
        logging.error("Failed to persist whitelist entry for %s: %s", ip_or_cidr, exc)
        return False
