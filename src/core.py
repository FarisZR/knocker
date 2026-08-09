from __future__ import annotations

import fcntl
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, Optional, Sequence, Tuple, Union, cast
from urllib.parse import unquote, urlsplit

try:
    from .config import (
        APIKeySettings,
        KnockRateLimitSettings,
        SecuritySettings,
        Settings,
        SettingsLike,
        validate_settings,
        validate_whitelist_storage_path,
    )
except ImportError:  # pragma: no cover - fallback for direct module execution
    from config import (
        APIKeySettings,
        KnockRateLimitSettings,
        SecuritySettings,
        Settings,
        SettingsLike,
        validate_settings,
        validate_whitelist_storage_path,
    )

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_runtime_state_lock = threading.Lock()
_RUNTIME_STATE_KEY = "_knocker_runtime_state"


def get_whitelist_storage_path(settings: SettingsLike) -> Path:
    if isinstance(settings, Settings):
        return Path(settings.whitelist.storage_path)

    whitelist_settings = settings.get("whitelist", {}) or {}
    if not isinstance(whitelist_settings, dict):
        raise ValueError("whitelist configuration must be a mapping")

    return validate_whitelist_storage_path(whitelist_settings.get("storage_path", "whitelist.json"))


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


def _parse_entry_list(
    entries: Iterable[str], label: str
) -> Tuple[Tuple[IPAddress, ...], Tuple[IPNetwork, ...]]:
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
            return any(
                expiry_time > now and address in network
                for network, expiry_time in self.networks_v4.items()
            )

        expiry = self.exact_v6.get(address)
        if expiry and expiry > now:
            return True
        return any(
            expiry_time > now and address in network
            for network, expiry_time in self.networks_v6.items()
        )

    def to_serialized(
        self, now: Optional[int] = None, include_expired: bool = True
    ) -> Dict[str, int]:
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
                raise ValueError(
                    f"Whitelist storage path is not readable and writable: {self.storage_path}"
                )
        elif not os.access(self.storage_path.parent, os.R_OK | os.W_OK | os.X_OK):
            raise ValueError(
                f"Whitelist storage directory is not accessible: {self.storage_path.parent}"
            )
        self.reload_from_disk()

    def _reload_from_disk_locked(self) -> None:
        raw = _read_whitelist_file(self.storage_path)
        normalized, changed = _normalize_serialized_whitelist(raw, drop_expired=True)
        self._index = DynamicWhitelistIndex.from_serialized(normalized)
        self._pending_compaction = changed

    def reload_from_disk(self) -> None:
        with self._lock:
            self._reload_from_disk_locked()

    def contains(self, address: IPAddress, now: Optional[int] = None) -> bool:
        with self._lock:
            return self._index.contains(address, now)

    def add(self, ip_or_cidr: str, expiry_time: int) -> None:
        if not is_valid_ip_or_cidr(ip_or_cidr):
            raise ValueError(f"Invalid IP address or CIDR notation: {ip_or_cidr}")

        now = int(time.time())
        if expiry_time <= now:
            raise ValueError(
                f"Expiry time {expiry_time} is not in the future (current time: {now})"
            )

        canonical, _ = _canonical_network(ip_or_cidr)
        with self._lock:
            with _interprocess_whitelist_lock(self.storage_path):
                persisted = _read_whitelist_file(self.storage_path)
                normalized, _ = _normalize_serialized_whitelist(
                    persisted, drop_expired=True, now=now
                )
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
                active, changed = _normalize_serialized_whitelist(
                    normalized, drop_expired=True, now=now
                )
                self._index = DynamicWhitelistIndex.from_serialized(active)
                self._pending_compaction = changed
        return normalized

    def compact_expired(self, now: Optional[int] = None) -> bool:
        cutoff = int(time.time()) if now is None else now
        with self._lock:
            before = self._index.to_serialized(include_expired=True)
            after = _limit_whitelist_entries(
                self._index.to_serialized(now=cutoff, include_expired=False), self.max_entries
            )
            if not self._pending_compaction and before == after:
                return False

            with _interprocess_whitelist_lock(self.storage_path):
                persisted = _read_whitelist_file(self.storage_path)
                active, changed = _normalize_serialized_whitelist(
                    persisted, drop_expired=True, now=cutoff
                )
                compacted = _limit_whitelist_entries(active, self.max_entries)
                wrote = changed or compacted != persisted
                if wrote:
                    _write_whitelist_file(self.storage_path, compacted)
            self._index = DynamicWhitelistIndex.from_serialized(compacted)
            self._pending_compaction = False
            return wrote

    def active_snapshot(self) -> Dict[str, int]:
        with self._lock:
            return self._index.to_serialized(now=int(time.time()), include_expired=False)


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
    def from_config(cls, security_settings: SecuritySettings) -> "PathExclusions":
        global_paths = tuple(normalize_path(path) for path in security_settings.excluded_paths)
        host_paths: Dict[str, Tuple[str, ...]] = {}
        for host, paths in security_settings.excluded_paths_by_host.items():
            normalized_host = normalize_host(host)
            if not normalized_host:
                raise ValueError(f"Invalid excluded_paths_by_host host '{host}'")
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


def is_path_excluded(path: str, settings: SettingsLike, host: Optional[str] = None) -> bool:
    runtime_state = (
        settings._runtime_state
        if isinstance(settings, Settings)
        else settings.get(_RUNTIME_STATE_KEY)
    )
    if isinstance(runtime_state, RuntimeState):
        return runtime_state.path_exclusions.matches(host, path)

    security_settings = (
        settings.security
        if isinstance(settings, Settings)
        else SecuritySettings.model_validate(settings.get("security", {}) or {})
    )
    path_exclusions = PathExclusions.from_config(security_settings)
    return path_exclusions.matches(host, path)


def is_trusted_proxy(
    client_ip: str, trusted_proxies: Union[Sequence[str], ParsedNetworkSet]
) -> bool:
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
    if not trusted_proxy:
        return direct_ip, False

    # A configured proxy is never a valid fallback client identity. If it does
    # not provide a complete forwarded chain, fail closed instead of treating
    # the proxy itself as the client.
    if not forwarded_for:
        return None, True

    raw_entries = [entry.strip() for entry in forwarded_for.split(",")]
    if not raw_entries or any(not entry for entry in raw_entries) or len(raw_entries) > 20:
        return None, True
    entries = raw_entries

    parsed_entries: list[IPAddress] = []
    for entry in entries:
        try:
            parsed_entries.append(ipaddress.ip_address(entry))
        except ValueError:
            return None, True

    for candidate in reversed(parsed_entries):
        if trusted_proxies.contains(candidate):
            continue
        return str(candidate), True

    # A chain containing only trusted hops still does not identify the client.
    # Never turn a proxy address into an authorization identity.
    return None, True


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
    name: str
    max_ttl: int
    allow_remote_whitelist: bool
    key: str

    def verify(self, presented_key: str) -> bool:
        if not isinstance(presented_key, str):
            return False
        return hmac.compare_digest(self.key, presented_key)


@dataclass
class APIKeyRegistry:
    records: Tuple[APIKeyRecord, ...]

    @classmethod
    def from_config(cls, api_keys: Sequence[APIKeySettings]) -> "APIKeyRegistry":
        records = tuple(
            APIKeyRecord(
                name=record.name or f"key-{index + 1}",
                max_ttl=record.max_ttl,
                allow_remote_whitelist=record.allow_remote_whitelist,
                key=record.key,
            )
            for index, record in enumerate(api_keys)
        )
        return cls(records=records)

    def resolve(self, candidate_key: Optional[str]) -> Optional[APIKeyRecord]:
        if not candidate_key:
            return None

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
    _events: Dict[Tuple[str, str], Deque[Tuple[int, int]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _token_counter: int = field(default=0, init=False)
    _last_global_prune: int = field(default=0, init=False)

    @classmethod
    def from_config(cls, config: KnockRateLimitSettings) -> "SlidingWindowRateLimiter":
        return cls(
            window_seconds=config.window_seconds,
            successful_requests=config.successful_requests,
            failed_requests=config.failed_requests,
        )

    def _prune_bucket(self, bucket: Deque[Tuple[int, int]], cutoff: int) -> None:
        while bucket and bucket[0][0] <= cutoff:
            bucket.popleft()

    def _prune_all_buckets(self, cutoff: int, now: int) -> None:
        if self._last_global_prune and now - self._last_global_prune < self.window_seconds:
            return

        empty_keys: list[Tuple[str, str]] = []
        for bucket_key, bucket in self._events.items():
            self._prune_bucket(bucket, cutoff)
            if not bucket:
                empty_keys.append(bucket_key)

        for bucket_key in empty_keys:
            self._events.pop(bucket_key, None)

        self._last_global_prune = now

    def reserve(
        self, actor: str, outcome: str, now: Optional[int] = None
    ) -> Optional[Tuple[int, int]]:
        limit = self.successful_requests if outcome == "success" else self.failed_requests
        timestamp = int(time.time()) if now is None else now
        if limit == 0:
            return (timestamp, 0)

        cutoff = timestamp - self.window_seconds
        bucket_key = (outcome, actor)
        with self._lock:
            self._prune_all_buckets(cutoff, timestamp)
            bucket = self._events[bucket_key]
            self._prune_bucket(bucket, cutoff)
            if len(bucket) >= limit:
                if not bucket:
                    self._events.pop(bucket_key, None)
                return None
            self._token_counter += 1
            reservation = (timestamp, self._token_counter)
            bucket.append(reservation)
            return reservation

    def release(self, actor: str, outcome: str, reservation: Tuple[int, int]) -> None:
        if reservation[1] == 0:
            return

        bucket_key = (outcome, actor)
        with self._lock:
            bucket = self._events.get(bucket_key)
            if not bucket:
                return
            try:
                bucket.remove(reservation)
            except ValueError:
                return
            if not bucket:
                self._events.pop(bucket_key, None)

    def allow(self, actor: str, outcome: str, now: Optional[int] = None) -> bool:
        reservation = self.reserve(actor, outcome, now)
        if reservation is None:
            return False
        return True

    def can_allow(self, actor: str, outcome: str, now: Optional[int] = None) -> bool:
        limit = self.successful_requests if outcome == "success" else self.failed_requests
        if limit == 0:
            return True

        timestamp = int(time.time()) if now is None else now
        cutoff = timestamp - self.window_seconds
        bucket_key = (outcome, actor)
        with self._lock:
            self._prune_all_buckets(cutoff, timestamp)
            bucket = self._events[bucket_key]
            self._prune_bucket(bucket, cutoff)
            if not bucket:
                self._events.pop(bucket_key, None)
            return len(bucket) < limit


@dataclass
class RuntimeState:
    trusted_proxies: ParsedNetworkSet
    always_allowed_ips: ParsedNetworkSet
    path_exclusions: PathExclusions
    api_keys: APIKeyRegistry
    whitelist: WhitelistStore
    rate_limiter: SlidingWindowRateLimiter
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


def _cached_runtime_state(settings: SettingsLike) -> Optional[RuntimeState]:
    if isinstance(settings, Settings):
        return settings._runtime_state
    runtime_state = settings.get(_RUNTIME_STATE_KEY)
    return runtime_state if isinstance(runtime_state, RuntimeState) else None


def _cache_runtime_state(settings: SettingsLike, runtime_state: RuntimeState) -> None:
    if isinstance(settings, Settings):
        settings._runtime_state = runtime_state
    else:
        cast(dict[str, Any], settings)[_RUNTIME_STATE_KEY] = runtime_state


def ensure_runtime_state(settings: SettingsLike) -> RuntimeState:
    runtime_state = _cached_runtime_state(settings)
    if runtime_state is not None:
        return runtime_state

    validated = validate_settings(settings)
    runtime_state = validated._runtime_state
    if isinstance(runtime_state, RuntimeState):
        _cache_runtime_state(settings, runtime_state)
        return runtime_state

    with _runtime_state_lock:
        runtime_state = _cached_runtime_state(settings)
        if runtime_state is not None:
            return runtime_state

        trusted_proxies = ParsedNetworkSet.from_entries(
            validated.server.trusted_proxies, "trusted_proxies"
        )
        always_allowed = ParsedNetworkSet.from_entries(
            validated.security.always_allowed_ips, "always_allowed_ips"
        )
        api_keys = APIKeyRegistry.from_config(validated.api_keys)
        runtime_state = RuntimeState(
            trusted_proxies=trusted_proxies,
            always_allowed_ips=always_allowed,
            path_exclusions=PathExclusions.from_config(validated.security),
            api_keys=api_keys,
            whitelist=WhitelistStore(
                storage_path=Path(validated.whitelist.storage_path),
                max_entries=validated.security.max_whitelist_entries,
            ),
            rate_limiter=SlidingWindowRateLimiter.from_config(validated.security.knock_rate_limit),
            cleanup_interval_seconds=validated.whitelist.cleanup_interval_seconds,
        )
        _cache_runtime_state(settings, runtime_state)
        if validated is not settings:
            validated._runtime_state = runtime_state
        return runtime_state


def start_runtime_state(settings: SettingsLike) -> RuntimeState:
    runtime_state = ensure_runtime_state(settings)
    runtime_state.start()
    return runtime_state


def stop_runtime_state(settings: SettingsLike) -> None:
    runtime_state = _cached_runtime_state(settings)
    if runtime_state is not None:
        runtime_state.stop()


def get_api_key_record(api_key: Optional[str], settings: SettingsLike) -> Optional[APIKeyRecord]:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.api_keys.resolve(api_key)


def is_valid_api_key(api_key: Optional[str], settings: SettingsLike) -> bool:
    return get_api_key_record(api_key, settings) is not None


def can_whitelist_remote(api_key: Optional[str], settings: SettingsLike) -> bool:
    record = get_api_key_record(api_key, settings)
    return bool(record and record.allow_remote_whitelist)


def get_max_ttl_for_key(api_key: Optional[str], settings: SettingsLike) -> int:
    record = get_api_key_record(api_key, settings)
    return record.max_ttl if record else 0


def get_api_key_name(api_key: Optional[str], settings: SettingsLike) -> str:
    record = get_api_key_record(api_key, settings)
    return record.name if record else ""


def record_knock_attempt(settings: SettingsLike, actor: str, outcome: str) -> bool:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.rate_limiter.allow(actor, outcome, int(time.time()))


def reserve_knock_attempt(
    settings: SettingsLike, actor: str, outcome: str
) -> Optional[Tuple[int, int]]:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.rate_limiter.reserve(actor, outcome, int(time.time()))


def release_knock_attempt(
    settings: SettingsLike, actor: str, outcome: str, reservation: Tuple[int, int]
) -> None:
    runtime_state = ensure_runtime_state(settings)
    runtime_state.rate_limiter.release(actor, outcome, reservation)


def can_record_knock_attempt(settings: SettingsLike, actor: str, outcome: str) -> bool:
    runtime_state = ensure_runtime_state(settings)
    return runtime_state.rate_limiter.can_allow(actor, outcome, int(time.time()))


def add_ip_to_whitelist_with_firewalld(
    ip_or_cidr: str, expiry_time: int, settings: SettingsLike
) -> bool:
    try:
        from . import firewalld
    except ImportError:
        import firewalld

    runtime_state = ensure_runtime_state(settings)
    firewalld_integration = firewalld.get_firewalld_integration()
    if firewalld_integration and firewalld_integration.is_enabled():
        if not firewalld_integration.add_whitelist_rule(ip_or_cidr, expiry_time):
            return False

    try:
        runtime_state.whitelist.add(ip_or_cidr, expiry_time)
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
