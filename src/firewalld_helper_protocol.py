"""Strict, versioned messages for the optional privileged Firewalld helper.

This module only validates data. It never starts a process, talks to D-Bus, or
issues firewall commands, so it can be shared by the unprivileged API and the
host-side helper without granting either side extra capabilities.

It is the first, self-contained step of #52: both components will be able to
exchange canonical operations once the helper transport is added.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Annotated, Final, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    TypeAdapter,
    ValidationError,
)

HELPER_PROTOCOL_VERSION: Final = 1
MAX_MESSAGE_BYTES: Final = 8192
MAX_ADDRESS_LENGTH: Final = 64
MAX_TTL_SECONDS: Final = 315360000

ErrorCode = Literal[
    "invalid_request",
    "unsupported_version",
    "forbidden",
    "validation_failed",
    "helper_unavailable",
    "internal_error",
]


class ProtocolError(ValueError):
    """A message was malformed, unsupported, or outside the configured allowlist."""

    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class HelperAllowlist:
    """Values the helper is permitted to act on, independent of the caller."""

    zones: frozenset[str]
    ports: frozenset[int]
    protocols: frozenset[str] = frozenset({"tcp", "udp"})
    max_ttl_seconds: int = MAX_TTL_SECONDS

    def __post_init__(self) -> None:
        if not self.zones or any(not zone or len(zone) > 64 for zone in self.zones):
            raise ValueError("helper allowlist requires non-empty zone names")
        if not self.ports or any(not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("helper allowlist requires ports between 1 and 65535")
        if not self.protocols or not self.protocols <= {"tcp", "udp"}:
            raise ValueError("helper allowlist supports only tcp and udp")
        if not 1 <= self.max_ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("helper allowlist max_ttl_seconds is out of range")


class _RequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: StrictInt = HELPER_PROTOCOL_VERSION
    request_id: StrictStr


class StatusRequest(_RequestBase):
    operation: Literal["status"] = "status"


class AddRuleRequest(_RequestBase):
    operation: Literal["add"] = "add"
    zone: StrictStr
    address: StrictStr
    port: StrictInt
    protocol: StrictStr
    ttl_seconds: StrictInt


class RemoveRuleRequest(_RequestBase):
    operation: Literal["remove"] = "remove"
    zone: StrictStr
    address: StrictStr
    port: StrictInt
    protocol: StrictStr


HelperRequest = Annotated[
    Union[StatusRequest, AddRuleRequest, RemoveRuleRequest], Field(discriminator="operation")
]


class HelperResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: StrictInt = HELPER_PROTOCOL_VERSION
    request_id: StrictStr
    ok: StrictBool
    error: ErrorCode | None = None
    data: dict[StrictStr, StrictStr] | None = None


_REQUEST_ADAPTER: TypeAdapter[HelperRequest] = TypeAdapter(HelperRequest)


def canonical_address(value: str) -> str:
    """Normalize an IP or CIDR to its canonical form, rejecting ambiguous input."""
    if not isinstance(value, str) or not value or len(value) > MAX_ADDRESS_LENGTH:
        raise ProtocolError("validation_failed", "invalid address")
    if value != value.strip() or any(char.isspace() for char in value):
        raise ProtocolError("validation_failed", "invalid address")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ProtocolError("validation_failed", "invalid address") from exc
    if network.num_addresses == 1:
        return str(network.network_address)
    return str(network)


def validate_request(request: HelperRequest, allowlist: HelperAllowlist) -> None:
    """Enforce the helper's independent allowlist on a parsed request."""
    if request.version != HELPER_PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "unsupported protocol version")
    if not request.request_id or len(request.request_id) > 64:
        raise ProtocolError("validation_failed", "invalid request id")
    if isinstance(request, StatusRequest):
        return
    if request.zone not in allowlist.zones:
        raise ProtocolError("forbidden", "zone is not allowed")
    if request.port not in allowlist.ports:
        raise ProtocolError("forbidden", "port is not allowed")
    if request.protocol not in allowlist.protocols:
        raise ProtocolError("forbidden", "protocol is not allowed")
    canonical_address(request.address)
    if (
        isinstance(request, AddRuleRequest)
        and not 1 <= request.ttl_seconds <= allowlist.max_ttl_seconds
    ):
        raise ProtocolError("validation_failed", "ttl_seconds is out of range")


def decode_request(payload: bytes | str, allowlist: HelperAllowlist) -> HelperRequest:
    """Parse and validate a bounded request payload."""
    text = _decode_text(payload, "request")
    try:
        raw: object = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError("invalid_request", "request is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ProtocolError("invalid_request", "request must be an object")
    try:
        request = _REQUEST_ADAPTER.validate_python(raw)
    except ValidationError as exc:
        raise ProtocolError(_schema_error_code(exc), "request does not match the protocol") from exc
    validate_request(request, allowlist)
    if not isinstance(request, StatusRequest):
        request.address = canonical_address(request.address)
    return request


def encode_request(request: HelperRequest) -> bytes:
    """Serialize a request in canonical form."""
    return _encode(request.model_dump())


def encode_response(response: HelperResponse) -> bytes:
    """Serialize a response without any caller-supplied error details."""
    return _encode(response.model_dump())


def decode_response(payload: bytes | str) -> HelperResponse:
    """Parse a bounded response payload."""
    text = _decode_text(payload, "response")
    try:
        raw: object = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError("invalid_request", "response is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ProtocolError("invalid_request", "response must be an object")
    try:
        response = HelperResponse.model_validate(raw)
    except ValidationError as exc:
        raise ProtocolError("invalid_request", "response does not match the protocol") from exc
    if response.version != HELPER_PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "unsupported protocol version")
    return response


def error_response(request_id: str, code: ErrorCode) -> HelperResponse:
    """Build a response that never echoes raw exception text."""
    return HelperResponse(request_id=request_id, ok=False, error=code)


def success_response(request_id: str, data: dict[str, str] | None = None) -> HelperResponse:
    """Build a successful response."""
    return HelperResponse(request_id=request_id, ok=True, data=data)


def _decode_text(payload: bytes | str, label: str) -> str:
    if isinstance(payload, bytes):
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ProtocolError("invalid_request", f"{label} is too large")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("invalid_request", f"{label} is not valid UTF-8") from exc
    else:
        text = payload
    try:
        byte_length = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ProtocolError("invalid_request", f"{label} is not valid UTF-8") from exc
    if byte_length > MAX_MESSAGE_BYTES:
        raise ProtocolError("invalid_request", f"{label} is too large")
    return text


def _schema_error_code(exc: ValidationError) -> ErrorCode:
    if any("version" in error.get("loc", ()) for error in exc.errors()):
        return "unsupported_version"
    return "invalid_request"


def _encode(value: dict[str, object]) -> bytes:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ProtocolError("invalid_request", "message is too large")
    return encoded
