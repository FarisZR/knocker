"""Tests for the strict Firewalld helper message protocol."""

import json

import pytest

from src.firewalld_helper_protocol import (
    HELPER_PROTOCOL_VERSION,
    MAX_MESSAGE_BYTES,
    AddRuleRequest,
    HelperAllowlist,
    ProtocolError,
    RemoveRuleRequest,
    StatusRequest,
    canonical_address,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
    error_response,
    success_response,
    validate_request,
)


@pytest.fixture
def allowlist():
    return HelperAllowlist(
        zones=frozenset({"knocker"}),
        ports=frozenset({22, 443}),
        max_ttl_seconds=3600,
    )


def _add_payload(**overrides):
    payload = {
        "request_id": "req-1",
        "operation": "add",
        "zone": "knocker",
        "address": "203.0.113.7",
        "port": 22,
        "protocol": "tcp",
        "ttl_seconds": 60,
    }
    payload.update(overrides)
    return payload


def test_status_request_roundtrip(allowlist):
    request = decode_request(json.dumps({"request_id": "s1", "operation": "status"}), allowlist)
    assert isinstance(request, StatusRequest)
    assert request.version == HELPER_PROTOCOL_VERSION
    assert isinstance(decode_request(encode_request(request), allowlist), StatusRequest)


def test_add_request_roundtrip(allowlist):
    request = decode_request(json.dumps(_add_payload()), allowlist)
    assert isinstance(request, AddRuleRequest)
    assert request.port == 22
    assert isinstance(decode_request(encode_request(request), allowlist), AddRuleRequest)


def test_remove_request_roundtrip(allowlist):
    payload = {
        "request_id": "r1",
        "operation": "remove",
        "zone": "knocker",
        "address": "2001:db8::1",
        "port": 443,
        "protocol": "tcp",
    }
    request = decode_request(json.dumps(payload), allowlist)
    assert isinstance(request, RemoveRuleRequest)
    assert isinstance(decode_request(encode_request(request), allowlist), RemoveRuleRequest)


def test_unknown_field_is_rejected(allowlist):
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(command="firewall-cmd --reload")), allowlist)
    assert exc.value.code == "invalid_request"


def test_extra_ttl_on_remove_is_rejected(allowlist):
    payload = {
        "request_id": "r2",
        "operation": "remove",
        "zone": "knocker",
        "address": "203.0.113.7",
        "port": 22,
        "protocol": "tcp",
        "ttl_seconds": 5,
    }
    with pytest.raises(ProtocolError):
        decode_request(json.dumps(payload), allowlist)


def test_unsupported_version_is_rejected(allowlist):
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(version=999)), allowlist)
    assert exc.value.code == "unsupported_version"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("zone", "public", "forbidden"),
        ("port", 80, "forbidden"),
        ("protocol", "icmp", "forbidden"),
        ("ttl_seconds", 3601, "validation_failed"),
        ("ttl_seconds", 0, "validation_failed"),
    ],
)
def test_allowlist_is_enforced(allowlist, field, value, code):
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(**{field: value})), allowlist)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "address", ["", "not-an-ip", "203.0.113.7\n", "203.0.113.999", "1.2.3.4/33"]
)
def test_invalid_address_is_rejected(allowlist, address):
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(address=address)), allowlist)
    assert exc.value.code == "validation_failed"


def test_canonical_address_normalization():
    assert canonical_address("203.0.113.7/32") == "203.0.113.7"
    assert canonical_address("2001:db8::/32") == "2001:db8::/32"
    assert canonical_address("192.0.2.17/24") == "192.0.2.0/24"


def test_oversized_and_malformed_payloads_are_rejected(allowlist):
    with pytest.raises(ProtocolError) as exc:
        decode_request(b"x" * (MAX_MESSAGE_BYTES + 1), allowlist)
    assert exc.value.code == "invalid_request"
    with pytest.raises(ProtocolError) as exc:
        decode_request(b"\xff\xfe", allowlist)
    assert exc.value.code == "invalid_request"
    with pytest.raises(ProtocolError) as exc:
        decode_request(b"[1, 2]", allowlist)
    assert exc.value.code == "invalid_request"


def test_request_id_validation(allowlist):
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(request_id="")), allowlist)
    assert exc.value.code == "validation_failed"
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(request_id="x" * 65)), allowlist)
    assert exc.value.code == "validation_failed"


def test_response_roundtrip():
    ok = success_response("req-1", {"state": "ready"})
    assert decode_response(encode_response(ok)) == ok
    err = error_response("req-1", "helper_unavailable")
    assert decode_response(encode_response(err)) == err
    assert err.error == "helper_unavailable"
    assert err.ok is False


def test_response_version_validation():
    bad = {"request_id": "req-1", "ok": True, "version": 999}
    with pytest.raises(ProtocolError) as exc:
        decode_response(json.dumps(bad))
    assert exc.value.code == "unsupported_version"


def test_error_response_does_not_echo_raw_details():
    raw = "firewall-cmd failed: secret-token=abc at /host/dbus/path"
    response = error_response("req-1", "internal_error")
    encoded = encode_response(response)
    assert raw not in encoded.decode()
    assert b"secret-token" not in encoded


def test_allowlist_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        HelperAllowlist(zones=frozenset(), ports=frozenset({22}))
    with pytest.raises(ValueError):
        HelperAllowlist(zones=frozenset({"knocker"}), ports=frozenset({0}))
    with pytest.raises(ValueError):
        HelperAllowlist(
            zones=frozenset({"knocker"}), ports=frozenset({22}), protocols=frozenset({"icmp"})
        )
    with pytest.raises(ValueError):
        HelperAllowlist(zones=frozenset({"knocker"}), ports=frozenset({22}), max_ttl_seconds=0)


def test_validate_request_rejects_wrong_version(allowlist):
    request = AddRuleRequest(
        version=999,
        request_id="x",
        zone="knocker",
        address="203.0.113.7",
        port=22,
        protocol="tcp",
        ttl_seconds=60,
    )
    with pytest.raises(ProtocolError) as exc:
        validate_request(request, allowlist)
    assert exc.value.code == "unsupported_version"


def test_decode_request_canonicalizes_address(allowlist):
    request = decode_request(json.dumps(_add_payload(address="192.0.2.17/24")), allowlist)
    assert request.address == "192.0.2.0/24"
    assert b"192.0.2.0/24" in encode_request(request)
    assert b"192.0.2.17" not in encode_request(request)


def test_deeply_nested_json_is_rejected(allowlist):
    nested = "[" * 5000
    with pytest.raises(ProtocolError) as exc:
        decode_request(nested, allowlist)
    assert exc.value.code == "invalid_request"
    with pytest.raises(ProtocolError) as exc:
        decode_response(nested)
    assert exc.value.code == "invalid_request"


def test_schema_errors_are_classified_by_field(allowlist):
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(operation="bogus")), allowlist)
    assert exc.value.code == "invalid_request"
    with pytest.raises(ProtocolError) as exc:
        decode_request(json.dumps(_add_payload(version="1")), allowlist)
    assert exc.value.code == "unsupported_version"


def test_string_payload_byte_limit(allowlist):
    with pytest.raises(ProtocolError) as exc:
        decode_request("é" * 5000, allowlist)
    assert exc.value.code == "invalid_request"


def test_encode_rejects_oversized_messages():
    with pytest.raises(ProtocolError) as exc:
        encode_response(success_response("r", {"x": "a" * MAX_MESSAGE_BYTES}))
    assert exc.value.code == "invalid_request"
