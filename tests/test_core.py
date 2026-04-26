import pytest
import json
from hxtpy.core.canonical import canonical_json, build_canonical, parse_canonical, validate_canonical
from hxtpy.core.constants import PROTOCOL_VERSION

def test_canonical_json_determinism() -> None:
    msg = {"z": 1, "a": 2, "protocol": "hxtp/3.0"}
    # Keys must be sorted: "a" then "protocol" then "z"
    # Numbers must be stringified
    res = canonical_json(msg)
    expected = '{"a":"2","protocol":"hxtp/3.0","z":"1"}'
    assert res == expected

def test_canonical_json_number_formatting() -> None:
    assert canonical_json({"v": 123}) == '{"protocol":"hxtp/3.0","v":"123"}'
    # Match TS toFixed(20) precision for 1.2
    assert canonical_json({"v": 1.2}) == '{"protocol":"hxtp/3.0","v":"1.19999999999999995559"}'
    assert canonical_json({"v": 1.0}) == '{"protocol":"hxtp/3.0","v":"1"}'

def test_build_canonical_success() -> None:
    msg = {
        "version": PROTOCOL_VERSION,
        "device_id": "dev-123",
        "client_id": "client-456",
        "message_id": "msg-789",
        "request_id": "req-000",
        "sequence_number": 1,
        "timestamp": 1713984000,
        "nonce": "abc",
        "message_type": "command",
        "payload_hash": "hash123",
    }
    canonical = build_canonical(msg)
    parsed = json.loads(canonical)
    assert parsed["protocol"] == "hxtp/3.0"
    assert parsed["device_id"] == "dev-123"
    assert parsed["sequence_number"] == "1"

def test_parse_canonical() -> None:
    data = {"hello": "world"}
    canonical = canonical_json(data)
    parsed = parse_canonical(canonical)
    assert parsed["hello"] == "world"
    assert parsed["protocol"] == "hxtp/3.0"

def test_validate_canonical() -> None:
    valid = canonical_json({"a": 1})
    assert validate_canonical(valid) is True
    assert validate_canonical("invalid json") is False

def test_crypto_engine() -> None:
    from hxtpy.crypto.engine import (
        constant_time_equal,
        generate_nonce,
        sha256_hex,
        sign_hmac_sha256,
    )

    secret = b"a" * 32
    data = "hello"

    # Sign
    signature = sign_hmac_sha256(secret, data)
    assert len(signature) == 64

    # Verify same
    assert constant_time_equal(signature, sign_hmac_sha256(secret, data))

    # Hash
    h = sha256_hex(data)
    assert len(h) == 64
    assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    # Nonce
    n = generate_nonce(16)
    assert len(n) == 32

def test_validation_pipeline() -> None:
    from hxtpy.core.envelope import build_envelope
    from hxtpy.validation.pipeline import validate_message

    secret = "a" * 64

    # build_envelope is a factory that takes individual fields
    envelope = build_envelope(
        secret_hex=secret,
        device_id="dev-123",
        tenant_id="tenant-456",
        message_type="command",
        params={"action": "test"},
        client_id="client-789",
        sequence=1,
    )

    # Validate the resulting envelope
    result = validate_message(envelope, secret_hex=secret)
    assert result.ok is True

    # Test version mismatch by tampering with the envelope
    envelope["version"] = "HxTP/0.1"
    result = validate_message(envelope, secret_hex=secret)
    assert result.ok is False
    assert result.code == "VERSION_MISMATCH"
