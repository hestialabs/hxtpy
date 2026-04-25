import pytest

from hxtpy.core.canonical import build_canonical, parse_canonical, validate_canonical
from hxtpy.core.constants import PROTOCOL_VERSION


def test_build_canonical_success():
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
    expected = (
        f"{PROTOCOL_VERSION}|dev-123|client-456|msg-789|req-000|1|1713984000|abc|command|hash123"
    )
    assert canonical == expected


def test_build_canonical_missing_field():
    msg = {
        "version": PROTOCOL_VERSION,
        # device_id missing
        "client_id": "client-456",
        "message_id": "msg-789",
        "request_id": "req-000",
        "sequence_number": 1,
        "timestamp": 1713984000,
        "nonce": "abc",
        "message_type": "command",
        "payload_hash": "hash123",
    }
    with pytest.raises(ValueError, match="CANONICAL_ERROR: Missing mandatory field at index 1"):
        build_canonical(msg)


def test_parse_canonical():
    canonical = (
        f"{PROTOCOL_VERSION}|dev-123|client-456|msg-789|req-000|1|1713984000|abc|command|hash123"
    )
    parsed = parse_canonical(canonical)
    assert parsed["version"] == PROTOCOL_VERSION
    assert parsed["device_id"] == "dev-123"
    assert parsed["sequence_number"] == "1"


def test_validate_canonical():
    valid = (
        f"{PROTOCOL_VERSION}|dev-123|client-456|msg-789|req-000|1|1713984000|abc|command|hash123"
    )
    assert validate_canonical(valid) is True

    invalid = f"{PROTOCOL_VERSION}|dev-123"
    assert validate_canonical(invalid) is False


def test_crypto_engine():
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


def test_validation_pipeline():
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
    envelope["version"] = "HxTP/1.0"
    result = validate_message(envelope, secret_hex=secret)
    assert result.ok is False
    assert result.code == "VERSION_MISMATCH"
