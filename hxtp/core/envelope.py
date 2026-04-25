"""
HXTP Core — Signed Envelope Constructor.

Constructs fully signed HxTP message envelopes ready for transmission.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import json
import time
from typing import Any

from hxtp.core.constants import PROTOCOL_VERSION, SECRET_HEX_LENGTH
from hxtp.core.nonce import generate_nonce
from hxtp.core.signing import sign_message
from hxtp.crypto.engine import sha256_hex


def _generate_uuid4() -> str:
    """
    Generate a UUID v4 string from random bytes.

    Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx

    Uses secrets module for cryptographic randomness.
    """
    import secrets

    raw = bytearray(secrets.token_bytes(16))

    # Set version (4) and variant (10xx) bits per RFC 4122
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80

    h = raw.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def build_envelope(
    *,
    secret_hex: str,
    device_id: str,
    tenant_id: str,
    message_type: str,
    params: dict[str, Any] | None = None,
    client_id: str | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    """
    Build a fully signed HxTP envelope ready for transmission.

    Steps:
      1. Generate message_id (UUID v4 via random bytes)
      2. Generate nonce (16 random bytes, hex-encoded)
      3. Compute payload_hash (SHA-256 of JSON.stringify(params))
      4. Build canonical string
      5. Compute HMAC-SHA256 signature
      6. Return complete envelope

    Args:
        secret_hex: 64-char hex-encoded shared secret.
        device_id: Device UUID.
        tenant_id: Tenant UUID.
        message_type: Message type string (e.g., "command", "heartbeat").
        params: Optional parameters payload dictionary.
        client_id: Optional client application identifier.
        sequence: Optional monotonic sequence number.

    Returns:
        Complete signed envelope dictionary.

    Raises:
        ValueError: If secret is not a valid 64-character hex string.
    """
    if not secret_hex or len(secret_hex) != SECRET_HEX_LENGTH:
        raise ValueError(
            f"Secret must be a {SECRET_HEX_LENGTH}-character hex string (32 bytes)."
        )

    message_id = _generate_uuid4()
    nonce = generate_nonce()
    timestamp = int(time.time() * 1000)

    # Use compact JSON separators — matches JSON.stringify() behavior
    params_json = json.dumps(params if params is not None else {}, separators=(",", ":"))
    payload_hash = sha256_hex(params_json)

    msg_fields: dict[str, Any] = {
        "version": PROTOCOL_VERSION,
        "message_type": message_type,
        "device_id": device_id,
        "client_id": client_id or "unknown-client",
        "message_id": message_id,
        "request_id": message_id,  # outbound commands/messages use RID=MID
        "sequence_number": sequence if sequence is not None else 0,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload_hash": payload_hash,
    }

    signature = sign_message(secret_hex, msg_fields)

    envelope: dict[str, Any] = {
        **msg_fields,
        "signature": signature,
        "params": params if params is not None else {},
    }

    return envelope
