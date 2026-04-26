"""
HXTP Core Protocol Engine — Constants.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

# ── Protocol Constants (Production Grade) ────────────────────────────────
PROTOCOL_VERSION: Final[str] = "HxTP/3.0"
CANONICAL_SEPARATOR: Final[str] = "|"
MAX_MESSAGE_AGE_SEC: Final[int] = 30
TIMESTAMP_SKEW_SEC: Final[int] = 5
NONCE_TTL_SEC: Final[int] = 60
MAX_PAYLOAD_BYTES: Final[int] = 16_384
HMAC_HEX_LENGTH: Final[int] = 64
SHA256_HEX_LENGTH: Final[int] = 64
MIN_NONCE_BYTES: Final[int] = 16
SECRET_BYTES: Final[int] = 32
SECRET_HEX_LENGTH: Final[int] = 64


# ── Message Types ───────────────────────────────────────────────────────


class MessageType:
    """HxTP message types. Matches backend Models.ts and embedded Types.h."""

    STATE: Final[str] = "state"
    COMMAND: Final[str] = "command"
    HEARTBEAT: Final[str] = "heartbeat"
    TELEMETRY: Final[str] = "telemetry"
    OTA: Final[str] = "ota"
    ACK: Final[str] = "ack"
    ERROR: Final[str] = "error"
    HELLO: Final[str] = "hello"

    ALL: Final[frozenset[str]] = frozenset(
        {STATE, COMMAND, HEARTBEAT, TELEMETRY, OTA, ACK, ERROR, HELLO}
    )


# ── MQTT Topic Channels ────────────────────────────────────────────────


class Channel:
    """MQTT topic channel segments. Matches backend Topics.ts and JS SDK."""

    STATE: Final[str] = "state"
    CMD: Final[str] = "cmd"
    CMD_ACK: Final[str] = "cmd_ack"
    HELLO: Final[str] = "hello"
    HEARTBEAT: Final[str] = "heartbeat"
    OTA: Final[str] = "ota"
    OTA_STATUS: Final[str] = "ota_status"
    TELEMETRY: Final[str] = "telemetry"


# ── Validation Steps ───────────────────────────────────────────────────


class ValidationStep:
    """Validation pipeline step identifiers."""

    VERSION: Final[str] = "VERSION_CHECK"
    TIMESTAMP: Final[str] = "TIMESTAMP_CHECK"
    PAYLOAD_SIZE: Final[str] = "PAYLOAD_SIZE_CHECK"
    NONCE: Final[str] = "NONCE_CHECK"
    PAYLOAD_HASH: Final[str] = "PAYLOAD_HASH_CHECK"
    SEQUENCE: Final[str] = "SEQUENCE_CHECK"
    SIGNATURE: Final[str] = "SIGNATURE_CHECK"


# ── Protocol Errors ────────────────────────────────────────────────────


class ProtocolError:
    """Protocol error codes. Matches backend Models.ts and JS SDK."""

    VERSION_MISMATCH: Final[str] = "VERSION_MISMATCH"
    TIMESTAMP_EXPIRED: Final[str] = "TIMESTAMP_EXPIRED"
    TIMESTAMP_FUTURE: Final[str] = "TIMESTAMP_FUTURE"
    PAYLOAD_TOO_LARGE: Final[str] = "PAYLOAD_TOO_LARGE"
    NONCE_MISSING: Final[str] = "NONCE_MISSING"
    NONCE_REUSED: Final[str] = "NONCE_REUSED"
    HASH_MISMATCH: Final[str] = "HASH_MISMATCH"
    SEQUENCE_VIOLATION: Final[str] = "SEQUENCE_VIOLATION"
    SIGNATURE_MISSING: Final[str] = "SIGNATURE_MISSING"
    SIGNATURE_INVALID: Final[str] = "SIGNATURE_INVALID"
    SECRET_MISSING: Final[str] = "SECRET_MISSING"
