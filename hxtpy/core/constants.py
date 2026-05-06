"""
HXTP Core — Protocol Constants.

Re-exported from core/__init__.py for direct import convenience.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from hxtpy.core import (
    CANONICAL_SEPARATOR,
    HMAC_HEX_LENGTH,
    LEGACY_PROTOCOL_VERSION,
    MAX_MESSAGE_AGE_SEC,
    MAX_PAYLOAD_BYTES,
    MIN_NONCE_BYTES,
    NONCE_TTL_SEC,
    PROTOCOL_VERSION,
    SECRET_BYTES,
    SECRET_HEX_LENGTH,
    SHA256_HEX_LENGTH,
    TIMESTAMP_SKEW_SEC,
    Channel,
    MessageType,
    ProtocolError,
    ValidationStep,
)

__all__ = [
    "PROTOCOL_VERSION",
    "LEGACY_PROTOCOL_VERSION",
    "CANONICAL_SEPARATOR",
    "MAX_MESSAGE_AGE_SEC",
    "TIMESTAMP_SKEW_SEC",
    "NONCE_TTL_SEC",
    "MAX_PAYLOAD_BYTES",
    "HMAC_HEX_LENGTH",
    "SHA256_HEX_LENGTH",
    "MIN_NONCE_BYTES",
    "SECRET_BYTES",
    "SECRET_HEX_LENGTH",
    "MessageType",
    "Channel",
    "ValidationStep",
    "ProtocolError",
]
