"""
HXTP Core — Protocol Constants.

Re-exported from core/__init__.py for direct import convenience.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from hxtp_py.core import (
    CANONICAL_SEPARATOR,
    ED25519_PRIV_HEX_LENGTH,
    ED25519_PUB_HEX_LENGTH,
    ED25519_SIG_HEX_LENGTH,
    LEGACY_PROTOCOL_VERSION,
    MAX_MESSAGE_AGE_SEC,
    MAX_PAYLOAD_BYTES,
    MIN_NONCE_BYTES,
    NONCE_TTL_SEC,
    PROTOCOL_VERSION,
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
    "ED25519_SIG_HEX_LENGTH",
    "SHA256_HEX_LENGTH",
    "MIN_NONCE_BYTES",
    "ED25519_PUB_HEX_LENGTH",
    "ED25519_PRIV_HEX_LENGTH",
    "SECRET_HEX_LENGTH",
    "MessageType",
    "Channel",
    "ValidationStep",
    "ProtocolError",
]
