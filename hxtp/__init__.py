"""
HXTP Python SDK — Official HxTP/3.0 Protocol Implementation.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from hxtp.client.async_client import HxTPClient
from hxtp.client.sync_client import SyncHxTPClient
from hxtp.core.canonical import (
    build_canonical,
    parse_canonical,
    validate_canonical,
)
from hxtp.core.constants import (
    CANONICAL_SEPARATOR,
    HMAC_HEX_LENGTH,
    MAX_MESSAGE_AGE_SEC,
    MAX_PAYLOAD_BYTES,
    MIN_NONCE_BYTES,
    NONCE_TTL_SEC,
    PROTOCOL_VERSION,
    SHA256_HEX_LENGTH,
    TIMESTAMP_SKEW_SEC,
    Channel,
    MessageType,
    ProtocolError,
    ValidationStep,
)
from hxtp.core.envelope import build_envelope
from hxtp.core.nonce import NonceCache, generate_nonce
from hxtp.core.signing import (
    sign_message,
    verify_signature,
    verify_signature_with_fallback,
)
from hxtp.core.topics import build_topic, build_wildcard, parse_topic
from hxtp.crypto.engine import (
    constant_time_equal,
    crypto_generate_nonce,
    sha256_hex,
    sign_hmac_sha256,
)
from hxtp.transport.interface import Transport, TransportState
from hxtp.validation.errors import (
    ExpiredTimestampError,
    HxTPValidationError,
    InvalidSignatureError,
    InvalidVersionError,
    PayloadTooLargeError,
    ReplayAttackError,
    SequenceViolationError,
)
from hxtp.validation.pipeline import validate_message

__version__ = "1.0.0"

__all__ = [
    # Version
    "__version__",
    # Constants
    "PROTOCOL_VERSION",
    "CANONICAL_SEPARATOR",
    "MAX_MESSAGE_AGE_SEC",
    "TIMESTAMP_SKEW_SEC",
    "NONCE_TTL_SEC",
    "MAX_PAYLOAD_BYTES",
    "HMAC_HEX_LENGTH",
    "SHA256_HEX_LENGTH",
    "MIN_NONCE_BYTES",
    "MessageType",
    "Channel",
    "ValidationStep",
    "ProtocolError",
    # Core
    "build_canonical",
    "parse_canonical",
    "validate_canonical",
    "build_envelope",
    "generate_nonce",
    "NonceCache",
    "sign_message",
    "verify_signature",
    "verify_signature_with_fallback",
    "build_topic",
    "build_wildcard",
    "parse_topic",
    # Crypto
    "sign_hmac_sha256",
    "sha256_hex",
    "constant_time_equal",
    "crypto_generate_nonce",
    # Validation
    "validate_message",
    "HxTPValidationError",
    "InvalidVersionError",
    "ExpiredTimestampError",
    "ReplayAttackError",
    "InvalidSignatureError",
    "PayloadTooLargeError",
    "SequenceViolationError",
    # Client
    "HxTPClient",
    "SyncHxTPClient",
    # Transport
    "Transport",
    "TransportState",
]
