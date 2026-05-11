"""
HXTP Python SDK — Official HxTP/3.0 Protocol Implementation.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from hxtp_py.client.async_client import HxTPClient
from hxtp_py.client.sync_client import SyncHxTPClient
from hxtp_py.core.canonical import (
    build_canonical,
    canonical_json,
    canonical_params_json,
)
from hxtp_py.core.constants import (
    CANONICAL_SEPARATOR,
    ED25519_PRIV_HEX_LENGTH,
    ED25519_PUB_HEX_LENGTH,
    ED25519_SIG_HEX_LENGTH,
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
from hxtp_py.core.envelope import build_envelope
from hxtp_py.core.nonce import NonceCache, generate_nonce
from hxtp_py.core.signing import (
    sign_message,
    verify_signature,
    verify_signature_with_fallback,
)
from hxtp_py.core.topics import build_topic, build_wildcard, parse_topic
from hxtp_py.crypto.engine import (
    generate_nonce as crypto_generate_nonce,
)
from hxtp_py.crypto.engine import (
    sha256_hex,
    sign_ed25519,
    verify_ed25519,
)
from hxtp_py.transport.interface import Transport, TransportState
from hxtp_py.validation.errors import (
    ExpiredTimestampError,
    HxTPValidationError,
    InvalidSignatureError,
    InvalidVersionError,
    PayloadTooLargeError,
    ReplayAttackError,
    SequenceViolationError,
)
from hxtp_py.validation.pipeline import validate_message

__version__ = "1.0.9"

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
    "ED25519_SIG_HEX_LENGTH",
    "SHA256_HEX_LENGTH",
    "MIN_NONCE_BYTES",
    "ED25519_PUB_HEX_LENGTH",
    "ED25519_PRIV_HEX_LENGTH",
    "MessageType",
    "Channel",
    "ValidationStep",
    "ProtocolError",
    # Core
    "canonical_json",
    "canonical_params_json",
    "build_canonical",
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
    "sign_ed25519",
    "verify_ed25519",
    "sha256_hex",
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
