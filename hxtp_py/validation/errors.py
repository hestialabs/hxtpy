"""
HXTP Validation — Protocol Error Exceptions.

Explicit exceptions for each validation failure.
No silent returns. Fail closed.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations


class HxTPValidationError(Exception):
    """Base class for all HxTP validation errors."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"{code}: {reason}")


class InvalidVersionError(HxTPValidationError):
    """Raised when protocol version does not match."""

    def __init__(self, reason: str = "Unsupported protocol version") -> None:
        super().__init__("VERSION_MISMATCH", reason)


class ExpiredTimestampError(HxTPValidationError):
    """Raised when message timestamp is too old or from the future."""

    def __init__(self, reason: str = "Timestamp expired") -> None:
        super().__init__("TIMESTAMP_EXPIRED", reason)


class TimestampFutureError(HxTPValidationError):
    """Raised when message timestamp is too far in the future."""

    def __init__(self, reason: str = "Timestamp from future") -> None:
        super().__init__("TIMESTAMP_FUTURE", reason)


class PayloadTooLargeError(HxTPValidationError):
    """Raised when payload exceeds size limit."""

    def __init__(self, reason: str = "Payload too large") -> None:
        super().__init__("PAYLOAD_TOO_LARGE", reason)


class NonceMissingError(HxTPValidationError):
    """Raised when nonce is missing."""

    def __init__(self, reason: str = "Missing nonce") -> None:
        super().__init__("NONCE_MISSING", reason)


class ReplayAttackError(HxTPValidationError):
    """Raised when a duplicate nonce is detected (replay attack)."""

    def __init__(self, reason: str = "Nonce already seen (replay)") -> None:
        super().__init__("NONCE_REUSED", reason)


class HashMismatchError(HxTPValidationError):
    """Raised when payload hash does not match."""

    def __init__(self, reason: str = "Payload hash mismatch") -> None:
        super().__init__("HASH_MISMATCH", reason)


class SequenceViolationError(HxTPValidationError):
    """Raised when sequence number is out of order or duplicate."""

    def __init__(self, reason: str = "Sequence violation") -> None:
        super().__init__("SEQUENCE_VIOLATION", reason)


class SignatureMissingError(HxTPValidationError):
    """Raised when signature is missing."""

    def __init__(self, reason: str = "Missing signature") -> None:
        super().__init__("SIGNATURE_MISSING", reason)


class InvalidSignatureError(HxTPValidationError):
    """Raised when HMAC-SHA256 signature verification fails."""

    def __init__(self, reason: str = "HMAC-SHA256 verification failed") -> None:
        super().__init__("SIGNATURE_INVALID", reason)
