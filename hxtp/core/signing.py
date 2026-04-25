"""
HXTP Core — HMAC-SHA256 Message Signing and Verification.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from hxtp.core.canonical import build_canonical
from hxtp.core.constants import HMAC_HEX_LENGTH, SECRET_HEX_LENGTH
from hxtp.crypto.engine import constant_time_equal, sign_hmac_sha256


def sign_message(secret_hex: str, msg: dict[str, Any]) -> str:
    """
    Sign a message with HMAC-SHA256 over the canonical string.

    Args:
        secret_hex: 64-char hex-encoded shared secret (32 bytes).
        msg: Message fields for canonical string construction.

    Returns:
        64-char lowercase hex HMAC-SHA256 signature.

    Raises:
        ValueError: If secret is not a valid 64-character hex string.
    """
    if not secret_hex or len(secret_hex) != SECRET_HEX_LENGTH:
        raise ValueError(
            f"Secret must be a {SECRET_HEX_LENGTH}-character hex string (32 bytes)."
        )
    secret_bytes = bytes.fromhex(secret_hex)
    canonical = build_canonical(msg)
    return sign_hmac_sha256(secret_bytes, canonical)


def verify_signature(
    secret_hex: str,
    msg: dict[str, Any],
    signature: str,
) -> bool:
    """
    Verify a message signature using the active secret.

    Args:
        secret_hex: 64-char hex-encoded shared secret.
        msg: Message fields for canonical string construction.
        signature: 64-char hex signature to verify.

    Returns:
        True if signature is valid, False otherwise.
    """
    if not signature or len(signature) != HMAC_HEX_LENGTH:
        return False
    if not secret_hex:
        return False
    computed = sign_message(secret_hex, msg)
    return constant_time_equal(computed, signature)


def verify_signature_with_fallback(
    active_secret_hex: str,
    previous_secret_hex: str | None,
    msg: dict[str, Any],
    signature: str,
) -> tuple[bool, bool]:
    """
    Verify with dual-key fallback for key rotation windows.

    Mirrors backend ``VerifySignatureWithFallback`` and embedded
    ``validate_signature()`` dual-key path.

    Args:
        active_secret_hex: Current active secret (hex).
        previous_secret_hex: Previous secret for rotation window (hex), or None.
        msg: Message fields for canonical string construction.
        signature: 64-char hex signature to verify.

    Returns:
        Tuple of (valid, rotated).
        rotated=True means the previous key matched.
    """
    active_valid = verify_signature(active_secret_hex, msg, signature)
    if active_valid:
        return (True, False)

    if previous_secret_hex:
        prev_valid = verify_signature(previous_secret_hex, msg, signature)
        if prev_valid:
            return (True, True)

    return (False, False)
