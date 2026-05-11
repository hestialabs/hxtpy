"""
HXTP Core — HMAC-SHA256 Message Signing and Verification.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from hxtpy.core.canonical import build_canonical, canonical_json
from hxtpy.core.constants import ED25519_SIG_HEX_LENGTH, SECRET_HEX_LENGTH
from hxtpy.crypto.engine import sign_ed25519, verify_ed25519


def sign_message(private_key_hex: str, msg: dict[str, Any]) -> str:
    """
    Sign a message with Ed25519 over the canonical string.

    Args:
        private_key_hex: 64-char hex-encoded private key seed (32 bytes).
        msg: Message fields for canonical string construction.

    Returns:
        128-char lowercase hex Ed25519 signature.
    """
    if not private_key_hex or len(private_key_hex) != SECRET_HEX_LENGTH:
        raise ValueError(f"Private key must be a {SECRET_HEX_LENGTH}-character hex string.")
    priv_bytes = bytes.fromhex(private_key_hex)
    signable = {k: v for k, v in msg.items() if k != "signature"}
    if signable.get("version") == "HxTP/3.1":
        canonical = build_canonical(signable)
    else:
        canonical = canonical_json(signable)
    return sign_ed25519(priv_bytes, canonical)


def verify_signature(
    public_key_hex: str,
    msg: dict[str, Any],
    signature: str,
) -> bool:
    """
    Verify a message signature using an Ed25519 public key.

    Args:
        public_key_hex: 64-char hex-encoded public key.
        msg: Message fields for canonical string construction.
        signature: 128-char hex signature to verify.

    Returns:
        True if signature is valid, False otherwise.
    """
    if not signature or len(signature) != ED25519_SIG_HEX_LENGTH:
        return False
    if not public_key_hex or len(public_key_hex) != 64:
        return False
    pub_bytes = bytes.fromhex(public_key_hex)
    signable = {k: v for k, v in msg.items() if k != "signature"}
    if signable.get("version") == "HxTP/3.1":
        canonical = build_canonical(signable)
    else:
        canonical = canonical_json(signable)
    return verify_ed25519(pub_bytes, canonical, signature)


def verify_signature_with_fallback(
    active_public_key_hex: str,
    previous_public_key_hex: str | None,
    msg: dict[str, Any],
    signature: str,
) -> tuple[bool, bool]:
    """
    Verify with dual-key fallback for key rotation windows.

    Args:
        active_public_key_hex: Current active public key (hex).
        previous_public_key_hex: Previous public key for rotation window (hex), or None.
        msg: Message fields for canonical string construction.
        signature: 128-char hex signature to verify.

    Returns:
        Tuple of (valid, rotated).
        rotated=True means the previous key matched.
    """
    active_valid = verify_signature(active_public_key_hex, msg, signature)
    if active_valid:
        return (True, False)

    if previous_public_key_hex:
        prev_valid = verify_signature(previous_public_key_hex, msg, signature)
        if prev_valid:
            return (True, True)

    return (False, False)
