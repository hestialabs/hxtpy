"""
HXTP Crypto Engine — SHA-256, HMAC-SHA256, constant-time compare, nonce generation.

Uses only Python stdlib: hmac, hashlib, secrets, time.
No third-party crypto libraries.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import secrets


def sign_hmac_sha256(secret: bytes, data: str) -> str:
    """
    Compute HMAC-SHA256 and return lowercase hex string (64 chars).

    Args:
        secret: Raw secret bytes (32 bytes).
        data: UTF-8 string to sign.

    Returns:
        64-character lowercase hex HMAC-SHA256 digest.
    """
    return _hmac.new(secret, data.encode("utf-8"), hashlib.sha256).hexdigest()


def sha256_hex(data: str) -> str:
    """
    Compute SHA-256 hash and return lowercase hex string (64 chars).

    Args:
        data: UTF-8 string to hash.

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    """
    Constant-time string comparison.

    Safe for comparing HMAC hex digests — prevents timing side-channels.
    Uses ``hmac.compare_digest`` which is the Python stdlib constant-time
    comparison function (wraps OpenSSL ``CRYPTO_memcmp``).

    Args:
        a: First string.
        b: Second string.

    Returns:
        True if strings are equal, False otherwise.
    """
    return _hmac.compare_digest(a, b)


def generate_nonce(byte_length: int = 16) -> str:
    """
    Generate a cryptographic nonce as hex string.

    Uses ``secrets.token_bytes`` for cryptographic randomness.

    Args:
        byte_length: Number of random bytes (default: 16).

    Returns:
        Hex-encoded nonce string (byte_length * 2 chars).
    """
    return secrets.token_bytes(byte_length).hex()


def random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes.

    Returns:
        Random bytes.
    """
    return secrets.token_bytes(length)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to lowercase hex string."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.

    Raises:
        ValueError: If hex string has odd length or invalid chars.
    """
    if len(hex_str) % 2 != 0:
        raise ValueError("Invalid hex string length")
    return bytes.fromhex(hex_str)
