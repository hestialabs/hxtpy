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
    """Compute HMAC-SHA256 and return lowercase hex string (64 chars)."""
    return _hmac.new(secret, data.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_ed25519(private_key_seed: bytes, data: str) -> str:
    """
    Sign data using Ed25519 and return hex signature (128 chars).

    Args:
        private_key_seed: 32-byte private key seed.
        data: String data to sign.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_seed)
    signature = priv_key.sign(data.encode("utf-8"))
    return signature.hex()


def verify_ed25519(public_key: bytes, data: str, signature_hex: str) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        public_key: 32-byte public key.
        data: Signed data string.
        signature_hex: 128-char hex signature.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    try:
        pub_key.verify(bytes.fromhex(signature_hex), data.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


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
