"""
HXTP Crypto Engine — Ed25519 signing, SHA-256 hashing, public key derivation.

Uses only Python stdlib and the `cryptography` package for Ed25519.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import hashlib
import secrets


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


def get_public_key(private_key_seed: bytes) -> bytes:
    """Derive Ed25519 public key from 32-byte private seed."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_seed)
    return priv_key.public_key().public_bytes_raw()


def sha256_hex(data: str) -> str:
    """
    Compute SHA-256 hash and return lowercase hex string (64 chars).

    Args:
        data: UTF-8 string to hash.

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


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
