"""
HXTP Core — Nonce Generation and Replay Cache.

Nonces are hex-encoded random bytes (min 16 bytes → 32 hex chars).

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import time

from hxtp_py.core.constants import MIN_NONCE_BYTES, NONCE_TTL_SEC
from hxtp_py.crypto.engine import generate_nonce as _crypto_generate_nonce


def generate_nonce(byte_length: int = MIN_NONCE_BYTES) -> str:
    """
    Generate a cryptographic nonce as hex string.

    Minimum 16 raw bytes → 32 hex characters.

    Args:
        byte_length: Number of random bytes (default: 16).

    Returns:
        Hex-encoded nonce string.

    Raises:
        ValueError: If byte_length < MIN_NONCE_BYTES.
    """
    if byte_length < MIN_NONCE_BYTES:
        raise ValueError(f"Nonce must be >= {MIN_NONCE_BYTES} bytes.")
    return _crypto_generate_nonce(byte_length)


class NonceCache:
    """
    In-memory nonce replay cache with TTL eviction.

    Suitable for long-lived processes.
    Mirrors JS SDK NonceCache and embedded NonceCache ring buffer.
    """

    __slots__ = ("_entries", "_max_size", "_ttl_ms")

    def __init__(
        self,
        max_size: int = 256,
        ttl_sec: int = NONCE_TTL_SEC,
    ) -> None:
        self._entries: list[tuple[str, float]] = []
        self._max_size = max_size
        self._ttl_ms = ttl_sec * 1000.0

    def check(self, nonce: str) -> bool:
        """
        Check if a nonce has been seen. Returns True if duplicate (replay).

        Automatically records the nonce if new.

        Args:
            nonce: Nonce string to check.

        Returns:
            True if duplicate (replay detected), False if new.
        """
        now = time.time() * 1000.0
        self._evict(now)

        for entry_nonce, _ in self._entries:
            if entry_nonce == nonce:
                return True

        self._entries.append((nonce, now))

        if len(self._entries) > self._max_size:
            self._entries.pop(0)

        return False

    def _evict(self, now: float) -> None:
        """Remove expired entries."""
        while self._entries and (now - self._entries[0][1]) > self._ttl_ms:
            self._entries.pop(0)

    def clear(self) -> None:
        """Clear all entries."""
        self._entries.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._entries)
