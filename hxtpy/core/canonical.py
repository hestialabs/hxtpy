"""
HXTP Core — FROZEN Canonical String Builder.

Format: version|device_id|client_id|message_id|request_id|sequence_number|timestamp|nonce|message_type|payload_hash

This format is FROZEN. Any change invalidates ALL signatures across
all deployed devices (embedded, backend, and client SDKs).

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from hxtpy.core.constants import CANONICAL_SEPARATOR


def build_canonical(msg: dict[str, Any]) -> str:
    """
    Build a canonical string from a message dictionary.
    MCSS v3.0 FROZEN FORMAT (10 fields):
    version|device_id|client_id|message_id|request_id|sequence_number|timestamp|nonce|message_type|payload_hash
    """
    parts: list[str] = [
        str(msg.get("version") or ""),
        str(msg.get("device_id") or ""),
        str(msg.get("client_id") or ""),
        str(msg.get("message_id") or ""),
        str(msg.get("request_id") or ""),
        str(msg.get("sequence_number") if msg.get("sequence_number") is not None else ""),
        str(msg.get("timestamp") or ""),
        str(msg.get("nonce") or ""),
        str(msg.get("message_type") or ""),
        str(msg.get("payload_hash") or ""),
    ]

    # Strict validation: all 10 fields are mandatory in v3.0
    for i, part in enumerate(parts):
        if not part:
            raise ValueError(f"CANONICAL_ERROR: Missing mandatory field at index {i}")

    return CANONICAL_SEPARATOR.join(parts)


def parse_canonical(canonical: str) -> dict[str, str]:
    """Parse a canonical string back into named components."""
    parts = canonical.split(CANONICAL_SEPARATOR)
    return {
        "version": parts[0] if len(parts) > 0 else "",
        "device_id": parts[1] if len(parts) > 1 else "",
        "client_id": parts[2] if len(parts) > 2 else "",
        "message_id": parts[3] if len(parts) > 3 else "",
        "request_id": parts[4] if len(parts) > 4 else "",
        "sequence_number": parts[5] if len(parts) > 5 else "",
        "timestamp": parts[6] if len(parts) > 6 else "",
        "nonce": parts[7] if len(parts) > 7 else "",
        "message_type": parts[8] if len(parts) > 8 else "",
        "payload_hash": parts[9] if len(parts) > 9 else "",
    }


def validate_canonical(canonical: str) -> bool:
    """Validate that a canonical string has exactly 10 non-empty fields."""
    parts = canonical.split(CANONICAL_SEPARATOR)
    return len(parts) == 10 and all(len(p) > 0 for p in parts)
