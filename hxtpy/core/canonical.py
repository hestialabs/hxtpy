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


import json
import unicodedata

def canonical_json(data: Any) -> str:
    """
    Deterministic JSON stringifier (Strict Mode).
    - Lexicographical key sorting
    - Unicode NFC normalization
    - Stable number formatting (No scientific notation)
    - Explicit null/boolean/UTF-8
    """
    if data is None:
        return "null"
    if isinstance(data, bool):
        return "true" if data else "false"
    if isinstance(data, (int, float)):
        # Stable float formatting: no scientific notation, no trailing zeros
        s = format(data, ".20f").rstrip("0").rstrip(".")
        if s == "" or s == "-0": s = "0"
        return s
    if isinstance(data, str):
        # JSON string escape + NFC normalization
        normalized = unicodedata.normalize("NFC", data)
        return json.dumps(normalized, ensure_ascii=False)
    if isinstance(data, list):
        return "[" + ",".join(canonical_json(x) for x in data) + "]"
    if isinstance(data, dict):
        keys = sorted(data.keys())
        parts = [f'{json.dumps(k, ensure_ascii=False)}:{canonical_json(data[k])}' for k in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"HXTP_CANONICAL_ERROR: Unsupported type {type(data)}")


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
