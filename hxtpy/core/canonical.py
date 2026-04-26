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
    Deterministic JSON stringifier (Production Grade).
    - Lexicographical key sorting
    - Unicode NFC normalization
    - Numbers converted to strict decimal strings (avoids IEEE-754 divergence)
    - Domain Separation: Inject "protocol": "hxtp/1.0"
    """
    # Top-level object injection for Domain Separation
    if isinstance(data, dict):
        if "protocol" not in data:
            data = {**data, "protocol": "hxtp/1.0"}

    def serialize(val: Any) -> str:
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)):
            # Bit-perfect cross-platform number strategy: Canonical Decimal String
            # Using .20f and trimming trailing zeros
            s = format(val, ".20f").rstrip("0").rstrip(".")
            if s == "" or s == "-0": s = "0"
            return f'"{s}"'
        if isinstance(val, str):
            # JSON string escape + NFC normalization
            normalized = unicodedata.normalize("NFC", val)
            return json.dumps(normalized, ensure_ascii=False)
        if isinstance(val, list):
            return "[" + ",".join(serialize(x) for x in val) + "]"
        if isinstance(val, dict):
            keys = sorted(val.keys())
            parts = [f'{json.dumps(k, ensure_ascii=False)}:{serialize(val[k])}' for k in keys]
            return "{" + ",".join(parts) + "}"
        raise TypeError(f"HXTP_CANONICAL_ERROR: Unsupported type {type(val)}")

    return serialize(data)


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
