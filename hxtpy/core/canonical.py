"""
HXTP Core — Production Grade Canonical JSON Stringifier.
Deterministic serialization for HMAC-SHA256 signatures.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any, cast


def canonical_json(data: Any) -> str:
    """
    Deterministic JSON stringifier (Production Grade).
    - Lexicographical key sorting
    - Unicode NFC normalization
    - Numbers converted to strict decimal strings (avoids IEEE-754 divergence)
    - Domain Separation: Inject "protocol": "hxtp/1.0"
    """
    # Top-level object injection for Domain Separation
    if isinstance(data, dict) and "protocol" not in data:
        data = {**data, "protocol": "hxtp/1.0"}

    def serialize(val: Any) -> str:
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)):
            # Bit-perfect cross-platform number strategy
            s = format(val, ".20f").rstrip("0").rstrip(".")
            if s == "" or s == "-0":
                s = "0"
            return f'"{s}"'
        if isinstance(val, str):
            normalized = unicodedata.normalize("NFC", val)
            return json.dumps(normalized, ensure_ascii=False)
        if isinstance(val, list):
            return "[" + ",".join(serialize(x) for x in val) + "]"
        if isinstance(val, dict):
            keys = sorted(val.keys())
            parts = [f"{json.dumps(k, ensure_ascii=False)}:{serialize(val[k])}" for k in keys]
            return "{" + ",".join(parts) + "}"
        raise TypeError(f"HXTP_CANONICAL_ERROR: Unsupported type {type(val)}")

    return serialize(data)


def build_canonical(msg: dict[str, Any]) -> str:
    """Legacy wrapper for CanonicalJSON (Production Grade)."""
    return canonical_json(msg)


def parse_canonical(canonical: str) -> dict[str, Any]:
    """Legacy helper (Deprecated — use JSON parsing)."""
    return cast("dict[str, Any]", json.loads(canonical))


def validate_canonical(canonical: str) -> bool:
    """Legacy helper (Deprecated)."""
    try:
        json.loads(canonical)
        return True
    except Exception:
        return False
