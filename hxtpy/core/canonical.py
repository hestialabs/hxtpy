"""
HXTP Core —  Canonical JSON Stringifier.
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
    Deterministic JSON stringifier ().
    - Lexicographical key sorting
    - Unicode NFC normalization
    - Numbers converted to strict decimal strings (avoids IEEE-754 divergence)
    - Domain Separation: Inject "protocol": "hxtp/3.0"
    """
    # Top-level object injection for Domain Separation
    if isinstance(data, dict) and "protocol" not in data:
        data = {**data, "protocol": "hxtp/3.0"}

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
    """Build the HxTP/3.1 10-field pipe canonical string."""
    if "payload_hash" not in msg:
        return canonical_json(msg)
    return "|".join(
        [
            str(msg["version"]),
            str(msg["device_id"]),
            str(msg["client_id"]),
            str(msg["message_id"]),
            str(msg["request_id"]),
            str(msg["sequence_number"]),
            str(msg["timestamp"]),
            str(msg["nonce"]),
            str(msg["message_type"]),
            str(msg["payload_hash"]),
        ]
    )


def canonical_params_json(data: Any) -> str:
    """Canonical params JSON for payload_hash without protocol injection."""

    def serialize(val: Any) -> str:
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)):
            s = format(val, ".20f").rstrip("0").rstrip(".")
            if s == "" or s == "-0":
                s = "0"
            return f'"{s}"'
        if isinstance(val, str):
            return json.dumps(unicodedata.normalize("NFC", val), ensure_ascii=False)
        if isinstance(val, list):
            return "[" + ",".join(serialize(x) for x in val) + "]"
        if isinstance(val, dict):
            return (
                "{"
                + ",".join(
                    f"{json.dumps(k, ensure_ascii=False)}:{serialize(val[k])}"
                    for k in sorted(val.keys())
                )
                + "}"
            )
        raise TypeError(f"HXTP_CANONICAL_ERROR: Unsupported type {type(val)}")

    return serialize(data if data is not None else {})


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
