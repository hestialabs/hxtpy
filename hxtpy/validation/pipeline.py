"""
HXTP Validation — 7-Step Validation Pipeline.

FROZEN pipeline order:
  1. Version check
  2. Timestamp freshness
  3. Payload size enforcement
  4. Nonce uniqueness
  5. Payload hash verification
  6. Sequence monotonicity
  7. HMAC-SHA256 signature verification (with dual-key fallback)

ANY failure → reject immediately. No fallback. No soft-fail.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from hxtpy.core.constants import (
    MAX_MESSAGE_AGE_SEC,
    MAX_PAYLOAD_BYTES,
    PROTOCOL_VERSION,
    TIMESTAMP_SKEW_SEC,
    ProtocolError,
)
from hxtpy.core.signing import verify_signature_with_fallback
from hxtpy.crypto.engine import sha256_hex
from hxtpy.validation.errors import (
    ExpiredTimestampError,
    HashMismatchError,
    HxTPValidationError,
    InvalidSignatureError,
    InvalidVersionError,
    NonceMissingError,
    PayloadTooLargeError,
    ReplayAttackError,
    SequenceViolationError,
    SignatureMissingError,
    TimestampFutureError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from hxtpy.core.nonce import NonceCache


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Result of the validation pipeline."""

    ok: bool
    code: str = ""
    reason: str = ""
    rotated: bool = False


class SequenceTracker:
    """
    Tracks sequence numbers for monotonicity enforcement.

    Mirrors embedded SequenceTracker.
    """

    __slots__ = ("_last_sequence", "_initialized")

    def __init__(self) -> None:
        self._last_sequence: int = -1
        self._initialized: bool = False

    def check_and_advance(self, seq: int) -> bool:
        """
        Check if incoming sequence is strictly greater than last.

        Updates last_sequence on success.

        Returns:
            True if valid (seq > last), False if violation.
        """
        if not self._initialized:
            self._last_sequence = seq
            self._initialized = True
            return True
        if seq <= self._last_sequence:
            return False
        self._last_sequence = seq
        return True

    def reset(self) -> None:
        """Reset tracker state."""
        self._last_sequence = -1
        self._initialized = False

    @property
    def last_sequence(self) -> int:
        """Last accepted sequence number."""
        return self._last_sequence


@dataclass
class ValidationOptions:
    """Options for the validation pipeline."""

    active_secret: str
    previous_secret: str | None = None
    nonce_cache: NonceCache | None = None
    sequence_tracker: SequenceTracker | None = None
    max_message_age_sec: int = MAX_MESSAGE_AGE_SEC
    timestamp_skew_sec: int = TIMESTAMP_SKEW_SEC
    max_payload_bytes: int = MAX_PAYLOAD_BYTES
    now_ms: int | None = None


def _normalize_timestamp_to_seconds(ts: int | float) -> int:
    """
    Normalize a timestamp to seconds.

    If the value exceeds 1e12 it is interpreted as milliseconds
    and divided by 1000. This mirrors the embedded SDK and JS SDK
    normalization logic so that all three layers agree on age checks.

    IMPORTANT: This normalization is for age/freshness comparison ONLY.
    The canonical string used for HMAC signing always uses the raw
    timestamp value — no conversion is applied there.
    """
    if ts > 1_000_000_000_000:
        return int(ts // 1000)
    return int(ts)


def _pass() -> ValidationResult:
    return ValidationResult(ok=True, code="", reason="", rotated=False)


def _fail(code: str, reason: str) -> ValidationResult:
    return ValidationResult(ok=False, code=code, reason=reason, rotated=False)


def validate_message(
    msg: dict[str, Any],
    *,
    secret_hex: str | None = None,
    previous_secret_hex: str | None = None,
    nonce_cache: NonceCache | None = None,
    sequence_tracker: SequenceTracker | None = None,
    max_message_age_sec: int = MAX_MESSAGE_AGE_SEC,
    timestamp_skew_sec: int = TIMESTAMP_SKEW_SEC,
    max_payload_bytes: int = MAX_PAYLOAD_BYTES,
    now_ms: int | None = None,
    opts: ValidationOptions | None = None,
    raise_on_failure: bool = False,
) -> ValidationResult:
    """
    Validate an inbound message through the 7-step pipeline.

    The pipeline mirrors the embedded SDK validation order exactly:
      1. Version → 2. Timestamp → 3. PayloadSize → 4. Nonce →
      5. PayloadHash → 6. Sequence → 7. Signature

    Args:
        msg: Message dictionary to validate.
        secret_hex: Active secret as 64-char hex string.
        previous_secret_hex: Previous secret for rotation window (hex), or None.
        nonce_cache: Optional NonceCache for replay detection.
        sequence_tracker: Optional SequenceTracker for monotonicity.
        max_message_age_sec: Maximum message age in seconds.
        timestamp_skew_sec: Allowed timestamp skew in seconds.
        max_payload_bytes: Maximum payload size in bytes.
        now_ms: Current time in milliseconds (default: wall clock).
        opts: ValidationOptions (alternative to individual params).
        raise_on_failure: If True, raise exception instead of returning result.

    Returns:
        ValidationResult with ok=True on success, or ok=False with error details.

    Raises:
        HxTPValidationError subclass if raise_on_failure=True and validation fails.
    """
    # Resolve options
    if opts is not None:
        active_secret = opts.active_secret
        prev_secret = opts.previous_secret
        nc = opts.nonce_cache
        st = opts.sequence_tracker
        max_age = opts.max_message_age_sec
        skew = opts.timestamp_skew_sec
        max_pl = opts.max_payload_bytes
        now = opts.now_ms
    else:
        active_secret = secret_hex or ""
        prev_secret = previous_secret_hex
        nc = nonce_cache
        st = sequence_tracker
        max_age = max_message_age_sec
        skew = timestamp_skew_sec
        max_pl = max_payload_bytes
        now = now_ms

    if now is None:
        now = int(time.time() * 1000)

    def fail_with(
        code: str, reason: str, exc_cls: Callable[[str], HxTPValidationError]
    ) -> ValidationResult:
        if raise_on_failure:
            raise exc_cls(reason)
        return _fail(code, reason)

    # ── Step 1: Version ──────────────────────────────────────────
    version = str(msg.get("version") or msg.get("protocol_version") or "")
    if version != PROTOCOL_VERSION:
        return fail_with(
            ProtocolError.VERSION_MISMATCH,
            f"Unsupported version: {version}",
            InvalidVersionError,
        )

    # ── Step 2: Timestamp Freshness ──────────────────────────────
    raw_ts = msg.get("timestamp", 0)
    ts = raw_ts if isinstance(raw_ts, (int, float)) else 0
    now_sec = now // 1000
    ts_sec = _normalize_timestamp_to_seconds(ts)
    age_sec = now_sec - ts_sec

    if age_sec > max_age:
        return fail_with(
            ProtocolError.TIMESTAMP_EXPIRED,
            f"Message too old: {age_sec}s",
            ExpiredTimestampError,
        )

    if ts_sec > now_sec + skew:
        return fail_with(
            ProtocolError.TIMESTAMP_FUTURE,
            f"Message from future: {ts_sec - now_sec}s ahead",
            TimestampFutureError,
        )

    # ── Step 3: Payload Size ─────────────────────────────────────
    params = msg.get("params")
    if params is not None:
        params_str = json.dumps(params, sort_keys=True, separators=(",", ":"))
        if len(params_str.encode("utf-8")) > max_pl:
            return fail_with(
                ProtocolError.PAYLOAD_TOO_LARGE,
                f"Payload exceeds {max_pl} bytes",
                PayloadTooLargeError,
            )

    # ── Step 4: Nonce ────────────────────────────────────────────
    nonce = msg.get("nonce")
    if not nonce:
        return fail_with(
            ProtocolError.NONCE_MISSING,
            "Missing nonce",
            NonceMissingError,
        )

    if nc is not None and nc.check(nonce):
        return fail_with(
            ProtocolError.NONCE_REUSED,
            "Nonce already seen (replay)",
            ReplayAttackError,
        )

    # ── Step 5: Payload Hash ─────────────────────────────────────
    payload_hash = msg.get("payload_hash")
    if payload_hash:
        params_json = json.dumps(
            params if params is not None else {}, sort_keys=True, separators=(",", ":")
        )
        computed = sha256_hex(params_json)
        if computed != payload_hash:
            return fail_with(
                ProtocolError.HASH_MISMATCH,
                "Payload hash mismatch",
                HashMismatchError,
            )

    # ── Step 6: Sequence ─────────────────────────────────────────
    sequence = msg.get("sequence_number")
    if sequence is None:
        sequence = msg.get("sequence")
    if isinstance(sequence, int) and st is not None and not st.check_and_advance(sequence):
        return fail_with(
            ProtocolError.SEQUENCE_VIOLATION,
            f"Sequence {sequence} <= last {st.last_sequence}",
            SequenceViolationError,
        )

    # ── Step 7: Signature ────────────────────────────────────────
    signature = msg.get("signature")
    if not signature:
        return fail_with(
            ProtocolError.SIGNATURE_MISSING,
            "Missing signature",
            SignatureMissingError,
        )

    if not active_secret:
        return fail_with(
            ProtocolError.SECRET_MISSING,
            "No secret available for verification",
            InvalidSignatureError,
        )

    valid, rotated = verify_signature_with_fallback(
        active_secret_hex=active_secret,
        previous_secret_hex=prev_secret,
        msg=msg,
        signature=signature,
    )

    if not valid:
        return fail_with(
            ProtocolError.SIGNATURE_INVALID,
            "HMAC-SHA256 verification failed",
            InvalidSignatureError,
        )

    return ValidationResult(ok=True, code="", reason="", rotated=rotated)
