"""
HXTP Client — Async-First Client API.

Features:
  - Ed25519 signed message construction (HxTP/3.1)
  - 11-field pipe-delimited canonical string (HxTP/3.1)
  - HELLO/HELLO_ACK lifecycle handshake
  - ACTIVE-state gating for command/message dispatch
  - Bootstrap/enrollment flow
  - Pluggable transport (default: WebSocket)
  - Auto-reconnect with exponential backoff
  - Heartbeat keepalive
  - Event-driven message handling
  - Inbound message validation (7-step pipeline)

No global singletons. No shared mutable state. No implicit caches.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from enum import Enum
from typing import TYPE_CHECKING, Any

from hxtpy.client.types import (
    HxTPCommandPayload,
    HxTPConfig,
    HxTPErrorEvent,
    HxTPMessageEvent,
    HxTPResponse,
)
from hxtpy.core.constants import ED25519_PRIV_HEX_LENGTH, MessageType
from hxtpy.core.envelope import build_envelope
from hxtpy.core.nonce import NonceCache
from hxtpy.crypto.engine import get_public_key
from hxtpy.transport.interface import Transport, TransportState
from hxtpy.transport.websocket import WebSocketTransport
from hxtpy.validation.pipeline import validate_message

if TYPE_CHECKING:
    from collections.abc import Callable


class LifecycleState(Enum):
    IDLE = "IDLE"
    HELLO_SENT = "HELLO_SENT"
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"


class HxTPClient:
    """
    Async-first HxTP protocol client.

    Constructs fully signed HxTP envelopes with:
      - Ed25519 signature over 11-field canonical string
      - SHA-256 payload hash
      - Cryptographic nonce
      - Monotonic sequence number
      - Lifecycle state machine (HELLO → HELLO_ACK → ACTIVE)

    Usage::

        client = HxTPClient(
            url="wss://api.hestialabs.in/ws",
            tenant_id="tenant-uuid",
            device_id="device-uuid",
            private_key_hex="64-char-hex-private-key",
        )
        await client.connect()
        response = await client.send_command({"action": "set_pin", "params": {"pin": 13}})
        await client.disconnect()
    """

    def __init__(
        self,
        url: str | None = None,
        tenant_id: str | None = None,
        device_id: str | None = None,
        private_key_hex: str | None = None,
        *,
        config: HxTPConfig | None = None,
        previous_private_key_hex: str | None = None,
        client_id: str | None = None,
        transport: Transport | None = None,
        replay_protection: bool = True,
        max_message_age_sec: int = 300,
        timestamp_skew_sec: int = 60,
        auto_reconnect: bool = True,
        reconnect_delay_ms: int = 1000,
        max_reconnect_delay_ms: int = 30000,
        heartbeat_interval_ms: int = 30000,
    ) -> None:
        if config is not None:
            self._config = config
        else:
            if not url:
                raise ValueError("url is required")
            if not tenant_id:
                raise ValueError("tenant_id is required")
            if not device_id:
                raise ValueError("device_id is required")
            if not private_key_hex:
                raise ValueError("private_key_hex is required")
            if not client_id:
                raise ValueError("client_id is required")
            if len(private_key_hex) != ED25519_PRIV_HEX_LENGTH:
                raise ValueError(
                    f"private_key_hex must be a {ED25519_PRIV_HEX_LENGTH}-character hex string"
                )
            public_key_hex = get_public_key(bytes.fromhex(private_key_hex)).hex()
            previous_public_key_hex: str | None = None
            if previous_private_key_hex:
                previous_public_key_hex = get_public_key(
                    bytes.fromhex(previous_private_key_hex)
                ).hex()
            self._config = HxTPConfig(
                url=url,
                tenant_id=tenant_id,
                device_id=device_id,
                private_key_hex=private_key_hex,
                public_key_hex=public_key_hex,
                previous_private_key_hex=previous_private_key_hex,
                previous_public_key_hex=previous_public_key_hex,
                client_id=client_id,
                transport=transport,
                replay_protection=replay_protection,
                max_message_age_sec=max_message_age_sec,
                timestamp_skew_sec=timestamp_skew_sec,
                auto_reconnect=auto_reconnect,
                reconnect_delay_ms=reconnect_delay_ms,
                max_reconnect_delay_ms=max_reconnect_delay_ms,
                heartbeat_interval_ms=heartbeat_interval_ms,
            )

        self._transport: Transport | None = None
        self._nonce_cache: NonceCache | None = None
        self._sequence: int = 0
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._reconnect_attempt: int = 0
        self._destroyed: bool = False
        self._lifecycle: LifecycleState = LifecycleState.IDLE

        # Event handlers
        self._message_handlers: list[Callable[[HxTPMessageEvent], None]] = []
        self._error_handlers: list[Callable[[HxTPErrorEvent], None]] = []
        self._connect_handlers: list[Callable[[], None]] = []
        self._disconnect_handlers: list[Callable[[int, str], None]] = []

    async def connect(self) -> None:
        """Connect to the server. Sends HELLO and waits for HELLO_ACK."""
        if self._destroyed:
            raise RuntimeError("Client has been destroyed")

        if self._config.replay_protection:
            self._nonce_cache = NonceCache()

        self._transport = self._config.transport or WebSocketTransport(self._config.url)

        def _on_message(data: str) -> None:
            asyncio.get_event_loop().call_soon(self._handle_message_sync, data)

        self._transport.on_message(_on_message)
        self._transport.on_close(lambda code, reason: self._handle_close(code, reason))
        self._transport.on_error(lambda err: self._handle_error(err))

        await self._transport.connect()
        self._reconnect_attempt = 0
        self._lifecycle = LifecycleState.HELLO_SENT

        await self._send_hello()

    async def _send_hello(self) -> None:
        """Send HELLO message with device identity (public key)."""
        assert self._transport is not None
        envelope = build_envelope(
            private_key_hex=self._config.private_key_hex,
            device_id=self._config.device_id,
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            message_type=MessageType.HELLO,
            params={
                "public_key": self._config.public_key_hex,
                "descriptor_hash": self._config.device_id,
            },
            sequence=0,
        )
        await self._transport.send(
            json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        )

    async def disconnect(self) -> None:
        """Disconnect gracefully and release resources."""
        self._destroyed = True
        self._lifecycle = LifecycleState.DISCONNECTED
        self._stop_heartbeat()
        self._stop_reconnect()

        if self._transport is not None:
            await self._transport.disconnect()
            self._transport = None

        if self._nonce_cache is not None:
            self._nonce_cache.clear()

    async def send_command(
        self,
        payload: dict[str, Any] | HxTPCommandPayload,
    ) -> HxTPResponse:
        """
        Send a signed command to the server.

        Args:
            payload: Command payload (dict with 'action' and 'params', or HxTPCommandPayload).

        Returns:
            HxTPResponse with ok=True and message metadata.

        Raises:
            RuntimeError: If not connected or lifecycle not ACTIVE.
        """
        if self._lifecycle != LifecycleState.ACTIVE:
            raise RuntimeError("Cannot send command: lifecycle is not ACTIVE")
        if self._transport is None or self._transport.state != TransportState.CONNECTED:
            raise RuntimeError("Not connected")
        if isinstance(self._transport, WebSocketTransport):
            raise RuntimeError(
                "HxTP command execution over WebSocket is not supported by the backend; "
                "use REST or MQTT ingress."
            )

        if isinstance(payload, dict):
            action = payload.get("action", "")
            params = payload.get("params", {})
            target_device = payload.get("device_id")
        else:
            action = payload.action
            params = payload.params
            target_device = payload.device_id

        self._sequence += 1

        envelope = build_envelope(
            private_key_hex=self._config.private_key_hex,
            device_id=target_device or self._config.device_id,
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            message_type=MessageType.COMMAND,
            action=action,
            params=params,
            sequence=self._sequence,
        )

        envelope_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        await self._transport.send(envelope_json)

        return HxTPResponse(
            ok=True,
            message_id=envelope["message_id"],
            timestamp=envelope["timestamp"],
        )

    async def send_message(
        self,
        message_type: str,
        params: dict[str, Any] | None = None,
    ) -> HxTPResponse:
        """
        Send a generic signed message (telemetry, state, etc).

        Args:
            message_type: Message type string (e.g. "telemetry", "state").
            params: Optional payload dictionary.

        Returns:
            HxTPResponse with ok=True and message metadata.

        Raises:
            RuntimeError: If not in ACTIVE lifecycle.
        """
        if self._lifecycle != LifecycleState.ACTIVE:
            raise RuntimeError(
                f"Cannot send {message_type}: lifecycle is not ACTIVE"
            )
        if self._transport is None or self._transport.state != TransportState.CONNECTED:
            raise RuntimeError("Not connected")

        self._sequence += 1

        envelope = build_envelope(
            private_key_hex=self._config.private_key_hex,
            device_id=self._config.device_id,
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            message_type=message_type,
            params=params or {},
            sequence=self._sequence,
        )

        envelope_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        await self._transport.send(envelope_json)

        return HxTPResponse(
            ok=True,
            message_id=envelope["message_id"],
            timestamp=envelope["timestamp"],
        )

    def on_message(self, handler: Callable[[HxTPMessageEvent], None]) -> None:
        """Register a message event handler."""
        self._message_handlers.append(handler)

    def on_error(self, handler: Callable[[HxTPErrorEvent], None]) -> None:
        """Register an error event handler."""
        self._error_handlers.append(handler)

    def on_connect(self, handler: Callable[[], None]) -> None:
        """Register a connect event handler."""
        self._connect_handlers.append(handler)

    def on_disconnect(self, handler: Callable[[int, str], None]) -> None:
        """Register a disconnect event handler."""
        self._disconnect_handlers.append(handler)

    @property
    def connected(self) -> bool:
        """Whether the client is currently connected and ACTIVE."""
        return (
            self._lifecycle == LifecycleState.ACTIVE
            and self._transport is not None
            and self._transport.state == TransportState.CONNECTED
        )

    @property
    def current_sequence(self) -> int:
        """Current monotonic sequence number."""
        return self._sequence

    @property
    def lifecycle(self) -> LifecycleState:
        """Current lifecycle state."""
        return self._lifecycle

    # ── Private Methods ─────────────────────────────────────────────

    def _handle_message_sync(self, raw: str) -> None:
        """Handle inbound message (sync wrapper for event loop)."""
        try:
            parsed: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            self._emit_error("PARSE_ERROR", "Invalid JSON message", False)
            return

        # Handle HELLO_ACK before entering ACTIVE
        if self._lifecycle == LifecycleState.HELLO_SENT:
            if parsed.get("message_type") == "hello_ack":
                self._lifecycle = LifecycleState.ACTIVE
                self._start_heartbeat()
                for cb in self._connect_handlers:
                    with contextlib.suppress(Exception):
                        cb()
                return
            self._emit_error("HELLO_TIMEOUT", "Expected HELLO_ACK", True)
            return

        # Validate inbound message (only when ACTIVE)
        result = validate_message(
            parsed,
            public_key_hex=self._config.public_key_hex,
            previous_public_key_hex=self._config.previous_public_key_hex,
            nonce_cache=self._nonce_cache,
            max_message_age_sec=self._config.max_message_age_sec,
            timestamp_skew_sec=self._config.timestamp_skew_sec,
        )

        if not result.ok:
            self._emit_error(result.code, result.reason, False)
            return

        evt = HxTPMessageEvent(
            raw=raw,
            parsed=parsed,
            timestamp=int(time.time() * 1000),
        )

        for msg_h in self._message_handlers:
            with contextlib.suppress(Exception):
                msg_h(evt)

    def _handle_close(self, code: int, reason: str) -> None:
        """Handle transport close."""
        self._lifecycle = LifecycleState.DISCONNECTED
        self._stop_heartbeat()

        for close_h in self._disconnect_handlers:
            with contextlib.suppress(Exception):
                close_h(code, reason)

        if not self._destroyed and self._config.auto_reconnect:
            self._schedule_reconnect()

    def _handle_error(self, err: Exception) -> None:
        """Handle transport error."""
        self._emit_error("TRANSPORT_ERROR", str(err), False)

    def _emit_error(self, code: str, message: str, fatal: bool) -> None:
        """Emit an error event."""
        err_evt = HxTPErrorEvent(code=code, message=message, fatal=fatal)
        for err_h in self._error_handlers:
            with contextlib.suppress(Exception):
                err_h(err_evt)

    def _start_heartbeat(self) -> None:
        """Start heartbeat keepalive task."""
        interval = self._config.heartbeat_interval_ms / 1000.0

        async def heartbeat_loop() -> None:
            while True:
                await asyncio.sleep(interval)
                if self._lifecycle == LifecycleState.ACTIVE:
                    with contextlib.suppress(Exception):
                        await self._send_heartbeat()

        self._heartbeat_task = asyncio.create_task(heartbeat_loop())

    async def _send_heartbeat(self) -> None:
        """Send a signed heartbeat message."""
        if self._lifecycle != LifecycleState.ACTIVE:
            return
        assert self._transport is not None

        self._sequence += 1

        envelope = build_envelope(
            private_key_hex=self._config.private_key_hex,
            device_id=self._config.device_id,
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            message_type=MessageType.HEARTBEAT,
            params={},
            sequence=self._sequence,
        )

        await self._transport.send(json.dumps(envelope, sort_keys=True, separators=(",", ":")))

    def _stop_heartbeat(self) -> None:
        """Stop heartbeat task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    def _schedule_reconnect(self) -> None:
        """Schedule exponential backoff reconnect."""
        self._reconnect_attempt += 1
        base = self._config.reconnect_delay_ms / 1000.0
        max_delay = self._config.max_reconnect_delay_ms / 1000.0
        delay = min(base * (2 ** (self._reconnect_attempt - 1)), max_delay)

        async def reconnect() -> None:
            await asyncio.sleep(delay)
            if self._destroyed:
                return
            try:
                if self._transport is not None:
                    self._lifecycle = LifecycleState.HELLO_SENT
                    await self._transport.connect()
                    self._reconnect_attempt = 0
                    await self._send_hello()
            except Exception:
                self._schedule_reconnect()

        self._reconnect_task = asyncio.create_task(reconnect())

    def _stop_reconnect(self) -> None:
        """Cancel pending reconnect."""
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None
