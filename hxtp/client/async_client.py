"""
HXTP Client — Async-First Client API.

Features:
  - Signed HMAC-SHA256 message construction
  - Pluggable transport (default: WebSocket)
  - Auto-reconnect with exponential backoff
  - Heartbeat keepalive
  - Event-driven message handling
  - Inbound message validation

No global singletons. No shared mutable state. No implicit caches.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable

from hxtp.client.types import (
    HxTPCommandPayload,
    HxTPConfig,
    HxTPErrorEvent,
    HxTPMessageEvent,
    HxTPResponse,
)
from hxtp.core.constants import MessageType, SECRET_HEX_LENGTH
from hxtp.core.envelope import build_envelope
from hxtp.core.nonce import NonceCache
from hxtp.transport.interface import Transport, TransportState
from hxtp.transport.websocket import WebSocketTransport
from hxtp.validation.pipeline import ValidationOptions, validate_message


class HxTPClient:
    """
    Async-first HxTP protocol client.

    Constructs fully signed HxTP envelopes with:
      - HMAC-SHA256 signature over frozen canonical string
      - SHA-256 payload hash
      - Cryptographic nonce
      - Monotonic sequence number

    Usage::

        client = HxTPClient(
            url="wss://api.hestialabs.in/ws",
            tenant_id="tenant-uuid",
            device_id="device-uuid",
            secret="64-char-hex-secret",
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
        secret: str | None = None,
        *,
        config: HxTPConfig | None = None,
        previous_secret: str | None = None,
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
            if not secret:
                raise ValueError("secret is required")
            if len(secret) != SECRET_HEX_LENGTH:
                raise ValueError(
                    f"secret must be a {SECRET_HEX_LENGTH}-character hex string"
                )
            self._config = HxTPConfig(
                url=url,
                tenant_id=tenant_id,
                device_id=device_id,
                secret=secret,
                previous_secret=previous_secret,
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

        # Event handlers
        self._message_handlers: list[Callable[[HxTPMessageEvent], None]] = []
        self._error_handlers: list[Callable[[HxTPErrorEvent], None]] = []
        self._connect_handlers: list[Callable[[], None]] = []
        self._disconnect_handlers: list[Callable[[int, str], None]] = []

    async def connect(self) -> None:
        """Connect to the server. Resolves when the connection is established."""
        if self._destroyed:
            raise RuntimeError("Client has been destroyed")

        if self._config.replay_protection:
            self._nonce_cache = NonceCache()

        self._transport = self._config.transport or WebSocketTransport(
            self._config.url
        )

        self._transport.on_message(lambda data: asyncio.get_event_loop().call_soon(
            self._handle_message_sync, data
        ))
        self._transport.on_close(lambda code, reason: self._handle_close(code, reason))
        self._transport.on_error(lambda err: self._handle_error(err))

        await self._transport.connect()
        self._reconnect_attempt = 0
        self._start_heartbeat()

        for handler in self._connect_handlers:
            try:
                handler()
            except Exception:
                pass

    async def disconnect(self) -> None:
        """Disconnect gracefully and release resources."""
        self._destroyed = True
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
            RuntimeError: If not connected.
        """
        if self._transport is None or self._transport.state != TransportState.CONNECTED:
            raise RuntimeError("Not connected")

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
            secret_hex=self._config.secret,
            device_id=target_device or self._config.device_id,
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            message_type=MessageType.COMMAND,
            params={"action": action, **params},
            sequence=self._sequence,
        )

        envelope_json = json.dumps(envelope, separators=(",", ":"))
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
        """Whether the client is currently connected."""
        return (
            self._transport is not None
            and self._transport.state == TransportState.CONNECTED
        )

    @property
    def current_sequence(self) -> int:
        """Current monotonic sequence number."""
        return self._sequence

    # ── Private Methods ─────────────────────────────────────────────

    def _handle_message_sync(self, raw: str) -> None:
        """Handle inbound message (sync wrapper for event loop)."""
        try:
            parsed: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            self._emit_error("PARSE_ERROR", "Invalid JSON message", False)
            return

        # Validate inbound message
        result = validate_message(
            parsed,
            secret_hex=self._config.secret,
            previous_secret_hex=self._config.previous_secret,
            nonce_cache=self._nonce_cache,
            max_message_age_sec=self._config.max_message_age_sec,
            timestamp_skew_sec=self._config.timestamp_skew_sec,
        )

        if not result.ok:
            self._emit_error(result.code, result.reason, False)
            return

        event = HxTPMessageEvent(
            raw=raw,
            parsed=parsed,
            timestamp=int(time.time() * 1000),
        )

        for handler in self._message_handlers:
            try:
                handler(event)
            except Exception:
                pass

    def _handle_close(self, code: int, reason: str) -> None:
        """Handle transport close."""
        self._stop_heartbeat()

        for handler in self._disconnect_handlers:
            try:
                handler(code, reason)
            except Exception:
                pass

        if not self._destroyed and self._config.auto_reconnect:
            self._schedule_reconnect()

    def _handle_error(self, err: Exception) -> None:
        """Handle transport error."""
        self._emit_error("TRANSPORT_ERROR", str(err), False)

    def _emit_error(self, code: str, message: str, fatal: bool) -> None:
        """Emit an error event."""
        event = HxTPErrorEvent(code=code, message=message, fatal=fatal)
        for handler in self._error_handlers:
            try:
                handler(event)
            except Exception:
                pass

    def _start_heartbeat(self) -> None:
        """Start heartbeat keepalive task."""
        interval = self._config.heartbeat_interval_ms / 1000.0

        async def heartbeat_loop() -> None:
            while True:
                await asyncio.sleep(interval)
                if self._transport and self._transport.state == TransportState.CONNECTED:
                    try:
                        await self._send_heartbeat()
                    except Exception:
                        pass

        self._heartbeat_task = asyncio.create_task(heartbeat_loop())

    async def _send_heartbeat(self) -> None:
        """Send a signed heartbeat message."""
        if self._transport is None or self._transport.state != TransportState.CONNECTED:
            return

        self._sequence += 1

        envelope = build_envelope(
            secret_hex=self._config.secret,
            device_id=self._config.device_id,
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            message_type=MessageType.HEARTBEAT,
            params={},
            sequence=self._sequence,
        )

        await self._transport.send(json.dumps(envelope, separators=(",", ":")))

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
                    await self._transport.connect()
                    self._reconnect_attempt = 0
                    self._start_heartbeat()
                    for handler in self._connect_handlers:
                        try:
                            handler()
                        except Exception:
                            pass
            except Exception:
                self._schedule_reconnect()

        self._reconnect_task = asyncio.create_task(reconnect())

    def _stop_reconnect(self) -> None:
        """Cancel pending reconnect."""
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None
