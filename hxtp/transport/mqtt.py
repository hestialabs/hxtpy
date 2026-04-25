"""
HXTP Transport — MQTT Transport Implementation.

Uses the ``gmqtt`` library for async MQTT communication.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable

from hxtp.core.constants import Channel, MessageType
from hxtp.core.topics import build_topic
from hxtp.transport.interface import Transport, TransportState

try:
    import gmqtt  # type: ignore
    _HAS_GMQTT = True
except ImportError:
    _HAS_GMQTT = False

Log = logging.getLogger("hxtp.transport.mqtt")


class MqttTransport(Transport):
    """
    MQTT transport implementation using the ``gmqtt`` library.

    This transport automatically maps HxTP message types to the correct 
    MQTT channels (e.g., heartbeat -> heartbeat, ack -> cmd_ack).

    Args:
        host: MQTT broker hostname.
        port: MQTT broker port (default: 1883).
        keepalive: MQTT keepalive interval in seconds (default: 60).
        ssl: SSL context if using MQTTS.
    """

    def __init__(
        self,
        host: str,
        port: int = 1883,
        *,
        keepalive: int = 60,
        ssl: Any = None,
        client_id: str | None = None,
    ) -> None:
        if not _HAS_GMQTT:
            raise ImportError(
                "gmqtt library is required for MQTT transport. "
                "Install it with: pip install gmqtt"
            )

        self._host = host
        self._port = port
        self._keepalive = keepalive
        self._ssl = ssl
        self._client_id = client_id

        self._client: gmqtt.Client | None = None
        self._state = TransportState.DISCONNECTED
        self._message_handlers: list[Callable[[str], None]] = []
        self._close_handlers: list[Callable[[int, str], None]] = []
        self._error_handlers: list[Callable[[Exception], None]] = []
        
        # Subscriptions to manage
        self._subscriptions: set[str] = set()

    @property
    def state(self) -> TransportState:
        return self._state

    async def connect(self) -> None:
        if self._state == TransportState.CONNECTED:
            return

        self._state = TransportState.CONNECTING
        self._client = gmqtt.Client(self._client_id)
        
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect
        
        if self._ssl:
            self._client.set_config_params(ssl=self._ssl)

        try:
            await self._client.connect(self._host, self._port, keepalive=self._keepalive)
            self._state = TransportState.CONNECTED
        except Exception as exc:
            self._state = TransportState.DISCONNECTED
            for handler in self._error_handlers:
                handler(exc)
            raise

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None
        self._state = TransportState.DISCONNECTED

    async def send(self, data: str) -> None:
        """
        Send a string payload. 
        Parses JSON to determine the correct MQTT topic.
        """
        if self._client is None or self._state != TransportState.CONNECTED:
            raise RuntimeError("MQTT not connected")

        try:
            envelope = json.loads(data)
            device_id = envelope.get("device_id")
            tenant_id = envelope.get("tenant_id")
            msg_type = envelope.get("message_type")
            
            if not all([device_id, tenant_id, msg_type]):
                raise ValueError("Incomplete HxTP envelope for MQTT routing")

            channel = self._resolve_channel(msg_type)
            topic = build_topic(tenant_id, device_id, channel)
            
            self._client.publish(topic, data, qos=1)
        except Exception as exc:
            Log.error(f"Failed to route MQTT message: {exc}")
            raise

    async def receive(self) -> str:
        """
        MQTT is event-driven; this interface is less natural here.
        HxTPClient primarily uses on_message.
        """
        raise NotImplementedError("Use on_message for MQTT transport")

    def on_message(self, handler: Callable[[str], None]) -> None:
        self._message_handlers.append(handler)

    def on_close(self, handler: Callable[[int, str], None]) -> None:
        self._close_handlers.append(handler)

    def on_error(self, handler: Callable[[Exception], None]) -> None:
        self._error_handlers.append(handler)

    async def subscribe(self, topic: str) -> None:
        """Subscribe to a specific HxTP topic."""
        if self._client is None:
            raise RuntimeError("MQTT client not initialized")
        self._client.subscribe(topic)
        self._subscriptions.add(topic)

    # ── Private Implementation ──────────────────────────────────────

    def _resolve_channel(self, msg_type: str) -> str:
        """Map HxTP message type to MQTT channel segment."""
        mapping = {
            MessageType.HEARTBEAT: Channel.HEARTBEAT,
            MessageType.STATE: Channel.STATE,
            MessageType.TELEMETRY: Channel.TELEMETRY,
            MessageType.ACK: Channel.CMD_ACK,
            MessageType.ERROR: Channel.CMD_ACK,
            MessageType.COMMAND: Channel.CMD,
        }
        # Special case for 'hello' which is a type of handshake not always in MessageType enum
        if msg_type == "hello":
            return Channel.HELLO
        return mapping.get(msg_type, Channel.STATE)

    def _on_connect(self, client: Any, flags: Any, rc: Any, properties: Any) -> None:
        Log.info(f"MQTT Connected (rc={rc})")
        # Re-subscribe on reconnect
        for topic in self._subscriptions:
            self._client.subscribe(topic)

    def _on_message(self, client: Any, topic: str, payload: bytes, qos: Any, properties: Any) -> None:
        data = payload.decode("utf-8")
        for handler in self._message_handlers:
            try:
                handler(data)
            except Exception:
                pass

    def _on_disconnect(self, client: Any, packet: Any, exc: Any) -> None:
        self._state = TransportState.DISCONNECTED
        reason = str(exc) if exc else "Graceful disconnect"
        for handler in self._close_handlers:
            try:
                handler(0, reason)
            except Exception:
                pass
