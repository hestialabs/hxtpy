"""
HXTP Transport — WebSocket Transport Implementation.

Uses the ``websockets`` library for async WebSocket communication.

Matches:
  - JS SDK: src/transport/websocket.ts → WebSocketTransport

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from hxtp.transport.interface import Transport, TransportState

try:
    import websockets.asyncio.client as ws_client  # type: ignore

    if TYPE_CHECKING:
        from collections.abc import Callable

        from websockets.asyncio.client import ClientConnection

    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False


class WebSocketTransport(Transport):
    """
    WebSocket transport implementation using the ``websockets`` library.

    Args:
        url: WebSocket server URL (ws:// or wss://).
        token: Optional authentication token sent as query param.
        connect_timeout: Connection timeout in seconds (default: 10).
    """

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        if not _HAS_WEBSOCKETS:
            raise ImportError(
                "websockets library is required for WebSocket transport. "
                "Install it with: pip install websockets"
            )

        if token:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}token={token}"

        self._url = url
        self._connect_timeout = connect_timeout
        self._connection: ClientConnection | None = None
        self._state = TransportState.DISCONNECTED
        self._message_handlers: list[Callable[[str], None]] = []
        self._close_handlers: list[Callable[[int, str], None]] = []
        self._error_handlers: list[Callable[[Exception], None]] = []
        self._receive_task: asyncio.Task[None] | None = None

    @property
    def state(self) -> TransportState:
        return self._state

    async def connect(self) -> None:
        if self._state == TransportState.CONNECTED:
            return

        self._state = TransportState.CONNECTING
        try:
            self._connection = await asyncio.wait_for(
                ws_client.connect(self._url),
                timeout=self._connect_timeout,
            )
            self._state = TransportState.CONNECTED
            self._receive_task = asyncio.create_task(self._receive_loop())
        except Exception as exc:
            self._state = TransportState.DISCONNECTED
            for handler in self._error_handlers:
                handler(exc)
            raise

    async def disconnect(self) -> None:
        if self._receive_task is not None:
            self._receive_task.cancel()
            if self._receive_task is not None:
                with contextlib.suppress(asyncio.CancelledError):
                    await self._receive_task
            self._receive_task = None

        if self._connection is not None:
            with contextlib.suppress(Exception):
                await self._connection.close()
            self._connection = None

        self._state = TransportState.DISCONNECTED

    async def send(self, data: str) -> None:
        if self._connection is None or self._state != TransportState.CONNECTED:
            raise RuntimeError("WebSocket not connected")
        await self._connection.send(data)

    async def receive(self) -> str:
        if self._connection is None or self._state != TransportState.CONNECTED:
            raise RuntimeError("WebSocket not connected")
        msg = await self._connection.recv()
        if isinstance(msg, bytes):
            return msg.decode("utf-8")
        return str(msg)

    def on_message(self, handler: Callable[[str], None]) -> None:
        self._message_handlers.append(handler)

    def on_close(self, handler: Callable[[int, str], None]) -> None:
        self._close_handlers.append(handler)

    def on_error(self, handler: Callable[[Exception], None]) -> None:
        self._error_handlers.append(handler)

    async def _receive_loop(self) -> None:
        """Background task to receive messages and dispatch to handlers."""
        assert self._connection is not None
        try:
            async for message in self._connection:
                data = message if isinstance(message, str) else message.decode("utf-8")
                for msg_h in self._message_handlers:
                    with contextlib.suppress(Exception):
                        msg_h(data)
        except asyncio.CancelledError:
            return
        except Exception as exc:
            for err_h in self._error_handlers:
                err_h(exc)
        finally:
            self._state = TransportState.DISCONNECTED
            self._connection = None
            for close_h in self._close_handlers:
                with contextlib.suppress(Exception):
                    close_h(1000, "Connection closed")
