"""
HXTP Client — Synchronous Wrapper.

Provides a synchronous API over the async HxTPClient using asyncio.run().
No global state. No implicit singletons.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

from hxtp_py.client.async_client import HxTPClient

if TYPE_CHECKING:
    from collections.abc import Callable

    from hxtp_py.client.types import (
        HxTPCommandPayload,
        HxTPConfig,
        HxTPErrorEvent,
        HxTPMessageEvent,
        HxTPResponse,
    )
    from hxtp_py.transport.interface import Transport


class SyncHxTPClient:
    """
    Synchronous HxTP client wrapper.

    Built using asyncio internally.
    All methods block until the async operation completes.

    Usage::

        client = SyncHxTPClient(
            url="wss://api.hestialabs.in/ws",
            tenant_id="tenant-uuid",
            device_id="device-uuid",
            private_key_hex="64-char-hex-private-key",
        )
        client.connect()
        response = client.send_command({"action": "set_pin", "params": {"pin": 13}})
        client.disconnect()
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
        self._loop: asyncio.AbstractEventLoop | None = None
        self._async_client = HxTPClient(
            url=url,
            tenant_id=tenant_id,
            device_id=device_id,
            private_key_hex=private_key_hex,
            config=config,
            previous_private_key_hex=previous_private_key_hex,
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

    def _run(self, coro: Any) -> Any:
        """Run an async coroutine synchronously."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # We're inside an already-running event loop (e.g., Jupyter)
            # Use nest_asyncio-style approach or create a new thread
            import threading

            result: Any = None
            exception: BaseException | None = None

            def run_in_thread() -> None:
                nonlocal result, exception
                new_loop = asyncio.new_event_loop()
                try:
                    result = new_loop.run_until_complete(coro)
                except BaseException as exc:
                    exception = exc
                finally:
                    new_loop.close()

            thread = threading.Thread(target=run_in_thread)
            thread.start()
            thread.join()

            if exception is not None:
                raise exception
            return result
        else:
            return asyncio.run(coro)

    def connect(self) -> None:
        """Connect to the server."""
        self._run(self._async_client.connect())

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self._run(self._async_client.disconnect())

    def send_command(
        self,
        payload: dict[str, Any] | HxTPCommandPayload,
    ) -> HxTPResponse:
        """Send a signed command to the server."""
        return cast("HxTPResponse", self._run(self._async_client.send_command(payload)))

    def on_message(self, handler: Callable[[HxTPMessageEvent], None]) -> None:
        """Register a message event handler."""
        self._async_client.on_message(handler)

    def on_error(self, handler: Callable[[HxTPErrorEvent], None]) -> None:
        """Register an error event handler."""
        self._async_client.on_error(handler)

    def on_connect(self, handler: Callable[[], None]) -> None:
        """Register a connect event handler."""
        self._async_client.on_connect(handler)

    def on_disconnect(self, handler: Callable[[int, str], None]) -> None:
        """Register a disconnect event handler."""
        self._async_client.on_disconnect(handler)

    @property
    def connected(self) -> bool:
        """Whether the client is currently connected."""
        return self._async_client.connected

    @property
    def current_sequence(self) -> int:
        """Current monotonic sequence number."""
        return self._async_client.current_sequence
