"""
HXTP Transport — Pluggable Transport Interface.

No protocol logic inside transport.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Callable


class TransportState(Enum):
    """Transport connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"


class Transport(ABC):
    """
    Abstract pluggable transport interface for HxTP client.

    Implementations must handle the raw byte/string transport only.
    No protocol logic inside transport.
    """

    @property
    @abstractmethod
    def state(self) -> TransportState:
        """Current connection state."""
        ...

    @abstractmethod
    async def connect(self) -> None:
        """Open the connection to the server."""
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Close the connection gracefully."""
        ...

    @abstractmethod
    async def send(self, data: str) -> None:
        """
        Send a string payload.

        Raises:
            RuntimeError: If not connected.
        """
        ...

    @abstractmethod
    async def receive(self) -> str:
        """
        Receive a string payload.

        Returns:
            Received string data.

        Raises:
            RuntimeError: If not connected.
        """
        ...

    @abstractmethod
    def on_message(self, handler: Callable[[str], None]) -> None:
        """Register a message handler."""
        ...

    @abstractmethod
    def on_close(self, handler: Callable[[int, str], None]) -> None:
        """Register a close/disconnect handler."""
        ...

    @abstractmethod
    def on_error(self, handler: Callable[[Exception], None]) -> None:
        """Register an error handler."""
        ...
