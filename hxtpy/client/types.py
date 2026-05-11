"""
HXTP Client — Type Definitions.

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hxtpy.transport.interface import Transport


@dataclass(frozen=True, slots=True)
class HxTPConfig:
    """HxTP client configuration."""

    url: str
    tenant_id: str
    device_id: str
    private_key_hex: str
    client_id: str
    public_key_hex: str = ""
    previous_private_key_hex: str | None = None
    previous_public_key_hex: str | None = None
    transport: Transport | None = None
    replay_protection: bool = True
    max_message_age_sec: int = 300
    timestamp_skew_sec: int = 60
    auto_reconnect: bool = True
    reconnect_delay_ms: int = 1000
    max_reconnect_delay_ms: int = 30000
    heartbeat_interval_ms: int = 30000


@dataclass(frozen=True, slots=True)
class HxTPCommandPayload:
    """Command payload for sending commands."""

    action: str
    params: dict[str, Any] = field(default_factory=dict)
    device_id: str | None = None


@dataclass(frozen=True, slots=True)
class HxTPResponse:
    """Response from sending a command."""

    ok: bool
    message_id: str
    timestamp: int
    data: dict[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class HxTPMessageEvent:
    """Inbound message event."""

    raw: str
    parsed: dict[str, Any]
    timestamp: int


@dataclass(frozen=True, slots=True)
class HxTPErrorEvent:
    """Error event."""

    code: str
    message: str
    fatal: bool
