"""
HXTP Core — MQTT Topic Builder and Parser.

Format: hxtp/{tenantId}/device/{deviceId}/{channel}

Copyright (c) 2026 Hestia Labs
SDK-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass


def build_topic(tenant_id: str, device_id: str, channel: str) -> str:
    """
    Build an MQTT topic string for a device channel.

    Args:
        tenant_id: Tenant UUID.
        device_id: Device UUID.
        channel: Channel name (e.g., "state", "cmd").

    Returns:
        MQTT topic string.
    """
    return f"hxtp/{tenant_id}/device/{device_id}/{channel}"


def build_wildcard(channel: str) -> str:
    """
    Build a wildcard subscription topic for a channel.

    Args:
        channel: Channel name.

    Returns:
        MQTT wildcard topic string.
    """
    return f"hxtp/+/device/+/{channel}"


def build_full_wildcard() -> str:
    """Build the full wildcard for all channels."""
    return "hxtp/+/device/+/#"


@dataclass(frozen=True, slots=True)
class ParsedTopic:
    """Parsed MQTT topic components."""

    tenant_id: str
    device_id: str
    channel: str


def parse_topic(topic: str) -> ParsedTopic | None:
    """
    Parse an MQTT topic string into components.

    Returns None if the topic does not match HxTP format.

    Args:
        topic: Raw MQTT topic string.

    Returns:
        ParsedTopic dataclass or None if invalid format.
    """
    parts = topic.split("/")
    if len(parts) != 5 or parts[0] != "hxtp" or parts[2] != "device":
        return None
    return ParsedTopic(
        tenant_id=parts[1],
        device_id=parts[3],
        channel=parts[4],
    )
