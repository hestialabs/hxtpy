# HXTP Python SDK

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.1-blue.svg)](https://pypi.org/project/hxtp-py/)

**HxTP/3.1** Python Client SDK — A high-performance implementation of the Ed25519-signed IoT protocol. Features bit-perfect parity with Go, JS, and C++ implementations.

---

## Installation

```bash
pip install hxtp-py
```

---

## Quick Start

### Async Client with MQTT Transport

```python
import asyncio
from hxtp-py.client import HxTPClient
from hxtp-py.transport.mqtt import MQTTTransport
from decimal import Decimal

async def main():
  # 1. Initialize the Protocol-Bound Client
  client = HxTPClient(
    url="https://api.hestialabs.in/api/v1",
    tenant_id="your-tenant-uuid",
    device_id="your-device-uuid",
    client_id="unique-client-id",
    private_key_hex="64-char-hex-private-key",
  )

  # 2. Use high-performance MQTT transport
  mqtt = MQTTTransport(url="tcp://broker.hestialabs.in:1883")
  client.set_transport(mqtt)
  
  await mqtt.connect()

  # 3. Send a signed command with numeric precision
  response = await client.send_command(
    device_id="light-1",
    action="set_level",
    params={"brightness": Decimal("85.50")} # Bit-perfect decimal parity
  )
  
  print(f" Sent: {response.message_id}")

async def run():
  await main()

if __name__ == "__main__":
  asyncio.run(run())
```

---

## Protocol Alignment: HxTP/3.1

This SDK implements HxTP/3.1 with **bit-perfect parity** across the execution stack.

| Component | Status | Details |
| :--- | :--- | :--- |
| **Framing** | | Pipe-separated (`|`) with mandatory backslash escaping. |
| **Normalization** | | Mandatory **Unicode NFC** normalization for all fields. |
| **Numbers** | | Deterministic decimal strings via `Decimal`. |
| **Compliance** | | Verified against the cross-language compliance suite. |

---

## License

MIT License — Copyright (c) 2026 Hestia Labs
