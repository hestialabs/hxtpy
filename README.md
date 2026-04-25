# HXTP Python SDK

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/hxtpy.svg)](https://pypi.org/project/hxtpy/)

## Installation

```bash
pip install hxtpy
```

With MQTT transport support:

```bash
pip install hxtpy[mqtt]
```

With development dependencies:

```bash
pip install hxtpy[all]
```

## Quick Start

### Async Client

```python
import asyncio
from hxtp.client import HxTPClient

async def main():
    client = HxTPClient(
        url="wss://api.hestialabs.in/ws",
        tenant_id="your-tenant-uuid",
        device_id="your-device-uuid",
        secret="64-char-hex-secret",
    )

    await client.connect()

    @client.on_message
    def handle(msg):
        print(f"Received: {msg}")

    response = await client.send_command({
        "action": "set_pin",
        "params": {"pin": 13, "value": 1},
    })
    print(f"Sent: {response}")

    await client.disconnect()

asyncio.run(main())
```

### Sync Client

```python
from hxtp.client import SyncHxTPClient

client = SyncHxTPClient(
    url="wss://api.hestialabs.in/ws",
    tenant_id="your-tenant-uuid",
    device_id="your-device-uuid",
    secret="64-char-hex-secret",
)

client.connect()
response = client.send_command({
    "action": "set_pin",
    "params": {"pin": 13, "value": 1},
})
client.disconnect()
```

### Core Protocol Engine (No Networking)

```python
from hxtp.core import build_canonical, parse_canonical, validate_canonical
from hxtp.crypto import sign_hmac_sha256, sha256_hex, generate_nonce

# Build canonical string
canonical = build_canonical({
    "version": "HxTP/3.0",
    "message_type": "command",
    "device_id": "device-uuid",
    "tenant_id": "tenant-uuid",
    "timestamp": 1708444800,
    "message_id": "msg-uuid",
    "nonce": "random-hex-nonce",
})

# Sign
secret = bytes.fromhex("a" * 64)
signature = sign_hmac_sha256(secret, canonical)

# Verify
from hxtp.crypto import constant_time_equal
expected = sign_hmac_sha256(secret, canonical)
assert constant_time_equal(signature, expected)
```

### Validation Pipeline

```python
from hxtp.validation import validate_message

result = validate_message(msg, secret_hex="your-secret", now_ms=None)
if not result.ok:
    print(f"Rejected: {result.code} — {result.reason}")
```

## License

MIT License — Copyright (c) 2026 Hestia Labs
