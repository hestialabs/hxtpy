# HXTP Python SDK

**Official HxTP/3.0 Python SDK** — Protocol reference engine, AI integration
layer, automation glue, provisioning toolkit, and security audit module.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/hxtp.svg)](https://pypi.org/project/hxtp/)

## Installation

```bash
pip install hxtp
```

With MQTT transport support:

```bash
pip install hxtp[mqtt]
```

With development dependencies:

```bash
pip install hxtp[all]
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

## Architecture

```
hxtp/
  __init__.py          # Public API surface
  core/                # Pure protocol engine (no networking)
    canonical.py       # FROZEN canonical string builder
    envelope.py        # Signed envelope constructor
    nonce.py           # Nonce generation + replay cache
    signing.py         # HMAC-SHA256 sign/verify
    topics.py          # MQTT topic builder/parser
    constants.py       # Protocol constants (FROZEN)
  crypto/              # Cryptographic primitives
    engine.py          # SHA256, HMAC-SHA256, constant-time compare
  validation/          # 7-step validation pipeline
    pipeline.py        # Full pipeline
    errors.py          # Protocol error exceptions
  transport/           # Pluggable transport layer
    interface.py       # Abstract transport
    websocket.py       # WebSocket transport
  client/              # High-level client API
    async_client.py    # Async-first client
    sync_client.py     # Sync wrapper
    types.py           # Client types
  tools/               # AI & automation utilities
    simulator.py       # Device/fleet simulator
    test_vectors.py    # Deterministic test vector exporter
    fuzzer.py          # Message fuzz tester
```

## Security

- HMAC-SHA256 signatures (no weak hashes)
- SHA-256 payload hashing
- Constant-time signature comparison
- Cryptographic nonce generation (secrets module)
- 7-step fail-closed validation pipeline
- Dual-key rotation support
- No insecure mode, no plaintext mode, no bypass

## License

MIT License — Copyright (c) 2026 Hestia Labs
