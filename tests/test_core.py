import unittest

from hxtp_py.core.canonical import (
    build_canonical,
    canonical_json,
)
from hxtp_py.core.constants import PROTOCOL_VERSION


class TestCore(unittest.TestCase):
    def test_canonical_json_determinism(self) -> None:
        msg = {"z": 1, "a": 2, "protocol": "hxtp/3.0"}
        # Keys must be sorted: "a" then "protocol" then "z"
        # Numbers must be stringified
        res = canonical_json(msg)
        expected = '{"a":"2","protocol":"hxtp/3.0","z":"1"}'
        self.assertEqual(res, expected)

    def test_canonical_json_number_formatting(self) -> None:
        self.assertEqual(canonical_json({"v": 123}), '{"protocol":"hxtp/3.0","v":"123"}')
        # Match TS toFixed(20) precision for 1.2
        self.assertEqual(
            canonical_json({"v": 1.2}),
            '{"protocol":"hxtp/3.0","v":"1.19999999999999995559"}',
        )
        self.assertEqual(canonical_json({"v": 1.0}), '{"protocol":"hxtp/3.0","v":"1"}')

    def test_build_canonical_success(self) -> None:
        msg = {
            "version": PROTOCOL_VERSION,
            "device_id": "dev-123",
            "tenant_id": "tenant-456",
            "client_id": "client-456",
            "message_id": "msg-789",
            "request_id": "req-000",
            "sequence_number": 1,
            "timestamp": 1713984000,
            "nonce": "abc",
            "message_type": "command",
            "payload_hash": "hash123",
        }
        canonical = build_canonical(msg)
        expected = (
            f"{PROTOCOL_VERSION}|dev-123|tenant-456|client-456|"
            "msg-789|req-000|1|1713984000|abc|command|hash123"
        )
        self.assertEqual(canonical, expected)

    def test_crypto_engine(self) -> None:
        from hxtp_py.crypto.engine import (
            generate_nonce,
            get_public_key,
            sha256_hex,
            sign_ed25519,
            verify_ed25519,
        )

        secret = b"a" * 32
        data = "hello"

        # Sign
        signature = sign_ed25519(secret, data)
        self.assertEqual(len(signature), 128)

        # Verify with derived public key
        public_key = get_public_key(secret)
        self.assertTrue(verify_ed25519(public_key, data, signature))

        # Hash
        h = sha256_hex(data)
        self.assertEqual(len(h), 64)
        self.assertEqual(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

        # Nonce
        n = generate_nonce(16)
        self.assertEqual(len(n), 32)

    def test_validation_pipeline(self) -> None:
        from hxtp_py.core.envelope import build_envelope
        from hxtp_py.crypto.engine import get_public_key
        from hxtp_py.validation.pipeline import validate_message

        private_key_bytes = b"a" * 32
        private_key = private_key_bytes.hex()
        public_key = get_public_key(private_key_bytes).hex()

        # build_envelope is a factory that takes individual fields
        envelope = build_envelope(
            private_key_hex=private_key,
            device_id="dev-123",
            tenant_id="tenant-456",
            message_type="command",
            params={"action": "test"},
            client_id="client-789",
            sequence=1,
        )

        # Validate the resulting envelope
        result = validate_message(envelope, public_key_hex=public_key)
        self.assertTrue(result.ok)

        # Test version mismatch by tampering with the envelope
        envelope["version"] = "HxTP/0.1"
        result = validate_message(envelope, public_key_hex=public_key)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "VERSION_MISMATCH")


if __name__ == "__main__":
    unittest.main()
