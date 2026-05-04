import json
import unittest
from typing import Any, Protocol, cast

from cryptography_suite.pipeline import (
    AESGCMEncrypt,
    CryptoModule,
    MLKEMDecrypt,
    MLKEMEncrypt,
    Pipeline,
)


class Upper(Protocol):
    def run(self, data: bytes) -> bytes: ...


class UpperCase:
    def run(self, data: bytes) -> bytes:
        return data.upper()

    def to_proverif(self) -> str:
        return "uppercase"

    def to_tamarin(self) -> str:
        return "uppercase"


class Reverse:
    def run(self, data: bytes) -> bytes:
        return data[::-1]

    def to_proverif(self) -> str:
        return "reverse"

    def to_tamarin(self) -> str:
        return "reverse"


class TestPipeline(unittest.TestCase):
    def test_sequential_pipeline(self):
        p: Pipeline[Any, Any] = Pipeline()
        p = p >> UpperCase() >> Reverse()
        result = p.run(b"abc")
        self.assertEqual(result, b"CBA")

    def test_describe(self):
        p: Pipeline[Any, Any] = Pipeline()
        p = p >> UpperCase()
        desc = p.describe()
        self.assertEqual(desc[0]["module"], "UpperCase")

    def test_describe_and_json_redact_sensitive_values(self):
        p = Pipeline() >> AESGCMEncrypt(password="pw", kdf="argon2")

        desc = p.describe()
        json_blob = p.to_json()
        parsed = json.loads(json_blob)

        self.assertNotIn("pw", str(desc))
        self.assertNotIn("pw", json_blob)
        self.assertEqual(desc[0]["params"]["password"], "***REDACTED***")
        self.assertEqual(parsed[0]["params"]["password"], "***REDACTED***")
        self.assertEqual(desc[0]["module"], "AESGCMEncrypt")
        self.assertEqual(desc[0]["params"]["kdf"], "argon2")

    def test_ml_kem_describe_and_json_redact_key_material(self):
        public_key = b"MLKEM_PUBLIC_KEY_MARKER"
        private_key = b"MLKEM_PRIVATE_KEY_MARKER"
        shared_secret_like = "DUMMY_KEM_SHARED_SECRET_MARKER"
        p: Pipeline[Any, Any] = Pipeline(
            [
                cast(CryptoModule[Any, Any], MLKEMEncrypt(public_key=public_key)),
                cast(CryptoModule[Any, Any], MLKEMDecrypt(private_key=private_key)),
            ]
        )

        desc = p.describe()
        json_blob = p.to_json()
        combined = f"{desc} {json_blob}"

        self.assertEqual(desc[0]["params"]["public_key"], "***REDACTED***")
        self.assertEqual(desc[1]["params"]["private_key"], "***REDACTED***")
        self.assertNotIn(public_key.decode(), combined)
        self.assertNotIn(private_key.decode(), combined)
        self.assertNotIn(shared_secret_like, combined)


if __name__ == "__main__":
    unittest.main()
