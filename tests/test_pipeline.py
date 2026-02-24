import unittest
import json

from cryptography_suite.pipeline import AESGCMEncrypt, Pipeline
from typing import Protocol

class Upper(Protocol):
    def run(self, data: bytes) -> bytes:
        ...

class UpperCase:
    def run(self, data: bytes) -> bytes:
        return data.upper()

class Reverse:
    def run(self, data: bytes) -> bytes:
        return data[::-1]

class TestPipeline(unittest.TestCase):
    def test_sequential_pipeline(self):
        p = Pipeline() >> UpperCase() >> Reverse()
        result = p.run(b"abc")
        self.assertEqual(result, b"CBA")

    def test_describe(self):
        p = Pipeline() >> UpperCase()
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

if __name__ == "__main__":
    unittest.main()
