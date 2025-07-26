import unittest

from cryptography_suite.pipeline import Pipeline
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

if __name__ == "__main__":
    unittest.main()
