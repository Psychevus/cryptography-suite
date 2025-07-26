import unittest
from cryptography_suite.pipeline import Pipeline

class Stub:
    def run(self, data: bytes) -> bytes:
        return data
    def to_proverif(self) -> str:
        return "(* Stub *)"

class TestExport(unittest.TestCase):
    def test_to_proverif(self):
        p = Pipeline() >> Stub()
        p.track_secret("token")
        out = p.to_proverif()
        self.assertIn("Stub", out)
        self.assertIn("token", out)

if __name__ == "__main__":
    unittest.main()
