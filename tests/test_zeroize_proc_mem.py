import ctypes
import os
import sys
import unittest
from pathlib import Path

# Ensure the ``src`` directory is on ``sys.path`` so the ``crypto_suite``
# package can be imported during testing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crypto_suite.utils.zeroize import secure_zero


class TestProcMemZeroize(unittest.TestCase):
    @unittest.skipIf(os.getenv("CI"), "skipping /proc memory test on CI")
    def test_proc_mem_cleared(self):
        secret = bytearray(b"pypy memory wipe")
        addr = ctypes.addressof(ctypes.c_char.from_buffer(secret))
        secure_zero(secret)
        try:
            with open(f"/proc/{os.getpid()}/mem", "rb", buffering=0) as mem:
                mem.seek(addr)
                dump = mem.read(len(secret))
        except OSError as exc:  # pragma: no cover - platform dependent
            self.skipTest(f"unable to read process memory: {exc}")
        self.assertEqual(dump, b"\x00" * len(secret))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
