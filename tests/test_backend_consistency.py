import pathlib
import re

ALLOWED = {
    pathlib.Path("cryptography_suite/experimental/salsa20.py"),
    pathlib.Path("examples/vulnerable.py"),
}

PATTERN = re.compile(r"(^|\n)\s*(from|import) Crypto(\.|\s)")


def test_no_pycryptodome_imports():
    for path in pathlib.Path("cryptography_suite").rglob("*.py"):
        if path in ALLOWED:
            continue
        text = path.read_text()
        assert not PATTERN.search(text)
