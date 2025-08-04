import os
import sys
from pathlib import Path

import pytest

# Ensure src is importable for crypto_suite package
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "experimental: mark test as requiring EXPERIMENTAL=1 to run"
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    if "experimental" in item.keywords and os.getenv("EXPERIMENTAL") != "1":
        pytest.skip("experimental features disabled")
