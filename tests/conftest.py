import sys
from pathlib import Path

# Ensure package root is importable when running tests without installing the package
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
