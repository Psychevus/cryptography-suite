from cryptography_suite import __all__ as core_all
try:
    from cryptography_suite.experimental import __all__ as experimental_all
except ImportError:  # pragma: no cover - experimental disabled
    experimental_all = []
from cryptography_suite.legacy import __all__ as legacy_all


def test_no_experimental_or_legacy_in_core() -> None:
    """Ensure the recommended namespace stays minimal."""

    overlap = set(core_all) & (set(experimental_all) | set(legacy_all))
    assert not overlap, f"Unexpected names leaked into core API: {sorted(overlap)}"

