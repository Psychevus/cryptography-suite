import pytest

from cryptography_suite.core.operations import RetryPolicy, retry_with_backoff, run_command
import cryptography_suite.cli as cli


def test_run_command_raises_on_nonzero_exit():
    with pytest.raises(RuntimeError):
        run_command(["python", "-c", "import sys; sys.exit(3)"], timeout_s=5, operation_name="test_cmd")


def test_retry_with_backoff_recovers():
    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise RuntimeError("boom")
        return "ok"

    out = retry_with_backoff(
        flaky,
        policy=RetryPolicy(max_attempts=3, base_delay_s=0.0, max_delay_s=0.0, jitter_s=0.0),
        logger_name="cryptography_suite.tests",
        operation_name="flaky_op",
    )
    assert out == "ok"
    assert attempts["n"] == 2


def test_keystore_migrate_requires_apply():
    with pytest.raises(ValueError, match="--apply"):
        cli.keystore_cli(["migrate", "--from", "a", "--to", "b"])
