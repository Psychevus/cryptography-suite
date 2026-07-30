from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cryptography_suite import ErrorCode
from cryptography_suite.streaming import TransactionalSink
from cryptography_suite.streaming.atomic import (
    AtomicFileSink,
    AtomicSinkError,
    AtomicSinkOptions,
    AtomicSinkState,
    CommitOutcome,
)


def _relative(*components: str) -> str:
    return os.path.join(*components)


def test_stage_is_invisible_until_commit_and_has_secure_final_mode(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "nested"
    parent.mkdir()
    destination = parent / "result.bin"
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination=_relative("nested", "result.bin"),
    )

    assert isinstance(sink, TransactionalSink)
    assert sink.state.value == AtomicSinkState.OPEN.value
    assert sink.outcome.value == CommitOutcome.NOT_PUBLISHED.value
    assert not destination.exists()
    sink.write(b"first")
    sink.write(b"")
    sink.write(b"-second")
    assert not destination.exists()

    sink.commit()

    assert destination.read_bytes() == b"first-second"
    assert sink.state is AtomicSinkState.COMMITTED
    assert sink.outcome is CommitOutcome.PUBLISHED
    assert sink.bytes_written == len(b"first-second")
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_abort_is_idempotent_and_never_publishes(tmp_path: Path) -> None:
    destination = tmp_path / "result.bin"
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
    )
    sink.write(b"staged")

    sink.abort()
    sink.abort()

    assert sink.state is AtomicSinkState.ABORTED
    assert sink.outcome is CommitOutcome.NOT_PUBLISHED
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_abort_after_commit_does_not_remove_destination(tmp_path: Path) -> None:
    destination = tmp_path / "result.bin"
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
    )
    sink.write(b"committed")
    sink.commit()

    sink.abort()

    assert destination.read_bytes() == b"committed"
    assert sink.state is AtomicSinkState.COMMITTED


def test_context_manager_aborts_without_commit(tmp_path: Path) -> None:
    with AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
    ) as sink:
        sink.write(b"staged")

    assert sink.state is AtomicSinkState.ABORTED
    assert list(tmp_path.iterdir()) == []


def test_write_bounds_and_type_are_deterministic(tmp_path: Path) -> None:
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
        options=AtomicSinkOptions(max_write_size=4, max_total_bytes=6),
    )
    sink.write(b"1234")
    with pytest.raises(AtomicSinkError) as chunk_error:
        sink.write(b"12345")
    assert chunk_error.value.code is ErrorCode.LIMIT_EXCEEDED
    with pytest.raises(AtomicSinkError) as total_error:
        sink.write(b"789")
    assert total_error.value.code is ErrorCode.LIMIT_EXCEEDED
    with pytest.raises(TypeError):
        sink.write(bytearray(b"x"))
    assert sink.state is AtomicSinkState.OPEN
    sink.abort()


@pytest.mark.parametrize(
    ("field", "value", "exception_type"),
    [
        ("max_write_size", True, TypeError),
        ("max_write_size", 0, ValueError),
        ("max_write_size", 4 * 1024 * 1024 + 1, ValueError),
        ("max_total_bytes", False, TypeError),
        ("max_total_bytes", 0, ValueError),
        ("max_total_bytes", (1 << 40) + 1, ValueError),
        ("policy_allows_overwrite", 1, TypeError),
        ("overwrite_requested", 1, TypeError),
    ],
)
def test_options_reject_invalid_values(
    field: str,
    value: object,
    exception_type: type[Exception],
) -> None:
    arguments: dict[str, object] = {
        "max_write_size": 1024,
        "max_total_bytes": 2048,
        "policy_allows_overwrite": False,
        "overwrite_requested": False,
    }
    arguments[field] = value
    with pytest.raises(exception_type):
        AtomicSinkOptions(**arguments)  # type: ignore[arg-type]


def test_options_reject_write_bound_above_total_bound() -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        AtomicSinkOptions(max_write_size=2, max_total_bytes=1)


@pytest.mark.parametrize(
    ("policy_allows", "requested"),
    [(False, False), (True, False), (False, True)],
)
def test_overwrite_requires_both_authorization_gates(
    tmp_path: Path,
    policy_allows: bool,
    requested: bool,
) -> None:
    destination = tmp_path / "result.bin"
    destination.write_bytes(b"original")
    with pytest.raises(AtomicSinkError) as captured:
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="result.bin",
            options=AtomicSinkOptions(
                policy_allows_overwrite=policy_allows,
                overwrite_requested=requested,
            ),
        )
    assert captured.value.code is ErrorCode.OUTPUT_EXISTS
    assert destination.read_bytes() == b"original"


def test_dual_authorized_overwrite_replaces_without_inheriting_mode(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "result.bin"
    destination.write_bytes(b"original")
    if os.name == "posix":
        destination.chmod(0o666)
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
        options=AtomicSinkOptions(
            policy_allows_overwrite=True,
            overwrite_requested=True,
        ),
    )
    sink.write(b"replacement")
    sink.commit()

    assert destination.read_bytes() == b"replacement"
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_state_rejects_repeated_commit_and_use_after_terminal_state(
    tmp_path: Path,
) -> None:
    committed = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="committed.bin",
    )
    committed.commit()
    with pytest.raises(AtomicSinkError) as second_commit:
        committed.commit()
    assert second_commit.value.code is ErrorCode.INTERNAL_ERROR
    with pytest.raises(AtomicSinkError):
        committed.write(b"x")

    aborted = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="aborted.bin",
    )
    aborted.abort()
    with pytest.raises(AtomicSinkError):
        aborted.commit()
    with pytest.raises(AtomicSinkError):
        aborted.write(b"x")


def test_capability_report_names_atomic_primitives(tmp_path: Path) -> None:
    capabilities = AtomicFileSink.capabilities(tmp_path.absolute())

    assert capabilities.fully_supported is True
    assert capabilities.atomic_no_overwrite_publication is True
    assert capabilities.atomic_replacement is True
    assert capabilities.file_fsync is True
    assert capabilities.directory_durability is True
    assert "rename" in capabilities.overwrite_primitive.lower()


@pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX mode guarantee",
)
def test_permissive_umask_cannot_weaken_owner_only_mode(tmp_path: Path) -> None:
    previous = os.umask(0)
    try:
        sink = AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="result.bin",
        )
        temporary = tmp_path / sink._temporary.name  # type: ignore[union-attr]
        assert stat.S_IMODE(temporary.stat().st_mode) == 0o600
        sink.write(b"payload")
        sink.commit()
    finally:
        os.umask(previous)

    assert stat.S_IMODE((tmp_path / "result.bin").stat().st_mode) == 0o600


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows owner-only DACL guarantee",
)
def test_windows_staging_dacl_matches_claim(tmp_path: Path) -> None:
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
    )
    temporary = sink._temporary
    assert temporary is not None
    handle = temporary.windows_handle
    assert handle is not None
    assert sink._filesystem._windows_has_owner_only_dacl(handle)  # type: ignore[attr-defined]
    sink.abort()
