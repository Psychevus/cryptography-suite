from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cryptography_suite import ErrorCode
from cryptography_suite._internal.filesystem import (
    FilesystemFailureReason,
    FilesystemOperationError,
    StandardFilesystemOS,
)
from cryptography_suite.streaming.atomic import (
    AtomicFileSink,
    AtomicSinkError,
    AtomicSinkOptions,
    AtomicSinkState,
    CommitOutcome,
)


class FaultFilesystem:
    """One-shot fault wrapper around the real platform facade."""

    def __init__(
        self,
        method: str,
        *,
        occurrence: int = 1,
        reason: FilesystemFailureReason = FilesystemFailureReason.IO_FAILED,
        published: bool = False,
        partial_first_write: bool = False,
    ) -> None:
        self.base = StandardFilesystemOS()
        self.method = method
        self.occurrence = occurrence
        self.reason = reason
        self.published = published
        self.partial_first_write = partial_first_write
        self.calls: defaultdict[str, int] = defaultdict(int)

    def __getattr__(self, name: str) -> Any:
        target = getattr(self.base, name)

        def intercepted(*args: Any, **kwargs: Any) -> Any:
            self.calls[name] += 1
            call = self.calls[name]
            if name == "write" and self.partial_first_write and call == 1:
                limited = args[1][:2]
                return target(args[0], limited)
            if name == self.method and call == self.occurrence:
                raise FilesystemOperationError(
                    self.reason,
                    operation=name,
                    published=self.published,
                )
            return target(*args, **kwargs)

        return intercepted


def _sink(tmp_path: Path, filesystem: FaultFilesystem) -> AtomicFileSink:
    return AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
        _filesystem=filesystem,
    )


@pytest.mark.parametrize(
    "method",
    ["capabilities", "open_parent", "create_temporary"],
)
def test_construction_failure_never_stages_or_publishes(
    tmp_path: Path,
    method: str,
) -> None:
    filesystem = FaultFilesystem(method)

    with pytest.raises(AtomicSinkError) as captured:
        _sink(tmp_path, filesystem)

    assert captured.value.code is ErrorCode.IO_FAILED
    assert captured.value.state is AtomicSinkState.FAILED
    assert captured.value.outcome is CommitOutcome.NOT_PUBLISHED
    assert list(tmp_path.iterdir()) == []


def test_unsupported_filesystem_report_fails_before_staging(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem("unused")
    real_capabilities = filesystem.base.capabilities

    def unsupported(root: str) -> Any:
        return replace(
            real_capabilities(root),
            atomic_no_overwrite_publication=False,
        )

    filesystem.capabilities = unsupported  # type: ignore[method-assign]

    with pytest.raises(AtomicSinkError) as captured:
        _sink(tmp_path, filesystem)

    assert captured.value.code is ErrorCode.IO_FAILED
    assert filesystem.calls["create_temporary"] == 0
    assert list(tmp_path.iterdir()) == []


def test_parent_traversal_failure_never_creates_a_temporary(
    tmp_path: Path,
) -> None:
    (tmp_path / "nested").mkdir()
    filesystem = FaultFilesystem(
        "open_parent",
        reason=FilesystemFailureReason.DESTINATION_UNSAFE,
    )

    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination=os.path.join("nested", "result.bin"),
            _filesystem=filesystem,
        )

    assert list((tmp_path / "nested").iterdir()) == []


def test_first_write_failure_is_abortable_without_publication(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem("write")
    sink = _sink(tmp_path, filesystem)

    with pytest.raises(AtomicSinkError) as captured:
        sink.write(b"payload")

    assert captured.value.state is AtomicSinkState.FAILED
    assert captured.value.outcome is CommitOutcome.NOT_PUBLISHED
    sink.abort()
    assert sink.state is AtomicSinkState.ABORTED
    assert list(tmp_path.iterdir()) == []


def test_partial_then_failed_write_tracks_no_completed_chunk(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem(
        "write",
        occurrence=2,
        partial_first_write=True,
    )
    sink = _sink(tmp_path, filesystem)

    with pytest.raises(AtomicSinkError):
        sink.write(b"payload")

    assert sink.bytes_written == 0
    assert sink.state is AtomicSinkState.FAILED
    sink.abort()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("method", "occurrence"),
    [
        ("fsync_file", 1),
        ("revalidate_temporary", 1),
        ("inspect_destination", 2),
        ("publish_no_overwrite", 1),
    ],
)
def test_prepublication_commit_failure_is_explicit_and_abortable(
    tmp_path: Path,
    method: str,
    occurrence: int,
) -> None:
    filesystem = FaultFilesystem(method, occurrence=occurrence)
    sink = _sink(tmp_path, filesystem)
    sink.write(b"payload")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.state is AtomicSinkState.FAILED
    assert captured.value.outcome is CommitOutcome.NOT_PUBLISHED
    assert not (tmp_path / "result.bin").exists()
    sink.abort()
    assert sink.state is AtomicSinkState.ABORTED
    assert list(tmp_path.iterdir()) == []


def test_cross_device_publication_failure_has_no_copy_fallback(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem(
        "publish_no_overwrite",
        reason=FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
    )
    sink = _sink(tmp_path, filesystem)
    sink.write(b"payload")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.code is ErrorCode.IO_FAILED
    assert captured.value.outcome is CommitOutcome.NOT_PUBLISHED
    assert filesystem.calls["publish_no_overwrite"] == 1
    sink.abort()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("method", "occurrence"),
    [
        ("fsync_file", 1),
        ("revalidate_temporary", 1),
        ("inspect_destination", 2),
        ("publish_overwrite", 1),
    ],
)
def test_prepublication_overwrite_failure_preserves_existing_bytes(
    tmp_path: Path,
    method: str,
    occurrence: int,
) -> None:
    destination = tmp_path / "result.bin"
    destination.write_bytes(b"original")
    filesystem = FaultFilesystem(method, occurrence=occurrence)
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
        options=AtomicSinkOptions(
            policy_allows_overwrite=True,
            overwrite_requested=True,
        ),
        _filesystem=filesystem,
    )
    sink.write(b"replacement")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.outcome is CommitOutcome.NOT_PUBLISHED
    assert destination.read_bytes() == b"original"
    sink.abort()
    assert destination.read_bytes() == b"original"


def test_postpublication_durability_failure_reports_uncertainty(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem(
        "fsync_directory",
        reason=FilesystemFailureReason.DURABILITY_FAILED,
        published=True,
    )
    sink = _sink(tmp_path, filesystem)
    sink.write(b"payload")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.state is AtomicSinkState.PUBLICATION_UNCERTAIN
    assert captured.value.outcome is CommitOutcome.PUBLISHED_DURABILITY_UNCERTAIN
    assert (tmp_path / "result.bin").read_bytes() == b"payload"
    sink.abort()
    assert (tmp_path / "result.bin").read_bytes() == b"payload"


@pytest.mark.parametrize("method", ["close_temporary", "close_parent"])
def test_postpublication_close_failure_never_removes_destination(
    tmp_path: Path,
    method: str,
) -> None:
    filesystem = FaultFilesystem(
        method,
        reason=FilesystemFailureReason.CLEANUP_FAILED,
        published=True,
    )
    sink = _sink(tmp_path, filesystem)
    sink.write(b"payload")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.state is AtomicSinkState.CLEANUP_INCOMPLETE
    assert captured.value.outcome is CommitOutcome.CLEANUP_INCOMPLETE
    assert (tmp_path / "result.bin").exists()
    sink.abort()
    assert (tmp_path / "result.bin").read_bytes() == b"payload"


def test_abort_cleanup_failure_can_be_retried_without_publication(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem(
        "unlink_temporary",
        reason=FilesystemFailureReason.CLEANUP_FAILED,
    )
    sink = _sink(tmp_path, filesystem)
    sink.write(b"payload")

    with pytest.raises(AtomicSinkError) as captured:
        sink.abort()

    assert captured.value.state is AtomicSinkState.CLEANUP_INCOMPLETE
    assert not (tmp_path / "result.bin").exists()
    sink.abort()
    assert sink.state is AtomicSinkState.ABORTED
    assert list(tmp_path.iterdir()) == []


def test_owned_temporary_identity_cleanup_failure_is_explicit(
    tmp_path: Path,
) -> None:
    filesystem = FaultFilesystem(
        "unlink_temporary",
        reason=FilesystemFailureReason.IDENTITY_MISMATCH,
    )
    sink = _sink(tmp_path, filesystem)

    with pytest.raises(AtomicSinkError) as captured:
        sink.abort()

    assert captured.value.state is AtomicSinkState.CLEANUP_INCOMPLETE
    assert captured.value.outcome is CommitOutcome.CLEANUP_INCOMPLETE
    sink.abort()
    assert sink.state is AtomicSinkState.ABORTED
    assert list(tmp_path.iterdir()) == []


def test_interrupted_write_is_retried(tmp_path: Path) -> None:
    filesystem = FaultFilesystem("unused")
    base_write = filesystem.base.write
    interrupted = False

    def write_once_interrupted(temporary: Any, data: memoryview) -> int:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise InterruptedError
        return base_write(temporary, data)

    filesystem.write = write_once_interrupted  # type: ignore[method-assign]
    sink = _sink(tmp_path, filesystem)
    sink.write(b"payload")
    sink.commit()

    assert interrupted is True
    assert (tmp_path / "result.bin").read_bytes() == b"payload"


def test_zero_progress_write_fails_closed(tmp_path: Path) -> None:
    filesystem = FaultFilesystem("unused")
    filesystem.write = lambda temporary, data: 0  # type: ignore[method-assign]
    sink = _sink(tmp_path, filesystem)

    with pytest.raises(AtomicSinkError):
        sink.write(b"payload")

    sink.abort()
    assert list(tmp_path.iterdir()) == []


def test_abort_does_not_touch_source_handle_or_source_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    with source.open("rb") as source_stream:
        sink = AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="result.bin",
            source_fd=source_stream.fileno(),
        )
        sink.write(b"staged")
        sink.abort()
        assert not source_stream.closed
        assert source_stream.read() == b"source"
    assert source.read_bytes() == b"source"
    assert not (tmp_path / "result.bin").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX namespace replacement test")
def test_replaced_temporary_name_is_not_deleted_as_owned(tmp_path: Path) -> None:
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
    )
    temporary_name = sink._temporary.name  # type: ignore[union-attr]
    temporary_path = tmp_path / temporary_name
    temporary_path.unlink()
    temporary_path.write_bytes(b"attacker")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.state is AtomicSinkState.FAILED
    with pytest.raises(AtomicSinkError):
        sink.abort()
    assert temporary_path.read_bytes() == b"attacker"
    assert not (tmp_path / "result.bin").exists()
