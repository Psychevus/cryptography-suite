from __future__ import annotations

import os
from pathlib import Path

import pytest

from cryptography_suite import ErrorCode
from cryptography_suite.streaming.atomic import (
    AtomicFileSink,
    AtomicSinkError,
    AtomicSinkOptions,
)


@pytest.mark.parametrize(
    "destination",
    [
        "",
        ".",
        "..",
        "../escape",
        "parent/../escape",
        "/absolute",
        "C:\\absolute",
        "\\\\server\\share\\file",
        "nul\x00name",
        "repeated//separator",
    ],
)
def test_rejects_invalid_destination_grammar(
    tmp_path: Path,
    destination: str,
) -> None:
    with pytest.raises(ValueError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination=destination,
        )


def test_rejects_platform_alternate_separator(tmp_path: Path) -> None:
    destination = "parent/file" if os.name == "nt" else "parent\\file"
    with pytest.raises(ValueError, match="alternate separator"):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination=destination,
        )


def test_rejects_relative_or_missing_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="explicit absolute"):
        AtomicFileSink(output_root="relative", relative_destination="result.bin")
    missing = tmp_path / "missing"
    with pytest.raises(AtomicSinkError) as captured:
        AtomicFileSink(
            output_root=missing.absolute(),
            relative_destination="result.bin",
        )
    assert captured.value.code is ErrorCode.IO_FAILED


def test_valid_nested_unicode_path(tmp_path: Path) -> None:
    parent = tmp_path / "داده"
    parent.mkdir()
    destination_name = "résultat.bin"
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination=os.path.join(parent.name, destination_name),
    )
    sink.write(b"unicode")
    sink.commit()
    assert (parent / destination_name).read_bytes() == b"unicode"


def test_missing_parent_and_parent_file_fail_without_staging(tmp_path: Path) -> None:
    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination=os.path.join("missing", "result.bin"),
        )
    parent_file = tmp_path / "parent"
    parent_file.write_bytes(b"not-directory")
    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination=os.path.join("parent", "result.bin"),
        )
    assert [path.name for path in tmp_path.iterdir()] == ["parent"]


def _create_symlink_or_skip(target: Path, link: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(
            "symlink creation privilege unavailable; reparse/symlink rejection "
            "is covered by the Phase 4A platform matrix: "
            f"{type(error).__name__}"
        )


def test_rejects_parent_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-parent"
    _create_symlink_or_skip(target, link, directory=True)

    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination=os.path.join("linked-parent", "result.bin"),
        )
    assert list(target.iterdir()) == []


def test_rejects_destination_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    link = tmp_path / "result.bin"
    _create_symlink_or_skip(target, link, directory=False)

    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="result.bin",
            options=AtomicSinkOptions(
                policy_allows_overwrite=True,
                overwrite_requested=True,
            ),
        )
    assert target.read_bytes() == b"target"


def test_rejects_destination_directory(tmp_path: Path) -> None:
    (tmp_path / "result.bin").mkdir()
    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="result.bin",
            options=AtomicSinkOptions(
                policy_allows_overwrite=True,
                overwrite_requested=True,
            ),
        )


def test_rejects_destination_with_multiple_hardlinks(tmp_path: Path) -> None:
    destination = tmp_path / "result.bin"
    destination.write_bytes(b"original")
    os.link(destination, tmp_path / "alias.bin")
    with pytest.raises(AtomicSinkError):
        AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="result.bin",
            options=AtomicSinkOptions(
                policy_allows_overwrite=True,
                overwrite_requested=True,
            ),
        )
    assert destination.read_bytes() == b"original"


def test_rejects_source_destination_identity_and_preserves_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    with source.open("rb") as source_stream:
        with pytest.raises(AtomicSinkError):
            AtomicFileSink(
                output_root=tmp_path.absolute(),
                relative_destination="source.bin",
                source_fd=source_stream.fileno(),
                options=AtomicSinkOptions(
                    policy_allows_overwrite=True,
                    overwrite_requested=True,
                ),
            )
        assert not source_stream.closed
    assert source.read_bytes() == b"source"


def test_rejects_source_destination_hardlink_identity(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "result.bin"
    source.write_bytes(b"source")
    os.link(source, destination)
    with source.open("rb") as source_stream:
        with pytest.raises(AtomicSinkError):
            AtomicFileSink(
                output_root=tmp_path.absolute(),
                relative_destination="result.bin",
                source_fd=source_stream.fileno(),
                options=AtomicSinkOptions(
                    policy_allows_overwrite=True,
                    overwrite_requested=True,
                ),
            )
    assert source.read_bytes() == b"source"
    assert destination.read_bytes() == b"source"


def test_destination_appearance_after_staging_is_not_overwritten(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "result.bin"
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
    )
    sink.write(b"staged")
    destination.write_bytes(b"winner")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()
    assert captured.value.code is ErrorCode.OUTPUT_EXISTS
    assert destination.read_bytes() == b"winner"
    sink.abort()
    assert destination.read_bytes() == b"winner"


def test_destination_replacement_after_staging_fails_closed(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "result.bin"
    destination.write_bytes(b"original")
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
        options=AtomicSinkOptions(
            policy_allows_overwrite=True,
            overwrite_requested=True,
        ),
    )
    destination.unlink()
    destination.write_bytes(b"changed")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()
    assert captured.value.code is ErrorCode.IO_FAILED
    assert destination.read_bytes() == b"changed"
    sink.abort()
    assert destination.read_bytes() == b"changed"


def test_overwrite_mode_does_not_replace_destination_that_appears_late(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "result.bin"
    sink = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="result.bin",
        options=AtomicSinkOptions(
            policy_allows_overwrite=True,
            overwrite_requested=True,
        ),
    )
    sink.write(b"staged")
    destination.write_bytes(b"late-winner")

    with pytest.raises(AtomicSinkError) as captured:
        sink.commit()

    assert captured.value.code is ErrorCode.OUTPUT_EXISTS
    assert destination.read_bytes() == b"late-winner"
    sink.abort()
    assert destination.read_bytes() == b"late-winner"


def test_errors_and_repr_never_expose_paths_or_temporary_names(
    tmp_path: Path,
) -> None:
    secret_root = str(tmp_path.absolute())
    destination = "sensitive-customer-name.bin"
    (tmp_path / destination).write_bytes(b"existing")

    with pytest.raises(AtomicSinkError) as captured:
        AtomicFileSink(
            output_root=secret_root,
            relative_destination=destination,
        )
    rendered = f"{captured.value!s} {captured.value!r}"
    assert secret_root not in rendered
    assert destination not in rendered
    assert ".cs4a-" not in rendered


def test_platform_case_behavior_is_native_and_documented(tmp_path: Path) -> None:
    first = AtomicFileSink(
        output_root=tmp_path.absolute(),
        relative_destination="Case.bin",
    )
    first.commit()

    alternate_case_aliases = (tmp_path / "case.bin").exists()
    if alternate_case_aliases:
        with pytest.raises(AtomicSinkError):
            AtomicFileSink(
                output_root=tmp_path.absolute(),
                relative_destination="case.bin",
            )
    else:
        second = AtomicFileSink(
            output_root=tmp_path.absolute(),
            relative_destination="case.bin",
        )
        second.abort()
