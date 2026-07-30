"""Internal failure-atomic filesystem sink.

This module is intentionally absent from public ``streaming.__all__``.
"""

from __future__ import annotations

import ntpath
import os
import sys
import threading
from dataclasses import dataclass
from enum import Enum
from types import TracebackType
from typing import Final

from .._internal.filesystem import (
    DestinationInfo,
    DestinationLease,
    FileIdentity,
    FilesystemCapabilities,
    FilesystemFailureReason,
    FilesystemOperationError,
    FilesystemOS,
    OwnedTemporary,
    ParentDirectory,
    StandardFilesystemOS,
)
from ..errors import CryptographySuiteError, ErrorCode

_HARD_MAX_WRITE_SIZE: Final = 4 * 1024 * 1024
_HARD_MAX_TOTAL_BYTES: Final = 1 << 40
_DEFAULT_MAX_WRITE_SIZE: Final = 1024 * 1024
_DEFAULT_MAX_TOTAL_BYTES: Final = 1024 * 1024 * 1024
_WINDOWS_INVALID_CHARACTERS: Final = frozenset('<>:"|?*')
_WINDOWS_RESERVED_BASENAMES: Final = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)


class AtomicSinkState(str, Enum):
    OPEN = "open"
    PUBLISHING = "publishing"
    COMMITTED = "committed"
    ABORTED = "aborted"
    FAILED = "failed"
    PUBLICATION_UNCERTAIN = "publication_uncertain"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"


class CommitOutcome(str, Enum):
    NOT_PUBLISHED = "not_published"
    PUBLISHED = "published"
    PUBLISHED_DURABILITY_UNCERTAIN = "published_durability_uncertain"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"


@dataclass(frozen=True)
class AtomicSinkOptions:
    """Internal result of a future policy decision."""

    max_write_size: int = _DEFAULT_MAX_WRITE_SIZE
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES
    policy_allows_overwrite: bool = False
    overwrite_requested: bool = False

    def __post_init__(self) -> None:
        _validate_bound(
            self.max_write_size,
            name="max_write_size",
            hard_maximum=_HARD_MAX_WRITE_SIZE,
        )
        _validate_bound(
            self.max_total_bytes,
            name="max_total_bytes",
            hard_maximum=_HARD_MAX_TOTAL_BYTES,
        )
        if self.max_write_size > self.max_total_bytes:
            raise ValueError("max_write_size must not exceed max_total_bytes")
        if type(self.policy_allows_overwrite) is not bool:
            raise TypeError("policy_allows_overwrite must be bool")
        if type(self.overwrite_requested) is not bool:
            raise TypeError("overwrite_requested must be bool")

    @property
    def overwrite_enabled(self) -> bool:
        return self.policy_allows_overwrite and self.overwrite_requested


class AtomicSinkError(CryptographySuiteError):
    """Typed nondisclosing internal filesystem transaction failure."""

    def __init__(
        self,
        code: ErrorCode,
        *,
        state: AtomicSinkState,
        outcome: CommitOutcome,
    ) -> None:
        if code not in {
            ErrorCode.IO_FAILED,
            ErrorCode.OUTPUT_EXISTS,
            ErrorCode.LIMIT_EXCEEDED,
            ErrorCode.INTERNAL_ERROR,
        }:
            raise ValueError("unsupported atomic sink error code")
        self._state = state
        self._outcome = outcome
        super().__init__(code)

    @property
    def state(self) -> AtomicSinkState:
        return self._state

    @property
    def outcome(self) -> CommitOutcome:
        return self._outcome


def _validate_bound(value: int, *, name: str, hard_maximum: int) -> None:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if not 1 <= value <= hard_maximum:
        raise ValueError(f"{name} is outside the internal safety bounds")


def _path_string(value: os.PathLike[str] | str, *, field: str) -> str:
    try:
        path = os.fspath(value)
    except TypeError:
        raise TypeError(f"{field} must be a text path") from None
    if not isinstance(path, str):
        raise TypeError(f"{field} must be a text path")
    if "\x00" in path:
        raise ValueError(f"{field} is invalid")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in path):
        raise ValueError(f"{field} is invalid")
    return path


def _validate_root(value: os.PathLike[str] | str) -> str:
    root = _path_string(value, field="output_root")
    if not root or not os.path.isabs(root):
        raise ValueError("output_root must be an explicit absolute path")
    if os.name == "nt" and root.startswith(
        ("\\\\", "//", "\\\\?\\", "\\\\.\\", "//?/")
    ):
        raise ValueError("output_root uses an unsupported anchor")
    return root


def _validate_relative_destination(
    value: os.PathLike[str] | str,
) -> tuple[tuple[str, ...], str]:
    destination = _path_string(value, field="relative_destination")
    if not destination:
        raise ValueError("relative_destination must not be empty")
    drive, _ = ntpath.splitdrive(destination)
    if drive or destination.startswith(("/", "\\")):
        raise ValueError("relative_destination must be unanchored")

    if os.name == "nt":
        if "/" in destination:
            raise ValueError("relative_destination uses an alternate separator")
        separator = "\\"
    else:
        if "\\" in destination:
            raise ValueError("relative_destination uses an alternate separator")
        separator = "/"

    components = destination.split(separator)
    if any(not component for component in components):
        raise ValueError("relative_destination contains an empty component")
    for component in components:
        if component in {".", ".."}:
            raise ValueError("relative_destination contains a traversal component")
        _validate_component(component)
    return tuple(components[:-1]), components[-1]


def _validate_component(component: str) -> None:
    if os.name != "nt":
        try:
            component.encode(sys.getfilesystemencoding(), "strict")
        except UnicodeError:
            raise ValueError(
                "relative_destination contains an invalid component"
            ) from None
        return

    if component.endswith((" ", ".")):
        raise ValueError("relative_destination contains an invalid Windows name")
    if any(
        character in _WINDOWS_INVALID_CHARACTERS or ord(character) < 32
        for character in component
    ):
        raise ValueError("relative_destination contains an invalid Windows name")
    basename = component.split(".", 1)[0].upper()
    if basename in _WINDOWS_RESERVED_BASENAMES:
        raise ValueError("relative_destination contains a reserved Windows name")


def _filesystem_code(error: FilesystemOperationError) -> ErrorCode:
    if error.reason is FilesystemFailureReason.DESTINATION_EXISTS:
        return ErrorCode.OUTPUT_EXISTS
    return ErrorCode.IO_FAILED


class AtomicFileSink:
    """Private filesystem-backed implementation of ``TransactionalSink``."""

    def __init__(
        self,
        *,
        output_root: os.PathLike[str] | str,
        relative_destination: os.PathLike[str] | str,
        options: AtomicSinkOptions | None = None,
        source_fd: int | None = None,
        _filesystem: FilesystemOS | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._filesystem = (
            StandardFilesystemOS() if _filesystem is None else _filesystem
        )
        self._options = AtomicSinkOptions() if options is None else options
        if not isinstance(self._options, AtomicSinkOptions):
            raise TypeError("options must be AtomicSinkOptions")
        root = _validate_root(output_root)
        parent_components, destination_name = _validate_relative_destination(
            relative_destination
        )

        self._destination_name = destination_name
        self._parent: ParentDirectory | None = None
        self._temporary: OwnedTemporary | None = None
        self._destination_lease: DestinationLease | None = None
        self._source_identity: FileIdentity | None = None
        self._initial_destination_identity: FileIdentity | None = None
        self._initial_destination_present = False
        self._state = AtomicSinkState.FAILED
        self._outcome = CommitOutcome.NOT_PUBLISHED
        self._bytes_written = 0

        try:
            if not self._filesystem.capabilities(root).fully_supported:
                raise FilesystemOperationError(
                    FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
                    operation="capability_check",
                )
            if source_fd is not None:
                self._source_identity = self._filesystem.source_identity(source_fd)
            self._parent = self._filesystem.open_parent(root, parent_components)
            existing = self._filesystem.inspect_destination(
                self._parent,
                self._destination_name,
            )
            self._validate_destination(existing)
            if existing is not None:
                self._initial_destination_present = True
                self._initial_destination_identity = existing.identity
                self._destination_lease = self._filesystem.retain_destination(
                    self._parent,
                    self._destination_name,
                )
                if (
                    self._destination_lease is None
                    or self._destination_lease.info != existing
                ):
                    raise FilesystemOperationError(
                        FilesystemFailureReason.IDENTITY_MISMATCH,
                        operation="destination_retain",
                    )
            self._temporary = self._filesystem.create_temporary(self._parent)
        except FilesystemOperationError as error:
            self._construction_cleanup()
            raise AtomicSinkError(
                _filesystem_code(error),
                state=AtomicSinkState.FAILED,
                outcome=CommitOutcome.NOT_PUBLISHED,
            ) from None
        except BaseException:
            self._construction_cleanup()
            raise
        self._state = AtomicSinkState.OPEN

    @property
    def max_write_size(self) -> int:
        return self._options.max_write_size

    @property
    def max_total_bytes(self) -> int:
        return self._options.max_total_bytes

    @property
    def state(self) -> AtomicSinkState:
        return self._state

    @property
    def outcome(self) -> CommitOutcome:
        return self._outcome

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @classmethod
    def capabilities(
        cls,
        output_root: os.PathLike[str] | str,
    ) -> FilesystemCapabilities:
        root = _validate_root(output_root)
        return StandardFilesystemOS().capabilities(root)

    def write(self, chunk: bytes) -> None:
        with self._lock:
            self._require_state(AtomicSinkState.OPEN)
            if type(chunk) is not bytes:
                raise TypeError("chunk must be bytes")
            if not chunk:
                return
            if len(chunk) > self._options.max_write_size:
                raise self._limit_error()
            remaining_capacity = self._options.max_total_bytes - self._bytes_written
            if len(chunk) > remaining_capacity:
                raise self._limit_error()

            temporary = self._required_temporary()
            view = memoryview(chunk)
            offset = 0
            try:
                while offset < len(view):
                    try:
                        written = self._filesystem.write(temporary, view[offset:])
                    except InterruptedError:
                        continue
                    if not 0 < written <= len(view) - offset:
                        raise FilesystemOperationError(
                            FilesystemFailureReason.IO_FAILED,
                            operation="write",
                        )
                    offset += written
            except FilesystemOperationError as error:
                self._state = AtomicSinkState.FAILED
                raise AtomicSinkError(
                    _filesystem_code(error),
                    state=self._state,
                    outcome=self._outcome,
                ) from None
            finally:
                view.release()
            self._bytes_written += len(chunk)

    def commit(self) -> None:
        with self._lock:
            self._require_state(AtomicSinkState.OPEN)
            self._state = AtomicSinkState.PUBLISHING
            parent = self._required_parent()
            temporary = self._required_temporary()
            try:
                self._filesystem.fsync_file(temporary)
                self._filesystem.revalidate_temporary(parent, temporary)
                existing = self._filesystem.inspect_destination(
                    parent,
                    self._destination_name,
                )
                self._validate_destination(existing)
                self._validate_observed_destination(existing)
                self._validate_retained_destination(existing)
                if existing is None:
                    self._filesystem.publish_no_overwrite(
                        parent,
                        temporary,
                        self._destination_name,
                    )
                else:
                    self._filesystem.publish_overwrite(
                        parent,
                        temporary,
                        self._destination_name,
                    )
                self._outcome = CommitOutcome.PUBLISHED
                self._filesystem.fsync_directory(parent, temporary)
                self._close_all()
            except FilesystemOperationError as error:
                self._handle_commit_failure(error)
            self._state = AtomicSinkState.COMMITTED

    def abort(self) -> None:
        with self._lock:
            if self._state in {AtomicSinkState.ABORTED, AtomicSinkState.COMMITTED}:
                return

            cleanup_error: FilesystemOperationError | None = None
            temporary = self._temporary
            parent = self._parent
            published = (
                temporary.published
                if temporary is not None
                else self._outcome
                in {
                    CommitOutcome.PUBLISHED,
                    CommitOutcome.PUBLISHED_DURABILITY_UNCERTAIN,
                }
            )

            if temporary is not None:
                try:
                    self._filesystem.close_temporary(temporary)
                except FilesystemOperationError as error:
                    cleanup_error = error
                if parent is not None and (
                    not published
                    or (
                        self._outcome is CommitOutcome.CLEANUP_INCOMPLETE
                        and temporary.published
                    )
                ):
                    try:
                        self._filesystem.unlink_temporary(parent, temporary)
                    except FilesystemOperationError as error:
                        cleanup_error = error

            if parent is not None and cleanup_error is None:
                lease = self._destination_lease
                if lease is not None:
                    try:
                        self._filesystem.close_destination(lease)
                    except FilesystemOperationError as error:
                        cleanup_error = error

            if parent is not None and cleanup_error is None:
                try:
                    self._filesystem.close_parent(parent)
                except FilesystemOperationError as error:
                    cleanup_error = error

            if cleanup_error is not None:
                self._state = AtomicSinkState.CLEANUP_INCOMPLETE
                self._outcome = CommitOutcome.CLEANUP_INCOMPLETE
                raise AtomicSinkError(
                    ErrorCode.IO_FAILED,
                    state=self._state,
                    outcome=self._outcome,
                ) from None

            if not published:
                self._state = AtomicSinkState.ABORTED

    def __enter__(self) -> AtomicFileSink:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exception_type, exception, traceback
        if self._state is not AtomicSinkState.COMMITTED:
            self.abort()

    def _validate_destination(self, destination: DestinationInfo | None) -> None:
        if destination is None:
            return
        if (
            destination.is_link
            or destination.is_directory
            or destination.link_count != 1
        ):
            raise FilesystemOperationError(
                FilesystemFailureReason.DESTINATION_UNSAFE,
                operation="destination_validation",
            )
        if (
            self._source_identity is not None
            and destination.identity == self._source_identity
        ):
            raise FilesystemOperationError(
                FilesystemFailureReason.SOURCE_DESTINATION_IDENTICAL,
                operation="destination_validation",
            )
        if not self._options.overwrite_enabled:
            raise FilesystemOperationError(
                FilesystemFailureReason.DESTINATION_EXISTS,
                operation="destination_validation",
            )

    def _construction_cleanup(self) -> None:
        temporary = self._temporary
        parent = self._parent
        if temporary is not None:
            try:
                self._filesystem.close_temporary(temporary)
            except FilesystemOperationError:
                pass
            if parent is not None:
                try:
                    self._filesystem.unlink_temporary(parent, temporary)
                except FilesystemOperationError:
                    pass
        if parent is not None:
            lease = self._destination_lease
            if lease is not None:
                try:
                    self._filesystem.close_destination(lease)
                except FilesystemOperationError:
                    pass
            try:
                self._filesystem.close_parent(parent)
            except FilesystemOperationError:
                pass

    def _validate_observed_destination(
        self,
        destination: DestinationInfo | None,
    ) -> None:
        initial = self._initial_destination_identity
        if not self._initial_destination_present:
            if destination is not None:
                raise FilesystemOperationError(
                    FilesystemFailureReason.DESTINATION_EXISTS,
                    operation="destination_revalidation",
                )
            return
        if initial is None or destination is None or destination.identity != initial:
            raise FilesystemOperationError(
                FilesystemFailureReason.IDENTITY_MISMATCH,
                operation="destination_revalidation",
            )

    def _validate_retained_destination(
        self,
        destination: DestinationInfo | None,
    ) -> None:
        lease = self._destination_lease
        if lease is None:
            return
        retained = self._filesystem.revalidate_destination(lease)
        if (
            destination is None
            or retained.identity != lease.info.identity
            or retained.identity != destination.identity
            or retained.is_directory
            or retained.is_link
            or retained.link_count != 1
        ):
            raise FilesystemOperationError(
                FilesystemFailureReason.IDENTITY_MISMATCH,
                operation="destination_revalidation",
            )

    def _close_all(self) -> None:
        temporary = self._required_temporary()
        parent = self._required_parent()
        self._filesystem.close_temporary(temporary)
        lease = self._destination_lease
        if lease is not None:
            self._filesystem.close_destination(lease)
        self._filesystem.close_parent(parent)

    def _handle_commit_failure(self, error: FilesystemOperationError) -> None:
        if error.published or self._required_temporary().published:
            if error.reason is FilesystemFailureReason.DURABILITY_FAILED:
                self._state = AtomicSinkState.PUBLICATION_UNCERTAIN
                self._outcome = CommitOutcome.PUBLISHED_DURABILITY_UNCERTAIN
            else:
                self._state = AtomicSinkState.CLEANUP_INCOMPLETE
                self._outcome = CommitOutcome.CLEANUP_INCOMPLETE
            if self._state is AtomicSinkState.PUBLICATION_UNCERTAIN:
                try:
                    self._close_all()
                except FilesystemOperationError:
                    self._state = AtomicSinkState.CLEANUP_INCOMPLETE
                    self._outcome = CommitOutcome.CLEANUP_INCOMPLETE
        else:
            self._state = AtomicSinkState.FAILED
            self._outcome = CommitOutcome.NOT_PUBLISHED
        raise AtomicSinkError(
            _filesystem_code(error),
            state=self._state,
            outcome=self._outcome,
        ) from None

    def _limit_error(self) -> AtomicSinkError:
        return AtomicSinkError(
            ErrorCode.LIMIT_EXCEEDED,
            state=self._state,
            outcome=self._outcome,
        )

    def _require_state(self, required: AtomicSinkState) -> None:
        if self._state is not required:
            raise AtomicSinkError(
                ErrorCode.INTERNAL_ERROR,
                state=self._state,
                outcome=self._outcome,
            )

    def _required_parent(self) -> ParentDirectory:
        if self._parent is None:
            raise AtomicSinkError(
                ErrorCode.INTERNAL_ERROR,
                state=self._state,
                outcome=self._outcome,
            )
        return self._parent

    def _required_temporary(self) -> OwnedTemporary:
        if self._temporary is None:
            raise AtomicSinkError(
                ErrorCode.INTERNAL_ERROR,
                state=self._state,
                outcome=self._outcome,
            )
        return self._temporary


__all__: list[str] = []
