"""Strict standard-library filesystem facade for transactional publication."""

from __future__ import annotations

import errno
import ntpath
import os
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol, runtime_checkable


class FilesystemFailureReason(str, Enum):
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    CLEANUP_FAILED = "cleanup_failed"
    DESTINATION_EXISTS = "destination_exists"
    DESTINATION_UNSAFE = "destination_unsafe"
    DURABILITY_FAILED = "durability_failed"
    IDENTITY_MISMATCH = "identity_mismatch"
    INVALID_ROOT = "invalid_root"
    IO_FAILED = "io_failed"
    PATH_INVALID = "path_invalid"
    PERMISSION_UNVERIFIED = "permission_unverified"
    SOURCE_DESTINATION_IDENTICAL = "source_destination_identical"


class FilesystemOperationError(Exception):
    """Nondisclosing failure raised by the private OS boundary."""

    def __init__(
        self,
        reason: FilesystemFailureReason,
        *,
        operation: str,
        published: bool = False,
    ) -> None:
        self.reason = reason
        self.operation = operation
        self.published = published
        super().__init__(f"filesystem {operation} failed safely")


@dataclass(frozen=True)
class FilesystemCapabilities:
    platform: str
    exclusive_same_directory_create: bool
    no_follow_create: bool
    directory_relative_traversal: bool
    atomic_no_overwrite_publication: bool
    atomic_replacement: bool
    file_fsync: bool
    directory_durability: bool
    file_identity: bool
    link_detection: bool
    hardlink_count: bool
    owner_only_permissions: bool
    no_overwrite_primitive: str
    overwrite_primitive: str
    directory_durability_primitive: str

    @property
    def fully_supported(self) -> bool:
        return all(
            (
                self.exclusive_same_directory_create,
                self.no_follow_create,
                self.directory_relative_traversal,
                self.atomic_no_overwrite_publication,
                self.atomic_replacement,
                self.file_fsync,
                self.directory_durability,
                self.file_identity,
                self.link_detection,
                self.hardlink_count,
                self.owner_only_permissions,
            )
        )


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    file_index: int


@dataclass(frozen=True)
class DestinationInfo:
    identity: FileIdentity
    link_count: int
    is_directory: bool
    is_link: bool


@dataclass
class ParentDirectory:
    path: str
    posix_fd: int | None = None
    windows_handles: tuple[int, ...] = ()
    closed: bool = False


@dataclass
class OwnedTemporary:
    name: str
    identity: FileIdentity
    posix_fd: int | None = None
    windows_handle: int | None = None
    closed: bool = False
    published: bool = False


@runtime_checkable
class FilesystemOS(Protocol):
    def capabilities(self, root: str) -> FilesystemCapabilities: ...

    def open_parent(
        self, root: str, parent_components: tuple[str, ...]
    ) -> ParentDirectory: ...

    def close_parent(self, parent: ParentDirectory) -> None: ...

    def source_identity(self, source_fd: int) -> FileIdentity: ...

    def inspect_destination(
        self,
        parent: ParentDirectory,
        name: str,
    ) -> DestinationInfo | None: ...

    def create_temporary(self, parent: ParentDirectory) -> OwnedTemporary: ...

    def write(self, temporary: OwnedTemporary, data: memoryview) -> int: ...

    def fsync_file(self, temporary: OwnedTemporary) -> None: ...

    def revalidate_temporary(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
    ) -> None: ...

    def publish_no_overwrite(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
        destination_name: str,
    ) -> None: ...

    def publish_overwrite(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
        destination_name: str,
    ) -> None: ...

    def fsync_directory(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
    ) -> None: ...

    def close_temporary(self, temporary: OwnedTemporary) -> None: ...

    def unlink_temporary(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
    ) -> None: ...


_TEMPORARY_MODE: Final = 0o600
_TEMPORARY_PREFIX: Final = ".cs4a-"
_TEMPORARY_ATTEMPTS: Final = 32


def _operation_error(
    reason: FilesystemFailureReason,
    operation: str,
    *,
    published: bool = False,
) -> FilesystemOperationError:
    return FilesystemOperationError(
        reason,
        operation=operation,
        published=published,
    )


def _native_identity(file_stat: os.stat_result) -> FileIdentity:
    return FileIdentity(volume=int(file_stat.st_dev), file_index=int(file_stat.st_ino))


def _validate_secure_posix_directory(file_stat: os.stat_result) -> None:
    if not stat.S_ISDIR(file_stat.st_mode):
        raise _operation_error(FilesystemFailureReason.INVALID_ROOT, "directory_open")
    effective_user_id = vars(os)["geteuid"]()
    if file_stat.st_uid != effective_user_id or (
        stat.S_IMODE(file_stat.st_mode) & 0o022
    ):
        raise _operation_error(
            FilesystemFailureReason.PERMISSION_UNVERIFIED,
            "directory_permissions",
        )


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _INVALID_HANDLE_VALUE: Final = ctypes.c_void_p(-1).value
    _GENERIC_READ: Final = 0x80000000
    _GENERIC_WRITE: Final = 0x40000000
    _DELETE: Final = 0x00010000
    _READ_CONTROL: Final = 0x00020000
    _FILE_SHARE_READ: Final = 0x00000001
    _FILE_SHARE_WRITE: Final = 0x00000002
    _FILE_SHARE_DELETE: Final = 0x00000004
    _CREATE_NEW: Final = 1
    _OPEN_EXISTING: Final = 3
    _FILE_ATTRIBUTE_NORMAL: Final = 0x00000080
    _FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
    _FILE_FLAG_WRITE_THROUGH: Final = 0x80000000
    _ERROR_FILE_NOT_FOUND: Final = 2
    _ERROR_PATH_NOT_FOUND: Final = 3
    _ERROR_FILE_EXISTS: Final = 80
    _ERROR_ALREADY_EXISTS: Final = 183
    _SDDL_REVISION_1: Final = 1
    _OWNER_SECURITY_INFORMATION: Final = 0x00000001
    _DACL_SECURITY_INFORMATION: Final = 0x00000004
    _SE_FILE_OBJECT: Final = 1
    _FILE_RENAME_INFO_EX_CLASS: Final = 22
    _FILE_RENAME_FLAG_REPLACE_IF_EXISTS: Final = 0x00000001
    _OWNER_ONLY_SDDL: Final = "D:P(A;;FA;;;OW)"

    class _FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FILETIME),
            ("ftLastAccessTime", _FILETIME),
            ("ftLastWriteTime", _FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _KERNEL32.GetFileInformationByHandle.restype = wintypes.BOOL
    _KERNEL32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _KERNEL32.WriteFile.restype = wintypes.BOOL
    _KERNEL32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _KERNEL32.FlushFileBuffers.restype = wintypes.BOOL
    _KERNEL32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
    _KERNEL32.DeleteFileW.restype = wintypes.BOOL
    _KERNEL32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _KERNEL32.SetFileInformationByHandle.restype = wintypes.BOOL
    _KERNEL32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _KERNEL32.GetVolumeInformationW.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [wintypes.HLOCAL]
    _KERNEL32.LocalFree.restype = wintypes.HLOCAL

    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    _ADVAPI32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _ADVAPI32.GetSecurityInfo.restype = wintypes.DWORD
    _ADVAPI32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _ADVAPI32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = (
        wintypes.BOOL
    )


class StandardFilesystemOS:
    """Narrow production facade over required standard-library OS primitives."""

    def capabilities(self, root: str) -> FilesystemCapabilities:
        if os.name == "posix":
            required_dir_fd = {
                os.open,
                os.stat,
                os.unlink,
            }
            directory_relative = required_dir_fd.issubset(os.supports_dir_fd)
            link_relative = os.link in os.supports_dir_fd
            no_follow = hasattr(os, "O_NOFOLLOW") and (
                os.stat in os.supports_follow_symlinks
            )
            supported = (
                directory_relative
                and link_relative
                and no_follow
                and hasattr(os, "O_DIRECTORY")
                and hasattr(os, "O_CLOEXEC")
            )
            return FilesystemCapabilities(
                platform="posix",
                exclusive_same_directory_create=supported,
                no_follow_create=supported,
                directory_relative_traversal=supported,
                atomic_no_overwrite_publication=supported,
                atomic_replacement=supported,
                file_fsync=supported,
                directory_durability=supported,
                file_identity=supported,
                link_detection=supported,
                hardlink_count=supported,
                owner_only_permissions=supported,
                no_overwrite_primitive="linkat",
                overwrite_primitive="renameat",
                directory_durability_primitive="fsync(parent_fd)",
            )
        if os.name == "nt":
            supported = self._windows_root_is_local_ntfs(root)
            return FilesystemCapabilities(
                platform="windows-ntfs",
                exclusive_same_directory_create=supported,
                no_follow_create=supported,
                directory_relative_traversal=supported,
                atomic_no_overwrite_publication=supported,
                atomic_replacement=supported,
                file_fsync=supported,
                directory_durability=supported,
                file_identity=supported,
                link_detection=supported,
                hardlink_count=supported,
                owner_only_permissions=supported,
                no_overwrite_primitive="SetFileInformationByHandle(no-replace)",
                overwrite_primitive=(
                    "SetFileInformationByHandle(FILE_RENAME_FLAG_REPLACE_IF_EXISTS)"
                ),
                directory_durability_primitive=(
                    "FILE_FLAG_WRITE_THROUGH + post-rename FlushFileBuffers"
                ),
            )
        return FilesystemCapabilities(
            platform=os.name,
            exclusive_same_directory_create=False,
            no_follow_create=False,
            directory_relative_traversal=False,
            atomic_no_overwrite_publication=False,
            atomic_replacement=False,
            file_fsync=False,
            directory_durability=False,
            file_identity=False,
            link_detection=False,
            hardlink_count=False,
            owner_only_permissions=False,
            no_overwrite_primitive="unavailable",
            overwrite_primitive="unavailable",
            directory_durability_primitive="unavailable",
        )

    def open_parent(
        self,
        root: str,
        parent_components: tuple[str, ...],
    ) -> ParentDirectory:
        capabilities = self.capabilities(root)
        if not capabilities.fully_supported:
            raise _operation_error(
                FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
                "capability_probe",
            )
        if os.name == "posix":
            return self._open_parent_posix(root, parent_components)
        if os.name == "nt":
            return self._open_parent_windows(root, parent_components)
        raise _operation_error(
            FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
            "parent_traversal",
        )

    def close_parent(self, parent: ParentDirectory) -> None:
        if parent.closed:
            return
        failures = False
        if parent.posix_fd is not None:
            try:
                os.close(parent.posix_fd)
            except OSError:
                failures = True
            parent.posix_fd = None
        if os.name == "nt":
            for handle in reversed(parent.windows_handles):
                if not _KERNEL32.CloseHandle(handle):
                    failures = True
            parent.windows_handles = ()
        parent.closed = True
        if failures:
            raise _operation_error(FilesystemFailureReason.CLEANUP_FAILED, "close")

    def source_identity(self, source_fd: int) -> FileIdentity:
        if type(source_fd) is not int or source_fd < 0:
            raise _operation_error(
                FilesystemFailureReason.IO_FAILED,
                "source_identity",
            )
        try:
            if os.name == "posix":
                return _native_identity(os.fstat(source_fd))
            if os.name == "nt":
                handle = int(msvcrt.get_osfhandle(source_fd))
                return self._windows_handle_info(handle)[0]
        except (OSError, ValueError):
            pass
        raise _operation_error(
            FilesystemFailureReason.IO_FAILED,
            "source_identity",
        )

    def inspect_destination(
        self,
        parent: ParentDirectory,
        name: str,
    ) -> DestinationInfo | None:
        if os.name == "posix":
            parent_fd = self._posix_parent_fd(parent)
            try:
                file_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError as error:
                if error.errno == errno.ENOENT:
                    return None
                raise _operation_error(
                    FilesystemFailureReason.IO_FAILED,
                    "destination_inspection",
                ) from None
            return DestinationInfo(
                identity=_native_identity(file_stat),
                link_count=int(file_stat.st_nlink),
                is_directory=stat.S_ISDIR(file_stat.st_mode),
                is_link=stat.S_ISLNK(file_stat.st_mode),
            )
        if os.name == "nt":
            path = ntpath.join(parent.path, name)
            handle = self._windows_open_existing(path, share_delete=True)
            if handle is None:
                return None
            try:
                identity, links, attributes = self._windows_handle_info(handle)
                return DestinationInfo(
                    identity=identity,
                    link_count=links,
                    is_directory=bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
                    is_link=bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT),
                )
            finally:
                _KERNEL32.CloseHandle(handle)
        raise _operation_error(
            FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
            "destination_inspection",
        )

    def create_temporary(self, parent: ParentDirectory) -> OwnedTemporary:
        for _ in range(_TEMPORARY_ATTEMPTS):
            name = f"{_TEMPORARY_PREFIX}{secrets.token_hex(16)}"
            if os.name == "posix":
                result = self._create_temporary_posix(parent, name)
            elif os.name == "nt":
                result = self._create_temporary_windows(parent, name)
            else:
                raise _operation_error(
                    FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
                    "temporary_create",
                )
            if result is not None:
                return result
        raise _operation_error(
            FilesystemFailureReason.IO_FAILED,
            "temporary_create",
        )

    def write(self, temporary: OwnedTemporary, data: memoryview) -> int:
        if os.name == "posix":
            fd = self._posix_temporary_fd(temporary)
            try:
                return os.write(fd, data)
            except InterruptedError:
                raise
            except OSError:
                raise _operation_error(
                    FilesystemFailureReason.IO_FAILED,
                    "write",
                ) from None
        if os.name == "nt":
            handle = self._windows_temporary_handle(temporary)
            if len(data) == 0:
                return 0
            buffer = (ctypes.c_char * len(data)).from_buffer_copy(data)
            written = wintypes.DWORD()
            if not _KERNEL32.WriteFile(
                handle,
                buffer,
                len(data),
                ctypes.byref(written),
                None,
            ):
                raise _operation_error(
                    FilesystemFailureReason.IO_FAILED,
                    "write",
                )
            return int(written.value)
        raise _operation_error(FilesystemFailureReason.IO_FAILED, "write")

    def fsync_file(self, temporary: OwnedTemporary) -> None:
        try:
            if os.name == "posix":
                os.fsync(self._posix_temporary_fd(temporary))
                return
            if os.name == "nt":
                if _KERNEL32.FlushFileBuffers(
                    self._windows_temporary_handle(temporary)
                ):
                    return
        except OSError:
            pass
        raise _operation_error(
            FilesystemFailureReason.DURABILITY_FAILED,
            "file_fsync",
        )

    def revalidate_temporary(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
    ) -> None:
        if os.name == "posix":
            fd = self._posix_temporary_fd(temporary)
            parent_fd = self._posix_parent_fd(parent)
            try:
                handle_identity = _native_identity(os.fstat(fd))
                named = os.stat(
                    temporary.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError:
                raise _operation_error(
                    FilesystemFailureReason.IDENTITY_MISMATCH,
                    "temporary_identity",
                ) from None
            if (
                handle_identity != temporary.identity
                or _native_identity(named) != temporary.identity
                or not stat.S_ISREG(named.st_mode)
            ):
                raise _operation_error(
                    FilesystemFailureReason.IDENTITY_MISMATCH,
                    "temporary_identity",
                )
            return
        if os.name == "nt":
            handle = self._windows_temporary_handle(temporary)
            handle_identity, _, attributes = self._windows_handle_info(handle)
            named_handle = self._windows_open_existing(
                ntpath.join(parent.path, temporary.name),
                share_delete=True,
            )
            if named_handle is None:
                raise _operation_error(
                    FilesystemFailureReason.IDENTITY_MISMATCH,
                    "temporary_identity",
                )
            try:
                named_identity, _, named_attributes = self._windows_handle_info(
                    named_handle
                )
            finally:
                _KERNEL32.CloseHandle(named_handle)
            if (
                handle_identity != temporary.identity
                or named_identity != temporary.identity
                or attributes
                & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
                or named_attributes
                & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
            ):
                raise _operation_error(
                    FilesystemFailureReason.IDENTITY_MISMATCH,
                    "temporary_identity",
                )
            return
        raise _operation_error(
            FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
            "temporary_identity",
        )

    def publish_no_overwrite(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
        destination_name: str,
    ) -> None:
        if os.name == "posix":
            parent_fd = self._posix_parent_fd(parent)
            try:
                os.link(
                    temporary.name,
                    destination_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raise _operation_error(
                    FilesystemFailureReason.DESTINATION_EXISTS,
                    "publish",
                ) from None
            except OSError as error:
                reason = (
                    FilesystemFailureReason.CAPABILITY_UNAVAILABLE
                    if error.errno in (errno.EXDEV, errno.ENOTSUP, errno.EOPNOTSUPP)
                    else FilesystemFailureReason.IO_FAILED
                )
                raise _operation_error(reason, "publish") from None
            temporary.published = True
            try:
                os.unlink(temporary.name, dir_fd=parent_fd)
            except OSError:
                raise _operation_error(
                    FilesystemFailureReason.CLEANUP_FAILED,
                    "temporary_unlink",
                    published=True,
                ) from None
            return
        if os.name == "nt":
            self._windows_rename_by_handle(
                temporary,
                ntpath.join(parent.path, destination_name),
                replace=False,
            )
            temporary.published = True
            return
        raise _operation_error(
            FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
            "publish",
        )

    def publish_overwrite(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
        destination_name: str,
    ) -> None:
        if os.name == "posix":
            parent_fd = self._posix_parent_fd(parent)
            try:
                os.replace(
                    temporary.name,
                    destination_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            except OSError as error:
                reason = (
                    FilesystemFailureReason.CAPABILITY_UNAVAILABLE
                    if error.errno == errno.EXDEV
                    else FilesystemFailureReason.IO_FAILED
                )
                raise _operation_error(reason, "publish") from None
            temporary.published = True
            return
        if os.name == "nt":
            self._windows_rename_by_handle(
                temporary,
                ntpath.join(parent.path, destination_name),
                replace=True,
            )
            temporary.published = True
            return
        raise _operation_error(
            FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
            "publish",
        )

    def fsync_directory(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
    ) -> None:
        try:
            if os.name == "posix":
                os.fsync(self._posix_parent_fd(parent))
                return
            if os.name == "nt":
                if _KERNEL32.FlushFileBuffers(
                    self._windows_temporary_handle(temporary)
                ):
                    return
        except OSError:
            pass
        raise _operation_error(
            FilesystemFailureReason.DURABILITY_FAILED,
            "directory_fsync",
            published=True,
        )

    def close_temporary(self, temporary: OwnedTemporary) -> None:
        if temporary.closed:
            return
        success = True
        if temporary.posix_fd is not None:
            try:
                os.close(temporary.posix_fd)
            except OSError:
                success = False
            temporary.posix_fd = None
        if os.name == "nt" and temporary.windows_handle is not None:
            if not _KERNEL32.CloseHandle(temporary.windows_handle):
                success = False
            temporary.windows_handle = None
        temporary.closed = True
        if not success:
            raise _operation_error(
                FilesystemFailureReason.CLEANUP_FAILED,
                "close",
                published=temporary.published,
            )

    def unlink_temporary(
        self,
        parent: ParentDirectory,
        temporary: OwnedTemporary,
    ) -> None:
        if temporary.published and os.name != "posix":
            return
        if os.name == "posix":
            parent_fd = self._posix_parent_fd(parent)
            try:
                named = os.stat(
                    temporary.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            except OSError:
                raise _operation_error(
                    FilesystemFailureReason.CLEANUP_FAILED,
                    "temporary_unlink",
                    published=temporary.published,
                ) from None
            if _native_identity(named) != temporary.identity or not stat.S_ISREG(
                named.st_mode
            ):
                raise _operation_error(
                    FilesystemFailureReason.IDENTITY_MISMATCH,
                    "temporary_unlink",
                    published=temporary.published,
                )
            try:
                os.unlink(temporary.name, dir_fd=parent_fd)
            except OSError:
                raise _operation_error(
                    FilesystemFailureReason.CLEANUP_FAILED,
                    "temporary_unlink",
                    published=temporary.published,
                ) from None
            return
        if os.name == "nt":
            path = ntpath.join(parent.path, temporary.name)
            handle = self._windows_open_existing(path, share_delete=True)
            if handle is None:
                return
            try:
                identity, _, attributes = self._windows_handle_info(handle)
            finally:
                _KERNEL32.CloseHandle(handle)
            if identity != temporary.identity or attributes & (
                _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise _operation_error(
                    FilesystemFailureReason.IDENTITY_MISMATCH,
                    "temporary_unlink",
                    published=temporary.published,
                )
            if not _KERNEL32.DeleteFileW(path):
                raise _operation_error(
                    FilesystemFailureReason.CLEANUP_FAILED,
                    "temporary_unlink",
                    published=temporary.published,
                )
            return
        raise _operation_error(
            FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
            "temporary_unlink",
        )

    def _open_parent_posix(
        self,
        root: str,
        parent_components: tuple[str, ...],
    ) -> ParentDirectory:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            current = os.open(root, flags)
        except OSError:
            raise _operation_error(
                FilesystemFailureReason.INVALID_ROOT,
                "root_open",
            ) from None
        try:
            _validate_secure_posix_directory(os.fstat(current))
            os.fsync(current)
            for component in parent_components:
                try:
                    child = os.open(component, flags, dir_fd=current)
                except OSError:
                    raise _operation_error(
                        FilesystemFailureReason.DESTINATION_UNSAFE,
                        "parent_traversal",
                    ) from None
                os.close(current)
                current = child
                _validate_secure_posix_directory(os.fstat(current))
                os.fsync(current)
            return ParentDirectory(
                path=root,
                posix_fd=current,
            )
        except BaseException:
            try:
                os.close(current)
            except OSError:
                pass
            raise

    def _create_temporary_posix(
        self,
        parent: ParentDirectory,
        name: str,
    ) -> OwnedTemporary | None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(
                name,
                flags,
                _TEMPORARY_MODE,
                dir_fd=self._posix_parent_fd(parent),
            )
        except FileExistsError:
            return None
        except OSError:
            raise _operation_error(
                FilesystemFailureReason.IO_FAILED,
                "temporary_create",
            ) from None
        try:
            vars(os)["fchmod"](fd, _TEMPORARY_MODE)
            file_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or stat.S_IMODE(file_stat.st_mode) != _TEMPORARY_MODE
                or file_stat.st_nlink != 1
            ):
                raise _operation_error(
                    FilesystemFailureReason.PERMISSION_UNVERIFIED,
                    "temporary_permissions",
                )
            return OwnedTemporary(
                name=name,
                identity=_native_identity(file_stat),
                posix_fd=fd,
            )
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(name, dir_fd=self._posix_parent_fd(parent))
            except OSError:
                pass
            raise

    @staticmethod
    def _posix_parent_fd(parent: ParentDirectory) -> int:
        if parent.closed or parent.posix_fd is None:
            raise _operation_error(
                FilesystemFailureReason.CLEANUP_FAILED,
                "parent_handle",
            )
        return parent.posix_fd

    @staticmethod
    def _posix_temporary_fd(temporary: OwnedTemporary) -> int:
        if temporary.closed or temporary.posix_fd is None:
            raise _operation_error(
                FilesystemFailureReason.CLEANUP_FAILED,
                "temporary_handle",
                published=temporary.published,
            )
        return temporary.posix_fd

    if os.name == "nt":

        def _windows_root_is_local_ntfs(self, root: str) -> bool:
            if root.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\", "//?/")):
                return False
            drive, _ = ntpath.splitdrive(root)
            if len(drive) != 2 or drive[1] != ":":
                return False
            volume_root = f"{drive}\\"
            filesystem_name = ctypes.create_unicode_buffer(32)
            if not _KERNEL32.GetVolumeInformationW(
                volume_root,
                None,
                0,
                None,
                None,
                None,
                filesystem_name,
                len(filesystem_name),
            ):
                return False
            return filesystem_name.value.upper() == "NTFS"

        def _open_parent_windows(
            self,
            root: str,
            parent_components: tuple[str, ...],
        ) -> ParentDirectory:
            handles: list[int] = []
            current = root
            try:
                for path in (
                    root,
                    *(
                        ntpath.join(root, *parent_components[:index])
                        for index in range(1, len(parent_components) + 1)
                    ),
                ):
                    handle = _KERNEL32.CreateFileW(
                        path,
                        0,
                        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                        None,
                        _OPEN_EXISTING,
                        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
                        None,
                    )
                    if handle == _INVALID_HANDLE_VALUE:
                        raise _operation_error(
                            FilesystemFailureReason.DESTINATION_UNSAFE,
                            "parent_traversal",
                        )
                    handles.append(int(handle))
                    _, _, attributes = self._windows_handle_info(int(handle))
                    if not attributes & _FILE_ATTRIBUTE_DIRECTORY or (
                        attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                    ):
                        raise _operation_error(
                            FilesystemFailureReason.DESTINATION_UNSAFE,
                            "parent_traversal",
                        )
                    current = path
                return ParentDirectory(
                    path=current,
                    windows_handles=tuple(handles),
                )
            except BaseException:
                for handle in reversed(handles):
                    _KERNEL32.CloseHandle(handle)
                raise

        def _create_temporary_windows(
            self,
            parent: ParentDirectory,
            name: str,
        ) -> OwnedTemporary | None:
            descriptor = wintypes.LPVOID()
            if not _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                _OWNER_ONLY_SDDL,
                _SDDL_REVISION_1,
                ctypes.byref(descriptor),
                None,
            ):
                raise _operation_error(
                    FilesystemFailureReason.CAPABILITY_UNAVAILABLE,
                    "temporary_permissions",
                )
            attributes = _SECURITY_ATTRIBUTES(
                nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
                lpSecurityDescriptor=descriptor,
                bInheritHandle=False,
            )
            path = ntpath.join(parent.path, name)
            try:
                handle = _KERNEL32.CreateFileW(
                    path,
                    _GENERIC_READ | _GENERIC_WRITE | _DELETE | _READ_CONTROL,
                    0,
                    ctypes.byref(attributes),
                    _CREATE_NEW,
                    _FILE_ATTRIBUTE_NORMAL
                    | _FILE_FLAG_OPEN_REPARSE_POINT
                    | _FILE_FLAG_WRITE_THROUGH,
                    None,
                )
            finally:
                _KERNEL32.LocalFree(descriptor)
            if handle == _INVALID_HANDLE_VALUE:
                error = ctypes.get_last_error()
                if error in (_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS):
                    return None
                raise _operation_error(
                    FilesystemFailureReason.IO_FAILED,
                    "temporary_create",
                )
            owned_handle = int(handle)
            try:
                identity, links, file_attributes = self._windows_handle_info(
                    owned_handle
                )
                if (
                    links != 1
                    or file_attributes
                    & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
                    or not self._windows_has_owner_only_dacl(owned_handle)
                ):
                    raise _operation_error(
                        FilesystemFailureReason.PERMISSION_UNVERIFIED,
                        "temporary_permissions",
                    )
                return OwnedTemporary(
                    name=name,
                    identity=identity,
                    windows_handle=owned_handle,
                )
            except BaseException:
                _KERNEL32.CloseHandle(owned_handle)
                _KERNEL32.DeleteFileW(path)
                raise

        def _windows_open_existing(
            self,
            path: str,
            *,
            share_delete: bool,
        ) -> int | None:
            share = _FILE_SHARE_READ | _FILE_SHARE_WRITE
            if share_delete:
                share |= _FILE_SHARE_DELETE
            handle = _KERNEL32.CreateFileW(
                path,
                _READ_CONTROL,
                share,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE:
                error = ctypes.get_last_error()
                if error in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
                    return None
                raise _operation_error(
                    FilesystemFailureReason.IO_FAILED,
                    "destination_inspection",
                )
            return int(handle)

        @staticmethod
        def _windows_handle_info(
            handle: int,
        ) -> tuple[FileIdentity, int, int]:
            information = _BY_HANDLE_FILE_INFORMATION()
            if not _KERNEL32.GetFileInformationByHandle(
                handle,
                ctypes.byref(information),
            ):
                raise _operation_error(
                    FilesystemFailureReason.IO_FAILED,
                    "file_identity",
                )
            identity = FileIdentity(
                volume=int(information.dwVolumeSerialNumber),
                file_index=(
                    int(information.nFileIndexHigh) << 32
                    | int(information.nFileIndexLow)
                ),
            )
            return (
                identity,
                int(information.nNumberOfLinks),
                int(information.dwFileAttributes),
            )

        @staticmethod
        def _windows_temporary_handle(temporary: OwnedTemporary) -> int:
            if temporary.closed or temporary.windows_handle is None:
                raise _operation_error(
                    FilesystemFailureReason.CLEANUP_FAILED,
                    "temporary_handle",
                    published=temporary.published,
                )
            return temporary.windows_handle

        @staticmethod
        def _windows_has_owner_only_dacl(handle: int) -> bool:
            descriptor = wintypes.LPVOID()
            result = _ADVAPI32.GetSecurityInfo(
                handle,
                _SE_FILE_OBJECT,
                _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                ctypes.byref(descriptor),
            )
            if result != 0:
                return False
            rendered = wintypes.LPWSTR()
            try:
                if not (
                    _ADVAPI32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        descriptor,
                        _SDDL_REVISION_1,
                        _DACL_SECURITY_INFORMATION,
                        ctypes.byref(rendered),
                        None,
                    )
                ):
                    return False
                return rendered.value == _OWNER_ONLY_SDDL
            finally:
                if rendered:
                    _KERNEL32.LocalFree(rendered)
                _KERNEL32.LocalFree(descriptor)

        @staticmethod
        def _windows_rename_by_handle(
            temporary: OwnedTemporary,
            destination: str,
            *,
            replace: bool,
        ) -> None:
            encoded = destination.encode("utf-16-le")
            alignment = ctypes.alignment(wintypes.HANDLE)
            root_offset = (
                (ctypes.sizeof(wintypes.DWORD) + alignment - 1) // alignment * alignment
            )
            length_offset = root_offset + ctypes.sizeof(wintypes.HANDLE)
            name_offset = length_offset + ctypes.sizeof(wintypes.DWORD)
            size = name_offset + len(encoded)
            buffer = ctypes.create_string_buffer(size)
            flags = _FILE_RENAME_FLAG_REPLACE_IF_EXISTS if replace else 0
            ctypes.memmove(
                ctypes.addressof(buffer),
                ctypes.byref(wintypes.DWORD(flags)),
                ctypes.sizeof(wintypes.DWORD),
            )
            ctypes.memmove(
                ctypes.addressof(buffer) + length_offset,
                ctypes.byref(wintypes.DWORD(len(encoded))),
                ctypes.sizeof(wintypes.DWORD),
            )
            ctypes.memmove(
                ctypes.addressof(buffer) + name_offset,
                encoded,
                len(encoded),
            )
            if not _KERNEL32.SetFileInformationByHandle(
                StandardFilesystemOS._windows_temporary_handle(temporary),
                _FILE_RENAME_INFO_EX_CLASS,
                buffer,
                size,
            ):
                error = ctypes.get_last_error()
                reason = (
                    FilesystemFailureReason.DESTINATION_EXISTS
                    if not replace
                    and error in (_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS)
                    else FilesystemFailureReason.IO_FAILED
                )
                raise _operation_error(reason, "publish")


__all__: list[str] = []
