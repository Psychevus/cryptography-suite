# Phase 4A platform capability matrix

- **Status:** implementation capability contract
- **Detailed contract:** [filesystem-contract.md](filesystem-contract.md)

| Primitive | Linux mechanism | Windows mechanism | macOS mechanism |
| --- | --- | --- | --- |
| Existing absolute root | `open` with `O_DIRECTORY \| O_NOFOLLOW` | `CreateFileW`, directory and reparse flags | `open` with `O_DIRECTORY \| O_NOFOLLOW` |
| Parent traversal | descriptor-relative `open` per component | retained non-reparse directory handles | descriptor-relative `open` per component |
| Exclusive same-directory staging | `openat(O_CREAT \| O_EXCL \| O_NOFOLLOW)` | `CreateFileW(CREATE_NEW)` | `openat(O_CREAT \| O_EXCL \| O_NOFOLLOW)` |
| Owner-only staging/final mode | `fchmod` and `fstat`, exact `0600` | protected owner-only DACL, queried after creation | `fchmod` and `fstat`, exact `0600` |
| File identity/link count | `fstat`/`fstatat`, device+inode+nlink | `GetFileInformationByHandle` | `fstat`/`fstatat`, device+inode+nlink |
| Final-link detection | `fstatat(..., AT_SYMLINK_NOFOLLOW)` | open reparse point and inspect attributes | `fstatat(..., AT_SYMLINK_NOFOLLOW)` |
| Atomic no-overwrite | same-directory `linkat`, then owned-name unlink | handle rename without replace flag | same-directory `linkat`, then owned-name unlink |
| Atomic overwrite | same-directory `renameat` replacement | handle rename with replace flag | same-directory `renameat` replacement |
| File durability | `fsync(file_fd)` | `FlushFileBuffers(file_handle)` | `fsync(file_fd)` |
| Directory/rename durability | `fsync(parent_fd)` | write-through handle plus post-rename metadata flush | `fsync(parent_fd)` |
| Cross-filesystem fallback | none; refused | none; refused | none; refused |

## Claim and CI status

| Platform | Implementation | CI claim | Failure behavior | Known residual limitation |
| --- | --- | --- | --- | --- |
| Linux | Implemented for local filesystems exposing required `openat`, link, rename, permission, file-sync, and directory-sync semantics | Ubuntu matrix runs real path, permission, concurrency, failure, artifact, and installed-wheel tests | Capability failure occurs before staging; primitive failure is typed and nondisclosing | Filesystem/hardware may weaken crash persistence below kernel promises; caller must supply a parent not writable by another account |
| Windows | Implemented for local NTFS with Win32 handle, reparse, ACL, identity, rename, and write-through APIs | Windows matrix runs real path, ACL, reparse, concurrency, failure, artifact, and installed-wheel tests | Remote/non-NTFS or unverifiable ACL/reparse/durability support fails before staging | No POSIX directory `fsync` is claimed; the guarantee is the documented NTFS write-through rename/metadata barrier |
| macOS | Implemented using the POSIX path when runtime probes confirm every required primitive | macOS matrix runs real path, permission, concurrency, failure, artifact, and installed-wheel tests | Missing directory sync, no-follow, link, or permission support fails before staging | APFS/HFS Unicode normalization and case behavior are filesystem-defined |

## Status categories

- **Implemented and tested:** claimed rows after their required CI jobs pass.
- **Implemented but not available in current local CI:** Linux and macOS while
  development is performed on Windows; the GitHub matrix supplies evidence.
- **Deliberately unsupported and fail-closed:** Windows remote/non-NTFS roots,
  POSIX writable-by-other parents, and any runtime missing a required primitive.
- **Deferred:** network filesystems, recovery scanning, backups, alternative
  ACL models, and cross-filesystem copy-and-verify transactions.
