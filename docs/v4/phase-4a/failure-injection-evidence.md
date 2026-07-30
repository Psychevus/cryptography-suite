# Phase 4A failure-injection evidence

- **Implementation SHA:** `86bc82df8124e1cf329fc4a5bf5ffe533774658a`
- **Injection seam:** private `FilesystemOS` facade
- **Evidence test:** `tests/unit/test_atomic_failures.py`
- **Result:** 25 cases collected; 24 passed and the POSIX namespace-replacement
  case was skipped on Windows/Python 3.12

The facade wrapper raises one-shot `FilesystemOperationError` instances without
monkeypatching global filesystem functions. Except where the row says
`PUBLISHED_DURABILITY_UNCERTAIN` or `CLEANUP_INCOMPLETE`, the legal next action
is idempotent `abort()`, which was exercised and removed only the owned staging
name. No injected exception string or repr contained the supplied root,
destination, temporary name, source bytes, or staged bytes.

| Injected point | Actual state / outcome | Destination and source | Owned temporary | Exception |
| --- | --- | --- | --- | --- |
| Capability probe unavailable | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | never created | `AtomicSinkError`, `IO_FAILED` |
| Capability report lacks a required primitive | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | never created | `AtomicSinkError`, `IO_FAILED` |
| Root open | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | never created | `AtomicSinkError`, `IO_FAILED` |
| Parent traversal | `FAILED` / `NOT_PUBLISHED` | absent; nested parent unchanged | never created | `AtomicSinkError`, `IO_FAILED` |
| Pre-mutation parent durability barrier | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | never created | represented by the `open_parent` facade failure, `IO_FAILED` |
| Temporary creation | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | creation refused; parent closed | `AtomicSinkError`, `IO_FAILED` |
| First write | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | removed by abort | `AtomicSinkError`, `IO_FAILED` |
| Partial write followed by later failure | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied; completed-chunk count remains zero | removed by abort | `AtomicSinkError`, `IO_FAILED` |
| Interrupted write | remains `OPEN`, then `COMMITTED` / `PUBLISHED` | exact payload published | promotion removes staging name | interruption retried; no error escapes |
| Zero-progress write | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | removed by abort | `AtomicSinkError`, `IO_FAILED` |
| Userspace flush | not applicable: facade uses unbuffered OS writes | unchanged until commit | still owned | no weaker buffered path exists |
| File fsync | `FAILED` / `NOT_PUBLISHED` | absent or original bytes unchanged; source unchanged | removed by abort | `AtomicSinkError`, `IO_FAILED` |
| Temporary ownership revalidation | `FAILED` / `NOT_PUBLISHED` | absent or original bytes unchanged | removed only if identity still matches | `AtomicSinkError`, `IO_FAILED` |
| Destination revalidation | `FAILED` / `NOT_PUBLISHED` | absent or original bytes unchanged; source unchanged | removed by abort | `AtomicSinkError`, `IO_FAILED` |
| No-overwrite atomic promotion | `FAILED` / `NOT_PUBLISHED` | absent or concurrent winner unchanged | removed by abort | `AtomicSinkError`, `IO_FAILED` or `OUTPUT_EXISTS` |
| Overwrite atomic promotion | `FAILED` / `NOT_PUBLISHED` | original bytes unchanged; source unchanged | removed by abort | `AtomicSinkError`, `IO_FAILED` |
| Simulated cross-device promotion | `FAILED` / `NOT_PUBLISHED` | absent; no source supplied | removed by abort; no copy fallback | `AtomicSinkError`, `IO_FAILED` |
| Abort-time temporary unlink | `CLEANUP_INCOMPLETE` / `CLEANUP_INCOMPLETE` | absent; no source supplied | retained for explicit retry, then removed | `AtomicSinkError`, `IO_FAILED` |
| Abort-time owned-identity mismatch | `CLEANUP_INCOMPLETE` / `CLEANUP_INCOMPLETE` | absent; no source supplied | untrusted replacement not removed; one-shot facade retry cleans only the real fixture | `AtomicSinkError`, `IO_FAILED` |
| POSIX temporary pathname replacement | `FAILED`, then cleanup incomplete / `CLEANUP_INCOMPLETE` | destination absent | attacker replacement preserved | `AtomicSinkError`, `IO_FAILED`; POSIX CI case |
| Post-publication directory durability barrier | `PUBLICATION_UNCERTAIN` / `PUBLISHED_DURABILITY_UNCERTAIN` | new destination retained; source unchanged | closed; abort cannot remove destination | `AtomicSinkError`, `IO_FAILED` |
| Post-publication temporary-handle close | `CLEANUP_INCOMPLETE` / `CLEANUP_INCOMPLETE` | new destination retained; source unchanged | explicit abort retries close | `AtomicSinkError`, `IO_FAILED` |
| Post-publication parent-handle close | `CLEANUP_INCOMPLETE` / `CLEANUP_INCOMPLETE` | new destination retained; source unchanged | already promoted; explicit abort retries parent close | `AtomicSinkError`, `IO_FAILED` |

Real namespace-race tests supplement the injected points:

- a destination appearing after staging is preserved in both default and
  dual-authorized overwrite modes;
- an initially existing destination that is replaced after staging is
  preserved and publication fails closed;
- a POSIX staging pathname replacement is not deleted as owned;
- Windows denies staging-name replacement while its no-share handle is open;
- two synchronized processes race with no overwrite, producing one winner and
  one `OUTPUT_EXISTS` loser with no staging-name leak.

The independent Deep Security Scan remains **BLOCKED BY TOOLING FAILURE**. It
was not retried and this document is not a substitute for that scan.
