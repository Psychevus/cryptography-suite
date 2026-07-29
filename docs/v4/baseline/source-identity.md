# Phase 1 source identity

## Authoritative revision

| Field | Value |
| --- | --- |
| Repository | `Psychevus/cryptography-suite` |
| Working directory | `D:\cryptography-suite` |
| Branch | `docs/v4-phase-1-baseline` |
| HEAD | `fb8b0f39c4c598adbd8ffb85667acf3f37174b77` |
| Commit subject | `Merge pull request #192` |
| Commit author date | `2026-05-07T16:02:07+03:30` |
| Tags at HEAD | none |
| `git describe` | `3.0.0-134-gfb8b0f3` |
| Initial and final tracked state | clean before documentation; final state checked before commit |
| Inventory authority | `git ls-files`, 285 paths |

The Phase 1 execution date was 2026-07-29 in the Asia/Tehran time zone.
Build and test commands ran against a `git archive` of this exact HEAD under
`C:\Users\Mojta\AppData\Local\Temp\cryptography-suite-phase1-fb8b0f3-20260729`.
Windows `tar` could not materialize the tracked `docs/security.md` symlink, so
the isolated documentation copies used the target `SECURITY.md` content at that
path. This workaround did not alter the repository.

## Platform and tools

| Tool | Version |
| --- | --- |
| OS | Microsoft Windows 11 Pro for Workstations, 10.0.22631, 64-bit |
| PowerShell | 7.6.3 |
| Git | 2.55.0.windows.3 |
| System Python | 3.13.2 |
| Baseline Python | CPython 3.12.3 |
| pip | 26.1.2 |
| build | 1.5.0 |
| pytest | 9.1.1 |
| coverage.py | 7.15.2 |
| Ruff | 0.16.0 |
| Black | 26.5.1 |
| mypy | 2.3.0 |
| Bandit | 1.9.4 |
| pip-audit | 2.10.1 |
| Sphinx | 9.1.0 |
| MkDocs | 1.6.1 |
| Node.js / npm | 20.18.0 / 10.9.1 |

Only Python 3.12 and 3.13 were installed locally. The package declares
`>=3.10`; the repository CI configurations mention 3.11 and 3.12. This Phase 1
run does not provide local evidence for 3.10 or 3.11.

## Deep Security Scan status

**Deep Security Scan status: BLOCKED BY TOOLING FAILURE**

A discovery worker failed to create its required `threat_model.md` artifact,
and deterministic artifact validation terminated with `ENOENT`. No result from
that failed run was accepted or used as discovery evidence.
