# Phase 1 exhaustive repository baseline

## Outcome

Phase 1 is complete as a documentation baseline at
`fb8b0f39c4c598adbd8ffb85667acf3f37174b77`, with one unresolved mandatory
security prerequisite.

**Deep Security Scan status: BLOCKED BY TOOLING FAILURE**

Reason: A discovery worker failed to create its required `threat_model.md`
artifact, and deterministic artifact validation terminated with `ENOENT`.

Consequences:

- no Deep Security Scan result was accepted;
- no candidate from the failed run may be treated as validated;
- no no-findings conclusion may be made;
- independent security scanning remains a release blocker.

Deep Security Scan completion is an unresolved prerequisite for Phase 4 and the
v4 stable release.

## What the baseline establishes

- `git ls-files` contains 285 tracked paths and every path appears exactly once
  in `repository-inventory.csv`.
- The classification proposal contains 61 documentation, 132 test/tooling,
  46 move-to-labs, 26 rewrite, 12 delete/dead-code, five stable-core candidate,
  two legacy-decrypt-only, and one generated path.
- The wheel contains 71 tracked files, all from repository-root
  `cryptography_suite/`; the sdist contains 77 tracked files.
- All 88 tracked runtime/schema/template paths across
  `cryptography_suite/`, the three `src/` trees, and `protocol/handshake.proto`
  have a proposed disposition.
- The actual shipped source contradicts the intended v4 canonical
  `src/cryptography_suite/` layout.
- The package root explicitly exports 111 names, in addition to practical
  `__version__`; every current root group and public submodule/CLI surface has a
  v4 disposition.
- Current serialization, import/plugin, global-state, filesystem, network,
  subprocess, environment, logging, packaging, and CI boundaries are mapped.

## Build and test headline

- clean install, editable install, wheel/sdist build, built-wheel install, and
  external import passed;
- the complete suite passed: 460 passed, 42 skipped, 22 warnings;
- corrected branch coverage passed at 74%;
- repository-wide Ruff, Ruff format, Black, strict mypy, Bandit, Sphinx, and
  MkDocs baselines failed and are documented without configuration weakening;
- installed-wheel `keystore list` and `migrate-keys` are broken;
- Atheris could not build on Windows, so fuzz smoke is unresolved locally;
- 16 dependency sets resolved with no known vulnerabilities; `zk` and `legacy`
  could not be collected and therefore have no audit result.

## Manual security review

The manual review records ten items with exact evidence and conditional
exploitability:

1. local-keystore key-id path escape;
2. destructive/non-atomic encryption output;
3. missing serialized KDF work factors;
4. process-local counter nonce uniqueness;
5. PKCS#11 RSA PKCS#1 v1.5 decrypt and ambient PIN configuration;
6. executable code-generation interpolation;
7. silent registry replacement and enabled plugin execution;
8. non-durable migration-demo tamper-evidence claim;
9. unbounded generic encoded-message parsing;
10. mutable/fetched CI executable dependencies.

These are labeled only `Candidate`, `Confirmed by direct code inspection`, or
`Requires dynamic validation`. None is Deep-Scan validated and no severity is
invented.

## Product conclusion

The current repository is a broad educational/research suite, not a safe base
for additive v4 growth. The v4 stable product should be a new, small
policy-driven envelope/provider/lifecycle surface. Existing primitives,
protocol demos, PQC/FHE/ZK/Signal/BLS, pipeline, formal stubs, codegen,
visualization, fake migration backends, and caller-managed nonce APIs should
leave the stable wheel. Existing file formats should survive only through
explicit legacy decrypt/migration decisions.

## Definition-of-Done check

| Criterion | Result |
| --- | --- |
| Every tracked file appears exactly once | Met; CSV cross-check is 285/285 with no duplicates |
| Every production source file has a disposition | Met; 88/88 |
| Every public Python/CLI surface has a disposition | Met |
| Commands and failures recorded reproducibly | Met in `test-and-build-baseline.md` |
| Security evidence exact and non-speculative | Met for manual review; Deep Scan remains blocked |
| Only documentation changed | Must remain true and is checked immediately before commit |
| Single commit `docs(v4): add exhaustive repository baseline` | Created only after final validation |
| Stop before Phase 2/remediation | Met |

## Next permitted work

Do not begin Phase 2 or remediation from this work package. Before Phase 4 and
before any v4 stable release, rerun a fresh independent Deep Security Scan in a
separate authorized task and complete the release audit requirement.
