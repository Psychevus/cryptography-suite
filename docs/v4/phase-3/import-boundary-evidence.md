# Phase 3 import-boundary evidence

- **Base / rollback checkpoint:** `def6fe31329ada2b112b09fff3f31ff1965a3ffb`
- **Validated implementation HEAD:** `5211862d6597568e8daf912bbdab5faa4dba5e60`
- **Validated package version:** `3.0.0`
- **Canonical runtime source:** `src/cryptography_suite/`
- **Result:** pass

## Installed origin and import closure

A fresh virtual environment installed
`cryptography_suite-3.0.0-py3-none-any.whl`. From an unrelated temporary
directory, with isolated Python mode enabled, the root resolved to:

```text
.../Lib/site-packages/cryptography_suite/__init__.py
```

The repository path was absent from `sys.path`. Root import loaded only:

```text
cryptography_suite
cryptography_suite.audit
cryptography_suite.audit.events
cryptography_suite.context
cryptography_suite.envelope
cryptography_suite.envelope.models
cryptography_suite.errors
cryptography_suite.policy
cryptography_suite.protector
cryptography_suite.providers
cryptography_suite.providers.base
cryptography_suite.providers.models
cryptography_suite.streaming
cryptography_suite.streaming.sinks
```

It did not import `cryptography_suite.legacy`, lifecycle services, a CLI,
provider implementation, labs module, primitive suite, or experimental module.

## Enforced negative boundaries

The focused tests prove:

- the same root API and import closure are produced from unrelated working
  directories and different sentinel environments;
- an attempted network connection during root import fails the test;
- prohibited modules, including old primitives, CLI, keystores, labs,
  experimental modules, and a fake provider, cannot be imported from the
  installed wheel;
- the AST import graph matches the Phase 2 module-layer allowlist;
- only the canonical `src/cryptography_suite/__init__.py` is tracked as a
  runtime package identity; and
- provider selection and provider SDK packages are absent.

## Runtime mechanism search

The final stable source has zero occurrences of:

```text
sys.path
__path__
spec_from_file_location
exec_module
CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS
entry_points
Path.cwd
os.getcwd
getcwd(
os.environ
getenv(
```

Repository-wide nonhistorical matches are classified as:

- assertions and literals in Phase 3 negative tests;
- `docs/conf.py` documentation tooling;
- maintainer tooling outside the runtime; and
- historical Phase 3 evidence describing mechanisms that were removed.

No active stable-runtime result remains.

## Installed artifact checks

- Root facade snapshot: pass
- Import origin outside checkout: pass
- Repository checkout absent from interpreter paths: pass
- Forbidden imports: pass
- Entry points: none
- `pip check`: pass
- Wheel rebuilt from sdist: identical entry inventory
- Local full suite on CPython 3.13: 45 passed
- GitHub Quality Gate full suite on CPython 3.11: 45 passed
- GitHub compatibility suite on CPython 3.10: 39 passed

The CPython 3.10 job installs the package non-editably, imports it from outside
the checkout, checks the exact root API and removed-module failures, runs the
unit/contract/negative suite, and runs `pip check`.

Ordinary import performs no environment policy read, network operation,
provider discovery, filesystem discovery beyond normal module import, warning,
CLI initialization, or audit-sink initialization.
