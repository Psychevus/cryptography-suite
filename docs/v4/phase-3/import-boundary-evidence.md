# Phase 3 import-boundary evidence

- **Base / rollback checkpoint:** `def6fe31329ada2b112b09fff3f31ff1965a3ffb`
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
- `tools/generate_support_matrix.py` maintainer tooling outside the runtime;
  and
- old user documentation recording the removed v3 plugin flag.

No active stable-runtime result remains.

## Installed artifact checks

- Root facade snapshot: pass
- Import origin outside checkout: pass
- Repository checkout absent from interpreter paths: pass
- Forbidden imports: pass
- Entry points: none
- `pip check`: pass
- Wheel rebuilt from sdist: identical entry inventory
- Full Phase 3 suite: 25 passed

Ordinary import performs no environment policy read, network operation,
provider discovery, filesystem discovery beyond normal module import, warning,
CLI initialization, or audit-sink initialization.
