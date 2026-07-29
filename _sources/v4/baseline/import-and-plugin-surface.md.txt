# Import, registry, and plugin surface

## Import-time behavior

| Evidence | Behavior | Consequence |
| --- | --- | --- |
| `cryptography_suite/__init__.py` | Eagerly imports and re-exports most stable-looking primitives; `__getattr__` conditionally loads `experimental` | A normal root import has broad dependency and side-effect reach |
| `src/cryptography_suite/__init__.py:14-43` | Extends `__path__`, appends `src` to `sys.path`, walks `crypto_suite`, imports modules, and aliases them | Excluded wrapper can mask package identity and duplicate implementations |
| `cryptography_suite/config.py:7-10` | Clears the settings cache, reads environment, and publishes globals | Import order determines configuration snapshots |
| `cryptography_suite/constants.py:22-24` and `symmetric/kdf.py:40-45` | Read KDF environment overrides at import | Ciphertext behavior depends on ambient pre-import state |
| `crypto_backends/__init__.py:126-127` | Imports the pyca backend to register it | Import mutates the backend registry |
| `experimental/ascon.py` and `experimental/salsa20.py` | Emit deprecation/experimental warnings | Import is observable |
| `src/crypto_suite/handshake_pb2.py:17` | Registers a serialized protobuf descriptor | Generated global descriptor state |
| `fuzz/*.py` | Calls Atheris setup/fuzz at module top level | Harness import starts fuzzing |
| `docs/conf.py` | Mutates `sys.path` for autodoc | Documentation import behavior differs from installed-wheel behavior |

## Dynamic loading

`cryptography_suite/keystores/__init__.py:41-50` discovers and imports every
built-in keystore module. Lines 53-69 optionally execute every `*.py` file from
an explicit directory or from `cwd/keystores` when
`CRYPTOSUITE_LOAD_LOCAL_KEYSTORE_PLUGINS=1`. Lines 75-82 load the
`cryptosuite.keystores` entry-point group. Failures are logged and accumulated
rather than raised.

`cryptography_suite/cli.py:1084-1103` uses
`spec_from_file_location`/`exec_module` to load the excluded
`src/cryptography_suite/cli/migrate_keys.py` file. This works only in a
particular source checkout layout and fails from the built wheel.

`cryptography_suite/codegen/__init__.py` loads Jinja templates through package
resources. Optional modules otherwise use ordinary guarded imports or
`import_module`, notably the AWS KMS provider.

## Registries

| Registry | Evidence | Replacement behavior |
| --- | --- | --- |
| Keystore | `keystores/__init__.py:13,18-23` | `_REGISTRY[name] = cls`; silent replacement |
| Crypto backend | `crypto_backends/__init__.py:15,24-31,82-98` | Decorator and instance selection silently replace the name |
| Pipeline module | `pipeline.py:207-224` | Rejects a different class with an existing name |
| Entry points | `pyproject.toml` and `keystores/__init__.py:75-82` | Third-party code executes on load |

`use_backend()` constructs `_BackendContext`, whose constructor immediately
calls `__enter__` (`crypto_backends/__init__.py:38-45`). Merely creating the
context manager therefore mutates selection. If no selection exists,
`get_backend()` chooses the first insertion-ordered registered backend
(`:107-123`).

## Global mutable state

- keystore registry and failed-plugin list;
- backend registry plus current-backend/warning `ContextVar`s;
- pipeline module registry;
- audit logger singleton;
- CLI output format;
- operational metrics and process cancellation event;
- cached settings and import-time configuration constants;
- warning-deduplication sets in experimental helpers.

## v4 disposition

Stable v4 should use explicit provider construction and a sealed registry or
allowlist owned by an application context. Local executable discovery from the
current working directory is not a stable-core feature. Third-party providers
need an explicit enablement and conflict policy. Experimental import aliases,
source-path mutation, and the dynamically loaded migration file should be
removed during the canonical-layout work, after Phase 2 defines compatibility.
