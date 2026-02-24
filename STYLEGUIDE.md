# STYLEGUIDE

This guide defines the **"no surprises"** engineering standard for `cryptography-suite`.

## 1) Naming conventions

- **Modules/packages**: `snake_case` (for example `core/settings.py`).
- **Classes**: `PascalCase` (for example `KeyManager`).
- **Functions/variables**: `snake_case`.
- **Constants**: `UPPER_SNAKE_CASE`.
- **CLI commands/flags**: `kebab-case` for long options (`--output-format`).
- **Booleans**: prefer `is_` / `has_` prefixes when value semantics are unclear.

## 2) Module boundaries

- `cryptography_suite.core`: cross-cutting infrastructure (settings, logging, operation wrappers).
- `cryptography_suite.symmetric|asymmetric|protocols|keystores|pipeline`: domain modules.
- `cryptography_suite.experimental`: research-only and unstable surface; never production defaults.
- `cryptography_suite.cli`: argument parsing and user-facing command behavior only.

Boundary rules:

- Keep crypto primitives out of CLI plumbing.
- Keep filesystem/UI side effects at boundary layers.
- Prefer importing from package public modules over deep private internals.

## 3) Docstring format

Use concise imperative one-line summaries, then optional details.

- Public functions/classes must have docstrings.
- State expected input/output types and notable error behavior.
- Keep examples runnable when included.

## 4) Error and exception conventions

- Raise domain-specific errors where possible (`cryptography_suite.errors`).
- At CLI boundaries, convert exceptions to user-safe messages.
- Do not leak tracebacks by default for expected user failures.
- For incompatible interface changes, add deprecation notes and compatibility aliases.

## 5) Logging conventions

- Use structured logging helpers from `cryptography_suite.core.logging` for app-level events.
- Log machine-readable event names (`cli_invocation`, etc.).
- Never log secrets, plaintext key material, or passwords.
- Human-readable command output and structured logs should remain distinct concerns.

## 6) Public interface stability

- Maintain existing flags/subcommands unless there is a security or correctness reason.
- Additive changes are preferred over breaking changes.
- If replacement is necessary, keep a compatibility path for at least one minor release.

## 7) Output consistency standard

CLI commands should support:

- `--output-format text` (default): concise human-readable output.
- `--output-format json`: machine-readable output where command semantics allow.

Short/legacy aliases must be documented as deprecated with migration guidance.
