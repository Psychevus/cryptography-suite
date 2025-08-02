# Contributing Guidelines

We welcome contributions to *cryptography-suite*. Please follow these basic
practices when submitting patches:

- **Tests**: Include unit tests for any behavior change.
- **Style**: Keep code readable and consistent with the existing style.

## One-shot helpers

Legacy helper functions (e.g. `*_encrypt`, `*_decrypt`) exist only for backward
compatibility. New helper-style APIs will not be accepted. Any remaining helpers
must internally delegate to the Pipeline DSL modules. When in doubt, prefer
adding or extending pipeline stages instead of introducing new helpers.

