.. cryptography-suite documentation master file, created by
   sphinx-quickstart on Thu Jul 24 04:04:41 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

cryptography-suite documentation
================================

Welcome to the **Cryptography Suite** documentation. The API reference is
generated from the package's docstrings.
See the `reStructuredText <https://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html>`_
documentation for details.

What's new in 3.0.0
-------------------

Cryptography Suite 3.0.0 introduces a fully modular design and a focus on
formally verified, misuse-resistant workflows.

- Backend-Agnostic Core (Crypto Abstraction Layer)
- Pipeline DSL for Crypto Workflows
- Misuse-Resistant API (mypy plugin)
- Zeroization & Constant-Time Guarantees
- Formal Verification Export (ProVerif/Tamarin)
- Auto-Stub Generator for App Skeletons
- Rich Logging & Jupyter Widgets for Visualization
- HSM, YubiKey, PKCS#11, Cloud KMS Plugin Architecture
- Fuzzing Harness & Property-Based Testing
- Supply-Chain Attestation, SLSA, and Reproducible Builds


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   architecture.md
   protocols.md
   pipeline.md
   cli.md
   formal.md
   fuzzing.md
   mypy_plugin.md
   release_process.md
   migration_3.0.md
   migration_4.0.md
   threat_model.md
   visualization.md
   security.rst
   api/modules

