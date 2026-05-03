Security Considerations
=======================

.. warning::
   The following notes highlight important aspects for using ``cryptography-suite`` safely.

 - Experimental/insecure primitives (e.g., ``salsa20_encrypt``, ``ascon_encrypt``) are for research/education only and will be removed in v4.0.0. They are NOT supported for production use. If you depend on them, migrate now.

   > pip install cryptography-suite[legacy]
- Verbose/debug output is redacted before logging and must never include
  derived keys, raw keys, nonces, private keys, shared secrets, plaintext, or
  ciphertext internals. Keep ``CRYPTOSUITE_VERBOSE_MODE`` disabled in
  production unless a specific incident response runbook requires it.
- CLI passwords are no longer accepted as command-line argument values. Prefer
  the interactive prompt, ``--password-stdin``, or ``--password-fd``. Use
  ``--password-env`` or ``--password-file`` only for tightly controlled
  automation because process environments and files can leak outside the
  invoking process.
- File decryption writes plaintext only to a temporary file in the destination
  directory and atomically replaces the requested output path after AES-GCM
  authentication succeeds. Wrong passwords, corrupted files, malformed headers,
  and failed tags must leave any pre-existing output file untouched and remove
  operation-owned temporary files.
- New file-encryption output uses a v2 header authenticated as AES-GCM AAD.
  Pre-v2 versioned files and raw ``salt || nonce || ciphertext || tag`` files
  are decrypt-only compatibility formats and require explicit
  ``allow_legacy_format=True`` or the CLI ``--allow-legacy-format`` flag.
- Private keys should always be stored encrypted, either with a strong password or in
  a hardware-backed keystore (HSM, KMS, etc.). Use
  ``to_encrypted_private_pem`` / ``load_encrypted_private_pem`` for PEM helpers,
  or pass a password to :func:`cryptography_suite.serialize_private_key` and
  :class:`cryptography_suite.protocols.key_management.KeyManager`. Plaintext PEM
  export is available only through the explicitly named
  ``to_unencrypted_private_pem_unsafe`` helper, which emits a warning and is
  intended only for controlled testing or one-time migration.
- ``LocalKeyStore`` is a development/testing backend unless you add production
  filesystem, backup, monitoring, and lifecycle controls. It refuses plaintext
  private-key writes by default and preserves encrypted PEMs during migration.
- ``CRYPTOSUITE_STRICT_KEYS=error`` refuses loading or saving unencrypted private
  keys. ``warn`` logs or warns on legacy plaintext reads, and ``0``/``false``
  disables strict checks but does not remove explicit unsafe flags from write APIs.

Zeroization & Memory Safety
---------------------------

``cryptography-suite`` provides tools (``KeyVault``, ``secure_zero``) for
explicit zeroization of secrets. Because Python's ``bytes`` objects are
immutable and managed by the garbage collector, sensitive data handled as
plain ``bytes`` may persist in memory until collection occurs. For highest
assurance, wrap secrets in ``KeyVault`` or generate them with the
``sensitive=True`` option so they can be securely wiped.

Signal Protocol: Experimental Demo Only
---------------------------------------

The ``cryptography_suite.experimental.signal`` module is not a full Signal
implementation. It lacks critical security properties and should never be
used for production or high-assurance messaging.

Supply Chain Security
---------------------

All release artifacts are built in isolated environments with pinned
dependencies. Each GitHub release contains:

* a CycloneDX SBOM (``sbom.json``),
* a SLSA provenance attestation (``provenance.intoto.jsonl``), and
* ``cosign`` signatures for every file.

To verify a download, use ``cosign verify-blob`` against the artifact and
inspect the SBOM with ``cyclonedx-bom`` or ``pip sbom``. Detailed
instructions are available in :doc:`release_process`.
