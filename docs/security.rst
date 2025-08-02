Security Considerations
=======================

.. warning::
   The following notes highlight important aspects for using ``cryptography-suite`` safely.

- Experimental/insecure primitives (e.g., ``salsa20_encrypt``, ``ascon_encrypt``) are for research/education only and will be removed in v4.0.0. They are NOT supported for production use. If you depend on them, migrate now.
- Enabling ``VERBOSE_MODE`` prints derived keys and nonces to stdout. Do **not** enable
  this in production environments.
- Private keys should always be stored encrypted, either with a strong password or in
  a hardware-backed keystore (HSM, KMS, etc.). Unencrypted PEMs are only acceptable for
  testing or inside protected containers. When serializing private keys with
  :func:`cryptography_suite.serialize_private_key` or using
  :class:`cryptography_suite.protocols.key_management.KeyManager`, always supply a
  password so the key material is encrypted. Set the environment variable
  ``CRYPTOSUITE_STRICT_KEYS=1`` to forbid saving unencrypted keys entirely.

Signal Protocol: Experimental Demo Only
---------------------------------------

The ``cryptography_suite.experimental.signal`` module is not a full Signal
implementation. It lacks critical security properties and should never be
used for production or high-assurance messaging.
