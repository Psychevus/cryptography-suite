# Command Line Interface

The ``cryptography-suite`` executable exposes several subcommands. Run
``cryptography-suite --help`` to see the list.

.. note::
   The CLI uses the default registered backend. When writing scripts or
   libraries, call :func:`cryptography_suite.crypto_backends.use_backend`
   explicitly.

```bash
cryptography-suite --help
```

## File Encryption

Use the ``file`` group to encrypt and decrypt files:

```bash
cryptography-suite file encrypt --in INPUT --out OUTPUT --password PASS
cryptography-suite file decrypt --in INPUT --out OUTPUT --password PASS
```

`cryptography-suite encrypt` and `cryptography-suite decrypt` remain available
as hidden aliases for backward compatibility.

## Other Commands

- ``keygen`` – generate key pairs
- ``hash`` – compute file digests
- ``otp`` – generate time-based OTP codes
- ``export`` – export pipelines for formal verification
- ``gen`` – scaffold application code
- ``backends`` – manage crypto backends
- ``keystore`` – manage key storage plugins
- ``fuzz`` – run fuzzing harnesses (also exposed via ``cryptosuite-fuzz``)

## Keystore Command

RSA key generation writes the private key to disk encrypted with the supplied
password. Prefer `--password-file`, `--password-env`, or `--password-stdin` over
putting private-key passwords directly in argv:

```bash
CRYPTOSUITE_KEY_PASSWORD="$(pass show cryptosuite/rsa-key)"
cryptography-suite keygen rsa --private rsa_priv.pem --public rsa_pub.pem \
  --password-env CRYPTOSUITE_KEY_PASSWORD
```

The ``keystore`` group exposes pluggable key storage backends.  Available
backends are classified by stability:

``local`` (testing), ``mock_hsm`` (testing), ``aws-kms`` (limited,
requires ``pip install cryptography-suite[aws]``)

Use ``cryptography-suite keystore list`` to display the available backends
with their status and ``cryptography-suite keystore test`` to verify
connectivity.  Keys can be moved between backends with ``keystore migrate``:

```bash
cryptography-suite keystore migrate --from local --to mock_hsm --dry-run
```

Omit ``--key`` to migrate all keys.  Only migrations between backends that both advertise raw private-key
export/import support are permitted. ``aws-kms`` fails closed because AWS KMS
does not accept arbitrary private key bytes via this interface.
Plaintext private-key migration is refused unless
``--unsafe-allow-unencrypted-private-key`` is supplied for controlled
development/testing migration. Encrypted PEMs are preserved as encrypted PEMs
when moving through compatible raw migration backends.
