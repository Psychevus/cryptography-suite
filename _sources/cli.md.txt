# Command Line Interface

The ``cryptography-suite`` executable exposes several subcommands. Run
``cryptography-suite --help`` to see the list.

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
