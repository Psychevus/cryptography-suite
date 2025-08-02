# Using Hardware HSM (PKCS#11)

The suite can interface with hardware security modules via the PKCS#11
standard.  Install the optional dependency with:

```bash
pip install cryptography-suite[hsm]
```

Configuration can be provided through environment variables or a
`~/.cryptosuite.toml` file under the `[pkcs11]` section:

```toml
[pkcs11]
library_path = "/usr/lib/softhsm/libsofthsm2.so"
token_label = "TestToken"
pin = "1234"
```

## SoftHSM Quickstart

SoftHSMv2 offers a software implementation of an HSM for development:

```bash
softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 0000
cryptography-suite keystore list
```

## Security Caveats

SoftHSM is **not** a secure HSM.  It stores key material on disk and lacks
physical protections.  Use a real hardware module in production and ensure
proper access controls around the PKCS#11 library and PIN management.
