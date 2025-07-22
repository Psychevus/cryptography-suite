# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Windows-informational)]()
[![Build Status](https://github.com/Psychevus/cryptography-suite/actions/workflows/python-app.yml/badge.svg)](https://github.com/Psychevus/cryptography-suite/actions)
[![Coverage Status](https://coveralls.io/repos/github/Psychevus/cryptography-suite/badge.svg?branch=main)](https://coveralls.io/github/Psychevus/cryptography-suite?branch=main)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Cryptography Suite** is an advanced cryptographic toolkit for Python, meticulously engineered for applications demanding robust security and seamless integration. It offers a comprehensive set of cryptographic primitives and protocols, empowering developers and organizations to implement state-of-the-art encryption, hashing, key management, digital signatures, and more.

---

## 🚀 Why Choose Cryptography Suite?

- **Comprehensive Functionality**: Access a wide array of cryptographic algorithms and protocols, including symmetric and asymmetric encryption, digital signatures, key management, secret sharing, password-authenticated key exchange (PAKE), and one-time passwords (OTP).
- **High Security Standards**: Implements industry-leading algorithms with best practices, ensuring your data is safeguarded with the highest level of security.
- **Developer-Friendly API**: Offers intuitive and well-documented APIs that simplify integration and accelerate development.
- **Cross-Platform Compatibility**: Fully compatible with macOS, Linux, and Windows environments.
- **Rigorous Testing**: Achieves **95% code coverage** with a comprehensive test suite, guaranteeing reliability and robustness.

---

## 📦 Installation

### Install via pip

Install the latest stable release from PyPI:

```bash
pip install cryptography-suite
```

> **Note**: Requires Python 3.10 or higher. Homomorphic encryption features need `Pyfhel` installed separately.

### Install from Source

Clone the repository and install manually:

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
pip install .
```

---

## 🔑 Key Features

- **Symmetric Encryption**: AES-GCM and ChaCha20-Poly1305 with Argon2 key derivation by default (PBKDF2 and Scrypt also supported).
- **Asymmetric Encryption**: RSA encryption/decryption, key generation, serialization, and loading.
- **Digital Signatures**: Support for Ed25519, ECDSA, and BLS (BLS12-381) algorithms for secure message signing and verification.
- **Hashing Functions**: Implements SHA-256, SHA-384, SHA-512, and BLAKE2b hashing algorithms.
- **Key Management**: Secure generation, storage, loading, and rotation of cryptographic keys.
- **Secret Sharing**: Implementation of Shamir's Secret Sharing scheme for splitting and reconstructing secrets.
- **Password-Authenticated Key Exchange (PAKE)**: SPAKE2 protocol implementation for secure password-based key exchange.
- **One-Time Passwords (OTP)**: HOTP and TOTP algorithms for generating and verifying one-time passwords.
- **Utility Functions**: Includes Base62 encoding/decoding, secure random string generation, and memory zeroing.
- **Homomorphic Encryption**: Wrapper around Pyfhel supporting CKKS and BFV schemes.
- **Zero-Knowledge Proofs**: Bulletproof range proofs and zk-SNARK preimage proofs (optional dependencies).

---

## 💡 Usage Examples

### Symmetric Encryption

Encrypt and decrypt messages using AES-GCM with password-derived keys.

```python
from cryptography_suite.encryption import aes_encrypt, aes_decrypt

message = "Highly Confidential Information"
password = "ultra_secure_password"

# Encrypt the message
encrypted_message = aes_encrypt(message, password)
print(f"Encrypted: {encrypted_message}")

# Decrypt the message
decrypted_message = aes_decrypt(encrypted_message, password)
print(f"Decrypted: {decrypted_message}")

# Use Scrypt key derivation for compatibility
scrypt_encrypted = aes_encrypt(message, password, kdf="scrypt")
print(aes_decrypt(scrypt_encrypted, password, kdf="scrypt"))
```

Argon2id support is provided by the `cryptography` package and requires no
additional dependencies.

### File Encryption

Stream files of any size with AES-GCM. The functions read and write in
chunks, so even large files can be processed efficiently.

```python
from cryptography_suite import encrypt_file, decrypt_file

encrypt_file("secret.txt", "secret.enc", password)
decrypt_file("secret.enc", "secret.out", password)
```

### Asymmetric Encryption

Generate RSA key pairs and perform encryption/decryption.

```python
from cryptography_suite import ec_encrypt
from cryptography_suite.asymmetric import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    ec_decrypt,
    generate_x25519_keypair,
)

# Generate RSA key pair
private_key, public_key = generate_rsa_keypair()

message = b"Secure Data Transfer"

# Encrypt the message
encrypted_message = rsa_encrypt(message, public_key)
print(f"Encrypted: {encrypted_message}")

# Decrypt the message
decrypted_message = rsa_decrypt(encrypted_message, private_key)
print(f"Decrypted: {decrypted_message}")
```

### Digital Signatures

Sign and verify messages using Ed25519 or BLS.

```python
from cryptography_suite.signatures import (
    generate_ed25519_keypair,
    sign_message,
    verify_signature,
)

# Generate Ed25519 key pair
ed_priv, ed_pub = generate_ed25519_keypair()
signature = sign_message(b"Authenticate this message", ed_priv)
print(verify_signature(b"Authenticate this message", signature, ed_pub))

from cryptography_suite.bls import generate_bls_keypair, bls_sign, bls_verify

# Generate BLS key pair
bls_sk, bls_pk = generate_bls_keypair()
bls_sig = bls_sign(b"Authenticate this message", bls_sk)
print(bls_verify(b"Authenticate this message", bls_sig, bls_pk))
```

### Secret Sharing

Split and reconstruct secrets using Shamir's Secret Sharing.

```python
from cryptography_suite.secret_sharing import create_shares, reconstruct_secret

secret = 1234567890
threshold = 3
num_shares = 5

# Create shares
shares = create_shares(secret, threshold, num_shares)

# Reconstruct the secret
selected_shares = shares[:threshold]
recovered_secret = reconstruct_secret(selected_shares)
print(f"Recovered secret: {recovered_secret}")
```

### Homomorphic Encryption

Perform arithmetic over encrypted values using Pyfhel.

```python
from cryptography_suite.homomorphic import (
    fhe_keygen,
    fhe_encrypt,
    fhe_decrypt,
    fhe_add,
    fhe_multiply,
)

he = fhe_keygen("CKKS")

ct1 = fhe_encrypt(he, 10.5)
ct2 = fhe_encrypt(he, 5.25)

sum_ct = fhe_add(he, ct1, ct2)
prod_ct = fhe_multiply(he, ct1, ct2)

print(f"Sum: {fhe_decrypt(he, sum_ct)}")
print(f"Product: {fhe_decrypt(he, prod_ct)}")
```

### Zero-Knowledge Proofs

Prove knowledge of a SHA-256 preimage without revealing it. These
functions require the optional `PySNARK` dependency.

```python
from cryptography_suite import zksnark

zksnark.setup()
hash_hex, proof_file = zksnark.prove(b"secret")
print(zksnark.verify(hash_hex, proof_file))
```

## Advanced Protocols

### SPAKE2 Key Exchange

```python
from cryptography_suite import SPAKE2Client, SPAKE2Server

c, s = SPAKE2Client("pw"), SPAKE2Server("pw")
ck = c.compute_shared_key(s.generate_message())
sk = s.compute_shared_key(c.generate_message())
print(ck == sk)
```
Requires the optional `spake2` package.

### ECIES Encryption

```python
from cryptography_suite import ec_encrypt, ec_decrypt, generate_x25519_keypair

priv, pub = generate_x25519_keypair()
cipher = ec_encrypt(b"secret", pub)
print(ec_decrypt(cipher, priv))
```

### Signal Protocol Messaging

```python
from cryptography_suite import initialize_signal_session

sender, receiver = initialize_signal_session()
msg = sender.encrypt(b"hi")
print(receiver.decrypt(msg))
```

---

## 🧪 Running Tests

Ensure the integrity of the suite by running comprehensive tests:

```bash
coverage run -m unittest discover
coverage report -m
```

Our test suite achieves **95% code coverage**, guaranteeing reliability and robustness.

## 🖥 Command Line Interface

Two console scripts are provided for zero-knowledge proofs:

```bash
cryptosuite-bulletproof 42
cryptosuite-zksnark secret
```

Run each command with `-h` for detailed help.

---

## 🔒 Security Best Practices

- **Secure Key Storage**: Store private keys securely, using encrypted files or hardware security modules (HSMs).
- **Password Management**: Use strong, unique passwords and consider integrating with secret management solutions.
- **Key Rotation**: Regularly rotate cryptographic keys to minimize potential exposure.
- **Environment Variables**: Use environment variables for sensitive configurations to prevent hardcoding secrets.
- **Regular Updates**: Keep dependencies up to date to benefit from the latest security patches.

---

## 🛠 Advanced Usage & Customization

- **Custom Encryption Modes**: Extend the suite by implementing additional encryption algorithms or modes tailored to your needs.
- **Adjustable Key Sizes**: Customize RSA or AES key sizes to meet specific security and performance requirements.
- **Integration with Other Libraries**: Seamlessly integrate with other Python libraries and frameworks for enhanced functionality.
- **Optimized Performance**: Utilize performance profiling tools to optimize cryptographic operations in high-load environments.

---

## 📚 Project Structure

```plaintext
cryptography-suite/
├── cryptography_suite/
│   ├── __init__.py
│   ├── symmetric/
│   │   ├── __init__.py
│   │   ├── aes.py
│   │   ├── chacha.py
│   │   ├── ascon.py
│   │   └── kdf.py
│   ├── asymmetric/
│   │   ├── __init__.py
│   │   ├── bls.py
│   │   └── signatures.py
│   ├── pqc/
│   │   └── __init__.py
│   ├── zk/
│   │   ├── __init__.py
│   │   ├── bulletproof.py
│   │   └── zksnark.py
│   ├── hashing.py
│   ├── key_management.py
│   ├── otp.py
│   ├── pake.py
│   ├── secret_sharing.py
│   ├── homomorphic.py
│   └── utils.py
├── tests/
│   ├── test_asymmetric.py
│   ├── test_encryption.py
│   ├── test_hashing.py
│   ├── test_key_management.py
│   ├── test_otp.py
│   ├── test_pake.py
│   ├── test_secret_sharing.py
│   ├── test_signatures.py
│   └── test_utils.py
├── README.md
├── demo_homomorphic.py
├── setup.py
├── LICENSE
└── .github/
    └── workflows/
        └── python-app.yml
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributions

We welcome contributions from the community. To contribute:

1. **Fork the Repository**: Click on the 'Fork' button at the top right corner of the repository page.
2. **Create a New Branch**: Use a descriptive name for your branch (e.g., `feature/new-algorithm`).
3. **Commit Your Changes**: Make sure to write clear, concise commit messages.
4. **Push to GitHub**: Push your changes to your forked repository.
5. **Submit a Pull Request**: Open a pull request to the `main` branch of the original repository.

Please ensure that your contributions adhere to the project's coding standards and include relevant tests.

---

## 📬 Contact

For support or inquiries:

- **Email**: [psychevus@gmail.com](mailto:psychevus@gmail.com)
- **GitHub Issues**: [Create an Issue](https://github.com/Psychevus/cryptography-suite/issues)

---

## 🌟 Acknowledgements

Special thanks to all contributors and users who have helped improve this project through feedback and collaboration.

---

*Empower your applications with secure and reliable cryptographic functions using Cryptography Suite.*
