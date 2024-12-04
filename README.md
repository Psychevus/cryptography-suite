# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
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
- **Rigorous Testing**: Achieves **98% code coverage** with a comprehensive test suite, guaranteeing reliability and robustness.

---

## 📦 Installation

### Install via pip

Install the latest stable release from PyPI:

```bash
pip install cryptography-suite
```

> **Note**: Requires Python 3.8 or higher.

### Install from Source

Clone the repository and install manually:

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
pip install .
```

---

## 🔑 Key Features

- **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305 encryption with password-based key derivation using PBKDF2 and Scrypt.
- **Asymmetric Encryption**: RSA encryption/decryption, key generation, serialization, and loading.
- **Digital Signatures**: Support for Ed25519 and ECDSA algorithms for secure message signing and verification.
- **Hashing Functions**: Implements SHA-256, SHA-384, SHA-512, and BLAKE2b hashing algorithms.
- **Key Management**: Secure generation, storage, loading, and rotation of cryptographic keys.
- **Secret Sharing**: Implementation of Shamir's Secret Sharing scheme for splitting and reconstructing secrets.
- **Password-Authenticated Key Exchange (PAKE)**: SPAKE2 protocol implementation for secure password-based key exchange.
- **One-Time Passwords (OTP)**: HOTP and TOTP algorithms for generating and verifying one-time passwords.
- **Utility Functions**: Includes Base62 encoding/decoding, secure random string generation, and memory zeroing.

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
```

### Asymmetric Encryption

Generate RSA key pairs and perform encryption/decryption.

```python
from cryptography_suite.asymmetric import generate_rsa_keypair, rsa_encrypt, rsa_decrypt

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

Sign and verify messages using Ed25519.

```python
from cryptography_suite.signatures import generate_ed25519_keypair, sign_message, verify_signature

# Generate key pair
private_key, public_key = generate_ed25519_keypair()

message = b"Authenticate this message"

# Sign the message
signature = sign_message(message, private_key)

# Verify the signature
is_valid = verify_signature(message, signature, public_key)
print(f"Signature valid: {is_valid}")
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

---

## 🧪 Running Tests

Ensure the integrity of the suite by running comprehensive tests:

```bash
coverage run -m unittest discover
coverage report -m
```

Our test suite achieves **98% code coverage**, guaranteeing reliability and robustness.

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
│   ├── asymmetric.py
│   ├── encryption.py
│   ├── hashing.py
│   ├── key_management.py
│   ├── otp.py
│   ├── pake.py
│   ├── secret_sharing.py
│   ├── signatures.py
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
