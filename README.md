# Cryptography Suite

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Windows-informational)
![Build Status](https://img.shields.io/github/actions/workflow/status/Psychevus/cryptography-suite/python-app.yml)
![Coverage](https://img.shields.io/coveralls/github/Psychevus/cryptography-suite)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

**Cryptography Suite** is an advanced cryptographic toolkit in Python, engineered for high-stakes applications demanding airtight security and seamless integration. With AES encryption, RSA key management, SHA-384 hashing, and secure key handling at its core, this suite provides the essential building blocks for professional-grade encryption workflows.

---

## 🚀 Why Cryptography Suite?

Built with modern applications in mind, Cryptography Suite provides:
- **Cutting-edge cryptographic algorithms** integrated into a developer-friendly interface.
- **Modular design** to plug into diverse applications with minimal setup.
- **Enterprise-ready security practices** such as key rotation and password-protected serialization.
- **Detailed documentation** and **robust testing** for reliability and maintainability.

---

## 📦 Installation

### Installing with pip

Install Cryptography Suite directly from PyPI:

```bash
pip install cryptography-suite
```

### Installing from Source

Clone the repository for direct installation or customization:

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
pip install .
```

> **Prerequisite**: Python 3.12 or newer.

---

## 🔑 Key Features

- **AES Encryption**: High-performance, secure AES encryption in CBC mode with PKCS7 padding for sensitive data.
- **RSA Key Management**: Asymmetric encryption with full support for RSA key generation, serialization, and OAEP padding.
- **SHA-384 Hashing**: Robust SHA-384 hashing, optimized for data integrity in high-security environments.
- **Advanced Key Handling**: Secure key storage, retrieval, and rotation with password protection, ready for production use.
- **Built for Developers**: Intuitive, documented API with usage examples for a seamless developer experience.

---

## 💡 Usage Overview

### 1. AES Encryption/Decryption

AES encryption with password-derived keys, optimized for secure message handling.

```python
from cryptography_suite.encryption import aes_encrypt, aes_decrypt

message = "Highly Confidential Information"
password = "ultrasecurepassword"

encrypted = aes_encrypt(message, password)
print("Encrypted:", encrypted)

decrypted = aes_decrypt(encrypted, password)
print("Decrypted:", decrypted)
```

### 2. RSA Key Management

Generate RSA keys, and perform secure asymmetric encryption/decryption.

```python
from cryptography_suite.asymmetric import generate_rsa_keys, rsa_encrypt, rsa_decrypt

private_key, public_key = generate_rsa_keys()

message = "RSA-encrypted data"
encrypted = rsa_encrypt(message, public_key)
print("Encrypted:", encrypted)

decrypted = rsa_decrypt(encrypted, private_key)
print("Decrypted:", decrypted)
```

### 3. SHA-384 Hashing & Key Derivation

Advanced hashing and PBKDF2-based key derivation.

```python
from cryptography_suite.hashing import sha384_hash, generate_salt, derive_key, verify_derived_key

data = "Sensitive Data"
hashed_data = sha384_hash(data)
print("SHA-384 Hash:", hashed_data)

salt = generate_salt()
derived_key = derive_key(data, salt)
print("Derived Key:", derived_key)
print("Key Verified:", verify_derived_key(data, salt, derived_key))
```

### 4. Key Management

Full suite of key management operations for AES and RSA keys.

```python
from cryptography_suite.key_management import (
    generate_aes_key,
    rotate_aes_key,
    generate_rsa_key_pair,
    serialize_private_key,
    serialize_public_key,
    save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file
)

aes_key = generate_aes_key()
print("Generated AES Key:", aes_key)

rotated_key = rotate_aes_key()
print("Rotated AES Key:", rotated_key)

private_key, public_key = generate_rsa_key_pair()
password = "super_secure_password"

private_pem = serialize_private_key(private_key, password)
public_pem = serialize_public_key(public_key)
save_key_to_file(private_pem, "private_key.pem")
save_key_to_file(public_pem, "public_key.pem")

loaded_private_key = load_private_key_from_file("private_key.pem", password)
loaded_public_key = load_public_key_from_file("public_key.pem")
```

---

## 🧪 Running Tests

The suite includes a comprehensive test suite for each module, ensuring robustness and security across all operations.

```bash
python -m unittest discover -s tests
```

The tests cover a broad range of use cases, ensuring reliability for mission-critical applications.

---

## 🔒 Security Best Practices

- **Secure Key Storage**: Store keys in restricted-access files. For Unix-based systems, apply `chmod 600` permissions.
- **Environment Variables**: Use environment variables for passwords and other sensitive data to prevent exposure.
- **Regular Key Rotation**: Periodically rotate keys to minimize exposure risks in case of compromise.

---

## 🛠 Advanced Usage & Customization

### Extend Cryptography Suite

- **Custom Encryption Modes**: Extend the `encryption.py` module with new encryption modes for specific application needs.
- **RSA Key Size Customization**: Adjust RSA key sizes by setting `DEFAULT_RSA_KEY_SIZE` in `key_management.py`.
- **Layered Hashing**: Chain multiple hash functions for enhanced security in sensitive applications.

---

## 📚 Project Structure

The project follows a modular structure for easy navigation and code extension.

```plaintext
cryptography-suite/
├── encryption.py          # AES encryption and decryption functions
├── asymmetric.py          # RSA key generation, encryption, and decryption
├── hashing.py             # SHA-384 hashing and PBKDF2 key derivation
├── key_management.py      # Key generation, storage, retrieval, and rotation
├── utils.py               # Utility functions
└── example_usage.py       # Demonstrative scripts for each function
```

---

## 📜 License

Cryptography Suite is open-sourced under the MIT License. See [LICENSE](LICENSE) for more information.

---

## 🤝 Contributing

Contributions are welcome. To get started:
1. Fork the repository.
2. Create a feature branch.
3. Commit and push your changes.
4. Open a pull request for review.

Make sure all new code is well-documented and covered by tests.

---

## 📬 Contact

For any questions, suggestions, or support requests, feel free to reach out via [email](mailto:psychevus@gmail.com) or open an issue on GitHub.

---

## 🚀 Additional Resources

- **Cross-Platform Compatibility**: Built to work across macOS, Linux, and Windows.
- **Code Formatting**: Maintain clean code with tools like `black` and `isort`.
- **Performance Optimization**: Leverage `timeit` or `cProfile` for measuring and improving cryptographic operations.
