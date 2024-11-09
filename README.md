# Cryptography Suite

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Windows-informational)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

A robust, secure, and streamlined cryptographic toolkit in Python, crafted for high-level cryptographic operations. Designed to meet the demands of modern applications, this suite provides AES encryption, RSA key management, SHA-384 hashing, and secure key handling for professional use cases that require top-notch security.

## ⚡ Key Features

- **AES Encryption**: Secure, efficient encryption in CBC mode with PKCS7 padding.
- **RSA Key Management**: Generate, serialize, and manage RSA keys with OAEP padding for robust asymmetric encryption.
- **SHA-384 Hashing**: Generate strong SHA-384 hashes, designed for sensitive data handling.
- **Comprehensive Key Management**: Securely store, retrieve, and rotate keys, with optional password protection.
- **Developer-Friendly**: Clean, well-documented functions for seamless integration into larger systems.

## 🔧 Setup and Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
```

### 2. Create a Virtual Environment and Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

> **Note**: Ensure Python 3.8+ is installed.

### 3. Set Up Environment Variables for Security

Store sensitive information, such as encryption passwords, in environment variables:

```bash
export ENCRYPTION_PASSWORD="your_secure_password"
```

## 📁 Project Structure

```plaintext
cryptography-suite/
├── encryption.py          # AES encryption and decryption functions
├── asymmetric.py          # RSA key generation, encryption, and decryption functions
├── hashing.py             # SHA-384 hashing and PBKDF2 key derivation
├── key_management.py      # Key generation, storage, retrieval, and rotation functions
├── utils.py               # Utility functions (Base62, byte-char conversions)
└── example_usage.py       # Example script demonstrating functionality
```

## 🚀 Usage Examples

### 1. AES Encryption

```python
from encryption import aes_encrypt, aes_decrypt

message = "Top Secret Data"
password = "strongpassword"

encrypted = aes_encrypt(message, password)
print("Encrypted:", encrypted)

decrypted = aes_decrypt(encrypted, password)
print("Decrypted:", decrypted)
```

### 2. RSA Key Management

```python
from asymmetric import generate_rsa_keys, rsa_encrypt, rsa_decrypt

private_key, public_key = generate_rsa_keys()

message = "Secure message with RSA"
encrypted = rsa_encrypt(message, public_key)
print("Encrypted (RSA):", encrypted)

decrypted = rsa_decrypt(encrypted, private_key)
print("Decrypted (RSA):", decrypted)
```

### 3. Hashing and Key Derivation

```python
from hashing import sha384_hash, generate_salt, derive_key, verify_derived_key

data = "Sensitive Data"
hashed_data = sha384_hash(data)
print("SHA-384 Hash:", hashed_data)

salt = generate_salt()
derived_key = derive_key(data, salt)
print("Derived Key:", derived_key)
print("Key Verified:", verify_derived_key(data, salt, derived_key))
```

### 4. Key Management

```python
from key_management import (
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

new_aes_key = rotate_aes_key()
print("Rotated AES Key:", new_aes_key)

private_key, public_key = generate_rsa_key_pair()
password = "encryption_password"

private_pem = serialize_private_key(private_key, password)
public_pem = serialize_public_key(public_key)
save_key_to_file(private_pem, "private_key.pem")
save_key_to_file(public_pem, "public_key.pem")

loaded_private_key = load_private_key_from_file("private_key.pem", password)
loaded_public_key = load_public_key_from_file("public_key.pem")
```

## 🧪 Running Tests

To validate functionality, run the comprehensive test suite:

```bash
python -m unittest discover -s tests
```

The tests cover encryption, decryption, key verification, and various edge cases, ensuring robustness across the suite.

## 🔒 Security Best Practices

- **Key Storage**: Store private keys securely, with restricted access. Use `chmod 600` for private key files on Unix-based systems.
- **Environment Variables**: Store sensitive data in environment variables to avoid hardcoding.
- **Key Rotation**: Regularly rotate keys to reduce exposure risk.

## 🛠 Advanced Usage and Customization

- **Custom Encryption Modes**: Extend the `encryption.py` module to support additional encryption modes.
- **Dynamic Key Sizes**: Adjust the RSA key size by modifying `DEFAULT_RSA_KEY_SIZE` in `key_management.py`.
- **Multi-Layered Hashing**: For high-security needs, consider combining multiple hash functions.

## 📜 License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with the [cryptography](https://cryptography.io/) library to ensure robust, industry-grade cryptographic operations.

## 📬 Contact

Interested in contributing or have questions? Reach out to [psychevus@gmail.com](mailto:psychevus@gmail.com) or open an issue on GitHub. Contributions are welcome!

## ✨ Additional Ideas to Level Up

- **Cross-Platform Compatibility**: The suite is compatible with macOS, Linux, and Windows.
- **Automated Code Formatting**: Use `black` or `isort` for consistent code style.
- **Performance Profiling**: Optimize cryptographic operations by using tools like `timeit` or `cProfile`.