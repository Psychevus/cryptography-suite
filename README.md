
# Cryptography Suite

A powerful, secure, and easy-to-use cryptographic toolkit implemented in Python. This suite provides advanced AES encryption, RSA key management, SHA-384 hashing, and secure key handling, designed for professional applications demanding cutting-edge security.

## Features

- **AES Encryption**: Secure AES encryption in CBC mode with PKCS7 padding.
- **RSA Key Management**: Generate, serialize, and load RSA keys with OAEP padding for asymmetric encryption.
- **SHA-384 Hashing**: Generate secure SHA-384 hashes, ideal for sensitive data.
- **Key Management**: Securely store, retrieve, and rotate keys, with built-in password protection for private keys.

## Setup and Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
```

### 2. Create a Virtual Environment and Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install cryptography
```

### 3. Set Up Environment Variables for Security

To enhance security, store sensitive passwords in environment variables:

```bash
export ENCRYPTION_PASSWORD="your_secure_password"
```

## Project Structure

```plaintext
cryptography-suite/
├── encryption.py          # AES encryption and decryption
├── asymmetric.py          # RSA key generation, encryption, and decryption
├── hashing.py             # SHA-384 hashing and PBKDF2 key derivation
├── key_management.py      # Key generation, storage, and retrieval
├── utils.py               # Utility functions (Base62, byte-char conversions)
└── example_usage.py       # Example script demonstrating functionality
```

## Usage

### 1. AES Encryption

Encrypt and decrypt messages using AES with password-derived keys.

```python
from encryption import aes_encrypt, aes_decrypt

message = "Top Secret Data"
password = "strongpassword"

# Encrypt the message
encrypted = aes_encrypt(message, password)
print("Encrypted:", encrypted)

# Decrypt the message
decrypted = aes_decrypt(encrypted, password)
print("Decrypted:", decrypted)
```

### 2. RSA Key Management

Generate RSA key pairs, serialize them for secure storage, and use them for asymmetric encryption.

```python
from asymmetric import generate_rsa_keys, rsa_encrypt, rsa_decrypt

# Generate RSA key pair
private_key, public_key = generate_rsa_keys()

# Encrypt and decrypt a message
message = "Secure message with RSA"
encrypted = rsa_encrypt(message, public_key)
print("Encrypted (RSA):", encrypted)

decrypted = rsa_decrypt(encrypted, private_key)
print("Decrypted (RSA):", decrypted)
```

### 3. Hashing and Key Derivation

Use SHA-384 for secure hashing and PBKDF2 for key derivation.

```python
from hashing import sha384_hash, generate_salt, derive_key, verify_derived_key

# Hashing
data = "Sensitive Data"
hashed_data = sha384_hash(data)
print("SHA-384 Hash:", hashed_data)

# Key derivation and verification
salt = generate_salt()
derived_key = derive_key(data, salt)
print("Derived Key:", derived_key)
print("Key Verified:", verify_derived_key(data, salt, derived_key))
```

### 4. Key Management

Generate AES and RSA keys, serialize keys for secure storage, load them, and rotate keys as needed.

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

# Generate AES key
aes_key = generate_aes_key()
print("Generated AES Key:", aes_key)

# Rotate AES Key
new_aes_key = rotate_aes_key()
print("Rotated AES Key:", new_aes_key)

# RSA Key Management
private_key, public_key = generate_rsa_key_pair()
password = "encryption_password"

# Serialize keys
private_pem = serialize_private_key(private_key, password)
public_pem = serialize_public_key(public_key)
save_key_to_file(private_pem, "private_key.pem")
save_key_to_file(public_pem, "public_key.pem")

# Load keys from files
loaded_private_key = load_private_key_from_file("private_key.pem", password)
loaded_public_key = load_public_key_from_file("public_key.pem")
```

## Running Tests

To ensure everything works as expected, you can run the comprehensive tests included in `test_crypto.py`. The tests cover encryption, decryption, key verification, and edge cases.

```bash
python -m unittest test_crypto.py
```

## Security Considerations

- **Secure Key Storage**: Ensure private keys are stored in secure locations with restricted access. Use `chmod 600` for private key files on Unix-like systems.
- **Environment Variables**: Use environment variables to store sensitive passwords and avoid hardcoding them.
- **Key Rotation**: Regularly rotate AES keys to reduce the risk of key compromise.

## Advanced Usage and Customization

For advanced use cases, you can expand the cryptographic suite to:
- **Add additional encryption modes and hash algorithms** by updating the respective modules.
- **Use different key sizes for RSA encryption** by modifying `DEFAULT_RSA_KEY_SIZE` in `key_management.py`.

## License

This project is licensed under the MIT License. See `LICENSE` for more details.

---

## Acknowledgments

Built with the [cryptography](https://cryptography.io/) library for high-performance and secure cryptographic operations.

## Contact

Feel free to reach out to the repository owner for questions or collaboration opportunities.
