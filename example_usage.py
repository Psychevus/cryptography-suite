from encryption import aes_encrypt, aes_decrypt
from asymmetric import generate_rsa_keys, rsa_encrypt, rsa_decrypt
from hashing import sha384_hash, generate_salt, derive_key, verify_derived_key
from key_management import (
    generate_aes_key,
    serialize_private_key,
    serialize_public_key,
    secure_save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file,
    rotate_aes_key
)


def test_aes_encryption():
    password = "strongpassword"
    plaintext = "This is a secret message."
    print("\n--- AES Encryption Example ---")

    encrypted_data = aes_encrypt(plaintext, password)
    print("Encrypted (AES):", encrypted_data)

    decrypted_data = aes_decrypt(encrypted_data, password)
    print("Decrypted (AES):", decrypted_data)


def test_rsa_encryption():
    print("\n--- RSA Encryption Example ---")

    # Generate RSA key pair
    private_key, public_key = generate_rsa_keys()
    plaintext = "This is a secret message."

    # Encrypt and decrypt with RSA
    encrypted_data = rsa_encrypt(plaintext, public_key)
    print("Encrypted (RSA):", encrypted_data)

    decrypted_data = rsa_decrypt(encrypted_data, private_key)
    print("Decrypted (RSA):", decrypted_data)


def test_hashing():
    print("\n--- Hashing Example ---")

    data = "sensitive_data"
    salt = generate_salt()
    hashed_data = sha384_hash(data)
    print("SHA-384 Hash:", hashed_data)

    # Derive and verify a key
    derived_key = derive_key(data, salt)
    print("Derived Key:", derived_key)
    verification = verify_derived_key(data, salt, derived_key)
    print("Key Verification:", verification)


def test_key_management():
    print("\n--- Key Management Example ---")

    # AES Key Generation
    aes_key = generate_aes_key()
    print("Generated AES Key:", aes_key)

    # Rotate AES Key
    new_aes_key = rotate_aes_key()
    print("Rotated AES Key:", new_aes_key)

    # RSA Key Serialization and File Operations
    private_key, public_key = generate_rsa_keys()
    password = "storage_password"

    # Serialize and save keys to files
    private_pem = serialize_private_key(private_key, password)
    public_pem = serialize_public_key(public_key)
    secure_save_key_to_file(private_pem, "private_key.pem")
    secure_save_key_to_file(public_pem, "public_key.pem")

    # Load keys back from files
    loaded_private_key = load_private_key_from_file("private_key.pem", password)
    loaded_public_key = load_public_key_from_file("public_key.pem")

    # Check if keys match original
    test_message = "Testing key loading"
    encrypted_msg = rsa_encrypt(test_message, loaded_public_key)
    decrypted_msg = rsa_decrypt(encrypted_msg, loaded_private_key)
    print("Decrypted message (after loading keys):", decrypted_msg)


if __name__ == "__main__":
    test_aes_encryption()
    test_rsa_encryption()
    test_hashing()
    test_key_management()
