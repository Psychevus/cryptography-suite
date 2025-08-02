"""
Example usage of the Cryptography Suite.

This script demonstrates the usage of various cryptographic functions
provided by the library, including encryption, decryption, key management,
digital signatures, hashing, secret sharing, PAKE, and OTP.
"""

import base64
import os
from time import sleep

from cryptography_suite import (
    # Symmetric Encryption
    chacha20_encrypt,
    chacha20_decrypt,
    encrypt_file,
    decrypt_file,
    # Asymmetric Encryption
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    generate_x25519_keypair,
    derive_x25519_shared_key,
    # Signatures
    generate_ed25519_keypair,
    sign_message,
    verify_signature,
    # Hashing
    sha256_hash,
    sha512_hash,
    blake2b_hash,
    derive_key_scrypt,
    derive_key_pbkdf2,
    generate_salt,
    # Key Management
    generate_aes_key,
    rotate_aes_key,
    load_private_key_from_file,
    load_public_key_from_file,
    KeyManager,
    # Secret Sharing
    create_shares,
    reconstruct_secret,
    # PAKE
    SPAKE2Client,
    SPAKE2Server,
    # OTP
    generate_totp,
    verify_totp,
    generate_hotp,
    verify_hotp,
    # Utils
    base62_encode,
    base62_decode,
    generate_secure_random_string,
    use_backend,
)
from cryptography_suite.pipeline import (
    AESGCMEncrypt,
    AESGCMDecrypt,
    RSAEncrypt,
    RSADecrypt,
)


def main():
    with use_backend("pyca"):
        # Symmetric Encryption Example
        print("=== Symmetric Encryption ===")
        plaintext = "Hello, Symmetric Encryption!"
        symmetric_password = "strong_password"

        # AES Encryption with Scrypt KDF
        encrypted_aes = AESGCMEncrypt(password=symmetric_password, kdf="scrypt").run(
            plaintext
        )
        decrypted_aes = AESGCMDecrypt(password=symmetric_password, kdf="scrypt").run(
            encrypted_aes
        )
        print(f"AES Encrypted: {encrypted_aes}")
        print(f"AES Decrypted: {decrypted_aes}")

        # ChaCha20 Encryption
        encrypted_chacha = chacha20_encrypt(plaintext, symmetric_password)
        decrypted_chacha = chacha20_decrypt(encrypted_chacha, symmetric_password)
        print(f"ChaCha20 Encrypted: {encrypted_chacha}")
        print(f"ChaCha20 Decrypted: {decrypted_chacha}")

        # Symmetric File Encryption
        print("\n=== File Encryption ===")
        try:
            with open("test.txt", "w") as f:
                f.write("This is a test file for encryption.")

            encrypt_file("test.txt", "encrypted_test.enc", symmetric_password)
            decrypt_file("encrypted_test.enc", "decrypted_test.txt", symmetric_password)
            with open("decrypted_test.txt", "r") as f:
                decrypted_content = f.read()
            print(f"Decrypted File Content: {decrypted_content}")
        finally:
            # Clean up
            os.remove("test.txt")
            os.remove("encrypted_test.enc")
            os.remove("decrypted_test.txt")

        # Asymmetric Encryption Example
        print("\n=== Asymmetric Encryption ===")
        rsa_private_key, rsa_public_key = generate_rsa_keypair()
        message = b"Hello, Asymmetric Encryption!"

        rsa_ciphertext = RSAEncrypt(public_key=rsa_public_key).run(message)
        rsa_plaintext = RSADecrypt(private_key=rsa_private_key).run(rsa_ciphertext)
        print(f"RSA Decrypted Message: {rsa_plaintext.decode()}")

        # Key Serialization and Loading
        key_password = "encryption_password"
        private_pem = serialize_private_key(rsa_private_key, key_password)
        public_pem = serialize_public_key(rsa_public_key)
        loaded_private_key = load_private_key(private_pem, key_password)
    loaded_public_key = load_public_key(public_pem)
    print("RSA keys serialized and loaded successfully.")

    # X25519 Key Exchange
    print("\n=== X25519 Key Exchange ===")
    alice_private, alice_public = generate_x25519_keypair()
    bob_private, bob_public = generate_x25519_keypair()

    alice_shared_key = derive_x25519_shared_key(alice_private, bob_public)
    bob_shared_key = derive_x25519_shared_key(bob_private, alice_public)
    print(f"Alice's Shared Key: {alice_shared_key.hex()}")
    print(f"Bob's Shared Key: {bob_shared_key.hex()}")
    assert alice_shared_key == bob_shared_key, "Shared keys do not match!"

    # Digital Signatures
    print("\n=== Digital Signatures ===")
    ed_private_key, ed_public_key = generate_ed25519_keypair()
    sign_message_text = b"Message for signing."
    signature = sign_message(sign_message_text, ed_private_key)
    is_valid = verify_signature(sign_message_text, signature, ed_public_key)
    print(f"Signature Valid: {is_valid}")

    # Hashing Functions
    print("\n=== Hashing ===")
    data_to_hash = "Data to hash."
    sha256_digest = sha256_hash(data_to_hash)
    sha512_digest = sha512_hash(data_to_hash)
    blake2b_digest = blake2b_hash(data_to_hash)
    print(f"SHA-256: {sha256_digest}")
    print(f"SHA-512: {sha512_digest}")
    print(f"BLAKE2b: {blake2b_digest}")

    # Key Derivation
    print("\n=== Key Derivation ===")
    salt = generate_salt()
    derived_key_scrypt = derive_key_scrypt(key_password, salt)
    derived_key_pbkdf2 = derive_key_pbkdf2(key_password, salt)
    print(f"Derived Key (Scrypt): {derived_key_scrypt.hex()}")
    print(f"Derived Key (PBKDF2): {derived_key_pbkdf2.hex()}")

    # Secret Sharing
    print("\n=== Secret Sharing ===")
    secret_value = 1234567890
    threshold = 3
    num_shares = 5
    shares = create_shares(secret_value, threshold, num_shares)
    print(f"Shares: {shares}")
    recovered_secret = reconstruct_secret(shares[:threshold])
    print(f"Recovered Secret: {recovered_secret}")

    # Password-Authenticated Key Exchange (PAKE)
    print("\n=== PAKE ===")
    pake_password = "shared_password"
    client = SPAKE2Client(pake_password)
    server = SPAKE2Server(pake_password)

    client_msg = client.generate_message()
    server_msg = server.generate_message()

    client_shared_key = client.compute_shared_key(server_msg)
    server_shared_key = server.compute_shared_key(client_msg)
    print(f"Client's Shared Key: {client_shared_key.hex()}")
    print(f"Server's Shared Key: {server_shared_key.hex()}")
    assert client_shared_key == server_shared_key, "PAKE shared keys do not match!"

    # One-Time Passwords (OTP)
    print("\n=== One-Time Passwords ===")
    otp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")
    totp_code = generate_totp(otp_secret)
    print(f"Generated TOTP Code: {totp_code}")
    is_valid_totp = verify_totp(totp_code, otp_secret)
    print(f"TOTP Code Valid: {is_valid_totp}")

    # Wait for next interval to generate HOTP
    sleep(1)
    counter = 1
    hotp_code = generate_hotp(otp_secret, counter)
    print(f"Generated HOTP Code: {hotp_code}")
    is_valid_hotp = verify_hotp(hotp_code, otp_secret, counter)
    print(f"HOTP Code Valid: {is_valid_hotp}")

    # Utility Functions
    print("\n=== Utility Functions ===")
    random_bytes = os.urandom(16)
    base62_encoded = base62_encode(random_bytes)
    decoded_bytes = base62_decode(base62_encoded)
    print(f"Base62 Encoded: {base62_encoded}")
    print(f"Decoded Bytes Match: {random_bytes == decoded_bytes}")

    random_string = generate_secure_random_string(16)
    print(f"Secure Random String: {random_string}")

    # Key Management
    print("\n=== Key Management ===")
    private_key_path = "rsa_private.pem"
    public_key_path = "rsa_public.pem"
    ec_private = "ec_private.pem"
    ec_public = "ec_public.pem"

    km = KeyManager()
    km.generate_rsa_keypair_and_save(private_key_path, public_key_path, key_password)
    km.generate_ec_keypair_and_save(ec_private, ec_public, key_password)
    loaded_private_key = load_private_key_from_file(private_key_path, key_password)
    loaded_public_key = load_public_key_from_file(public_key_path)
    print("RSA keys generated, saved, and loaded from files successfully.")

    # Clean up key files
    os.remove(private_key_path)
    os.remove(public_key_path)
    os.remove(ec_private)
    os.remove(ec_public)

    # Rotate AES Key using KeyVault wrappers
    with generate_aes_key() as aes_key:
        print(f"Original AES Key: {aes_key.hex()}")
    with rotate_aes_key() as rotated_key:
        print(f"Rotated AES Key: {rotated_key.hex()}")

    # Homomorphic Encryption Demo
    print("\n=== Homomorphic Encryption ===")
    try:
        from cryptography_suite.experimental import (
            FHE_AVAILABLE,
            fhe_keygen,
            fhe_encrypt,
            fhe_decrypt,
            fhe_add,
            fhe_multiply,
        )

        if FHE_AVAILABLE:
            fhe = fhe_keygen("CKKS")
            c1 = fhe_encrypt(fhe, 10.5)
            c2 = fhe_encrypt(fhe, 5.25)
            print("Decrypted Sum:", fhe_decrypt(fhe, fhe_add(fhe, c1, c2)))
            print("Decrypted Product:", fhe_decrypt(fhe, fhe_multiply(fhe, c1, c2)))
        else:
            print("Pyfhel not installed; skipping homomorphic encryption demo.")
    except Exception:
        print("Pyfhel not installed; skipping homomorphic encryption demo.")


if __name__ == "__main__":
    main()
