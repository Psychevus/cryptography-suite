"""Demonstration of homomorphic encryption operations."""

from cryptography_suite.experimental import (
    fhe_add,
    fhe_decrypt,
    fhe_encrypt,
    fhe_keygen,
    fhe_multiply,
)


def main() -> None:
    he = fhe_keygen("CKKS")
    ct1 = fhe_encrypt(he, 10.5)
    ct2 = fhe_encrypt(he, 5.25)

    sum_ct = fhe_add(he, ct1, ct2)
    prod_ct = fhe_multiply(he, ct1, ct2)

    print("Decrypted Sum:", fhe_decrypt(he, sum_ct))
    print("Decrypted Product:", fhe_decrypt(he, prod_ct))


if __name__ == "__main__":
    main()
