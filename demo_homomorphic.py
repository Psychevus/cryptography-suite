"""Demonstration of homomorphic encryption operations."""
from cryptography_suite.homomorphic import keygen, encrypt, decrypt, add, multiply


def main() -> None:
    he = keygen("CKKS")
    ct1 = encrypt(he, 10.5)
    ct2 = encrypt(he, 5.25)

    sum_ct = add(he, ct1, ct2)
    prod_ct = multiply(he, ct1, ct2)

    print("Decrypted Sum:", decrypt(he, sum_ct))
    print("Decrypted Product:", decrypt(he, prod_ct))


if __name__ == "__main__":
    main()
