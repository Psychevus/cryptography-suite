import atheris
import sys
from cryptography_suite.asymmetric import generate_x25519_keypair, ec_encrypt, ec_decrypt

PRIVATE_KEY, PUBLIC_KEY = generate_x25519_keypair()

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    msg = fdp.ConsumeBytes(128)
    try:
        ciphertext = ec_encrypt(msg, PUBLIC_KEY, raw_output=True)
        plaintext = ec_decrypt(ciphertext, PRIVATE_KEY)
        if plaintext != msg:
            raise RuntimeError("Roundtrip mismatch")
    except Exception:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
