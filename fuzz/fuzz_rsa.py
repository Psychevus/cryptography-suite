import atheris
import sys
from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.pipeline import RSAEncrypt, RSADecrypt

PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair(key_size=2048)

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    msg = fdp.ConsumeBytes(128)
    try:
        ciphertext = RSAEncrypt(public_key=PUBLIC_KEY, raw_output=True).run(msg)
        plaintext = RSADecrypt(private_key=PRIVATE_KEY).run(ciphertext)
        if plaintext != msg:
            raise RuntimeError("Roundtrip mismatch")
    except Exception:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
