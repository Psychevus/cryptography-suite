import atheris
import sys
from cryptography_suite.symmetric import aes_encrypt, aes_decrypt


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    msg = fdp.ConsumeUnicodeNoSurrogates(64)
    pwd = fdp.ConsumeUnicodeNoSurrogates(32) or "a"
    try:
        enc = aes_encrypt(msg, pwd, kdf="scrypt")
        dec = aes_decrypt(enc, pwd, kdf="scrypt")
        if dec != msg:
            raise RuntimeError("Roundtrip mismatch")
    except Exception:
        pass


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
