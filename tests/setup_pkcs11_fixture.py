"""Generate a 2048-bit RSA keypair in the configured SoftHSM slot.

The script expects PKCS11_LIBRARY, PKCS11_TOKEN_LABEL and PKCS11_PIN
in the environment. It creates an RSA keypair labeled "rsa" if one
isn't already present.
"""
import os
import pkcs11
from pkcs11 import KeyType

lib = pkcs11.lib(os.environ["PKCS11_LIBRARY"])
token = lib.get_token(token_label=os.environ["PKCS11_TOKEN_LABEL"])

with token.open(rw=True, user_pin=os.environ["PKCS11_PIN"]) as session:
    existing = list(session.get_objects({pkcs11.Attribute.LABEL: "rsa"}))
    if not existing:
        session.generate_keypair(KeyType.RSA, 2048, label="rsa", store=True)
        print("Generated RSA keypair in HSM")
    else:
        print("RSA keypair already exists")
