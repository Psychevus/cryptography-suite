from cryptography_suite.cli import bulletproof_cli, zksnark_cli, file_cli
from cryptography_suite.pqc import (
    kyber_encrypt,
    kyber_decrypt,
    dilithium_sign,
    dilithium_verify,
    sphincs_sign,
    sphincs_verify,
)
from cryptography_suite.protocols.key_management import KeyManager
from cryptography_suite.protocols.pake import SPAKE2Client, SPAKE2Server

# Mark symbols used via tests or reflection
used = [
    bulletproof_cli,
    zksnark_cli,
    file_cli,
    kyber_encrypt,
    kyber_decrypt,
    dilithium_sign,
    dilithium_verify,
    sphincs_sign,
    sphincs_verify,
    KeyManager.rotate_keys,
    SPAKE2Client.generate_message,
    SPAKE2Client.compute_shared_key,
    SPAKE2Client.get_shared_key,
    SPAKE2Server.generate_message,
    SPAKE2Server.compute_shared_key,
]
