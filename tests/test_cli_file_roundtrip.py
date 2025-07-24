"""Integration test: encrypt via CLI and decrypt via library."""

from pathlib import Path
import tempfile

from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.cli import file_cli
from cryptography_suite.symmetric import decrypt_file


def test_cli_file_roundtrip():
    """Generate RSA key, encrypt file via CLI, decrypt using library."""
    # ensure RSA key generation works
    priv, pub = generate_rsa_keypair()
    assert priv and pub

    with tempfile.TemporaryDirectory() as tmpdir:
        plain = Path(tmpdir) / "plain.txt"
        plain.write_text("hello integration")
        enc = Path(tmpdir) / "enc.bin"
        dec = Path(tmpdir) / "out.txt"

        file_cli(["encrypt", "--in", str(plain), "--out", str(enc), "--password", "pw"])
        decrypt_file(str(enc), str(dec), "pw")

        assert dec.read_text() == "hello integration"
