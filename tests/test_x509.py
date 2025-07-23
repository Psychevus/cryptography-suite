import unittest
from cryptography import x509

from cryptography_suite.x509 import generate_csr, self_sign_certificate, load_certificate
from cryptography_suite.asymmetric import generate_rsa_keypair


class TestX509(unittest.TestCase):
    def test_generate_csr_and_load_certificate(self):
        priv, _ = generate_rsa_keypair()
        csr_pem = generate_csr("example.com", priv)
        self.assertIsInstance(csr_pem, bytes)
        csr = x509.load_pem_x509_csr(csr_pem)
        self.assertEqual(
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "example.com",
        )

        cert_pem = self_sign_certificate("example.com", priv, days_valid=1)
        self.assertIsInstance(cert_pem, bytes)
        cert = load_certificate(cert_pem)
        self.assertIsInstance(cert, x509.Certificate)
        self.assertEqual(cert.subject, cert.issuer)
        self.assertEqual(
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "example.com",
        )

    def test_load_certificate_invalid(self):
        from cryptography_suite.errors import CryptographySuiteError

        with self.assertRaises(CryptographySuiteError):
            load_certificate(b"invalid")


if __name__ == "__main__":
    unittest.main()
