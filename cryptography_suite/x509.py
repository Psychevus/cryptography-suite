from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .errors import CryptographySuiteError

__all__ = [
    "generate_csr",
    "self_sign_certificate",
    "load_certificate",
]


def generate_csr(common_name: str, private_key) -> bytes:
    """Generate a Certificate Signing Request (CSR).

    Parameters
    ----------
    common_name : str
        The Common Name to include in the CSR.
    private_key : Any
        Private key used to sign the CSR.

    Returns
    -------
    bytes
        The PEM-encoded CSR.
    """
    try:
        if not common_name or private_key is None:
            raise ValueError("Invalid parameters")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        csr = builder.sign(private_key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM)
    except Exception as exc:  # pragma: no cover - high level
        raise CryptographySuiteError(f"Failed to generate CSR: {exc}") from exc


def self_sign_certificate(common_name: str, private_key, days_valid: int = 365) -> bytes:
    """Generate a self-signed X.509 certificate.

    Parameters
    ----------
    common_name : str
        Common Name for the certificate.
    private_key : Any
        Private key to sign the certificate with.
    days_valid : int, optional
        Number of days the certificate is valid for. Defaults to ``365``.

    Returns
    -------
    bytes
        The PEM-encoded certificate.
    """
    try:
        if not common_name or private_key is None:
            raise ValueError("Invalid parameters")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=days_valid))
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        cert = builder.sign(private_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)
    except Exception as exc:  # pragma: no cover - high level
        raise CryptographySuiteError(f"Failed to generate certificate: {exc}") from exc


def load_certificate(pem_data: bytes) -> x509.Certificate:
    """Load a PEM encoded certificate.

    Parameters
    ----------
    pem_data : bytes
        The PEM-encoded certificate data.

    Returns
    -------
    cryptography.x509.Certificate
        Parsed certificate object.
    """
    try:
        return x509.load_pem_x509_certificate(pem_data)
    except Exception as exc:  # pragma: no cover - high level
        raise CryptographySuiteError(f"Failed to load certificate: {exc}") from exc
