import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from .exceptions import RequestConsistencyError

AVAIL_HASHES = {
    "sha224",
    "sha256",
    "sha384",
    "sha512",
}


def get_common_names(csr):
    return csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)


def csr_from_str(csr_str):
    try:
        # construct x509 request from PEM string
        csr_data = bytes(csr_str, encoding='utf-8')
        csr = x509.load_pem_x509_csr(
                data=csr_data,
                backend=default_backend()
        )
    except (UnicodeEncodeError, ValueError):
        raise RequestConsistencyError("Invalid CSR format")

    return csr


def create_random_nonce():
    return os.urandom(32).hex()


def create_random_sid():
    return os.urandom(32).hex()


def key_match(cert_bytes, csr_bytes):
    """ Compare public keys of two cryptographic objects and return True if
    they are the same, otherwise return False.
    """
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())
    return cert.public_key().public_numbers() == csr.public_key().public_numbers()
