"""TLS for the control channel (protocol doc §4 steps 2-3).

Development uses a self-signed certificate made here. The Runner is handed this
exact certificate in its bootstrap config and trusts nothing else. That is why
the Runner side turns hostname checking off: it reaches the Host at the
Sandbox's gateway address, which changes every boot, and trusting a single
pinned certificate already proves the peer holds the Host's private key.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_NAME, KEY_NAME = "host-cert.pem", "host-key.pem"


def _still_valid(cert_path: Path, margin: dt.timedelta = dt.timedelta(days=1)) -> bool:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.not_valid_after_utc - margin > dt.datetime.now(dt.timezone.utc)


def ensure_dev_cert(directory: Path, days: int = 90) -> tuple[Path, Path]:
    """Create a self-signed Host certificate, or reuse one that is still valid."""
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / CERT_NAME, directory / KEY_NAME
    if cert_path.exists() and key_path.exists() and _still_valid(cert_path):
        return cert_path, key_path

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scrp-host")])
    now = dt.datetime.now(dt.timezone.utc)
    pub = key.public_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=True, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("scrp-host"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def fingerprint(cert_pem: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_pem)
    return hashlib.sha256(der).hexdigest()


def server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def client_context(cert_pem: str) -> ssl.SSLContext:
    """What a Runner uses: trust exactly the Host certificate from its bootstrap."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)      # CERT_REQUIRED by default
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False                         # gateway IP varies; see module docstring
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx
