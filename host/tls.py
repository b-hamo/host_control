"""TLS for the control channel (protocol doc §4 steps 2-3).

Development uses a self-signed certificate made here. The Runner is handed this
exact certificate (and its SHA-256 fingerprint) in its bootstrap config and
trusts nothing else: it pins it. Pinning needs no host-name check, so the
Sandbox-side Host address changing between boots does not matter, and nothing
has to be installed into the Windows certificate store (doing that is what
brings up a "install this CA certificate?" dialog in every new Sandbox).

For a Runner that still checks the host name, the Host address it uses can be
put into the SAN (`ensure_dev_cert(addresses=...)`); the certificate is then
remade whenever that address changes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_NAME, KEY_NAME = "host-cert.pem", "host-key.pem"
log = logging.getLogger("host-tls")


RENEW_BEFORE = dt.timedelta(days=1)
DEFAULT_DNS = ("scrp-host",)
DEFAULT_IPS = ("127.0.0.1",)


def _wanted(addresses) -> tuple[set[str], set[str]]:
    """Split the requested names into DNS names and IP addresses for the SAN."""
    dns, ips = set(DEFAULT_DNS), set(DEFAULT_IPS)
    for a in addresses or ():
        a = str(a).strip()
        if not a:
            continue
        try:
            ips.add(str(ipaddress.ip_address(a)))
        except ValueError:
            dns.add(a)
    return dns, ips


def _san(cert: x509.Certificate) -> tuple[set[str], set[str]]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set(), set()
    return set(ext.get_values_for_type(x509.DNSName)), {str(i) for i in ext.get_values_for_type(x509.IPAddress)}


def _why_new(cert_path: Path, key_path: Path, dns: set[str], ips: set[str]) -> str | None:
    """None if the existing certificate can be reused, otherwise the reason it cannot."""
    if not (cert_path.exists() and key_path.exists()):
        return "no certificate yet"
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except ValueError:
        return "existing certificate is unreadable"
    if cert.not_valid_after_utc - RENEW_BEFORE <= dt.datetime.now(dt.timezone.utc):
        return f"it expires {cert.not_valid_after_utc:%Y-%m-%d %H:%M} UTC"
    have_dns, have_ips = _san(cert)
    if (have_dns, have_ips) != (dns, ips):
        return f"addresses changed: had {sorted(have_ips | have_dns)}, need {sorted(ips | dns)}"
    return None


def ensure_dev_cert(directory: Path, days: int = 90, addresses=()) -> tuple[Path, Path]:
    """Create a self-signed Host certificate, or reuse one that still fits.

    `addresses` are the names the Runner uses to reach the Host, e.g. the
    Host address Windows Sandbox sees (it changes between boots, 172.20.x →
    192.168.x). They go into the SAN next to 127.0.0.1 and scrp-host. The
    current Runner keeps Windows chain and host name checks and adds a leaf
    pin, so it needs the address here (see the README).

    A new certificate (and key) is made when there is none, when it has less
    than a day left, or when the requested addresses differ from the SAN.
    The reason is logged; renewal keeps the requested addresses.
    """
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / CERT_NAME, directory / KEY_NAME
    dns, ips = _wanted(addresses)
    why = _why_new(cert_path, key_path, dns, ips)
    if why is None:
        return cert_path, key_path
    log.info("host certificate: making a new one (%s) for %s", why, sorted(ips | dns))

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scrp-host")])
    now = dt.datetime.now(dt.timezone.utc)
    pub = key.public_key()
    san = [x509.DNSName(d) for d in sorted(dns)] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
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
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def fingerprint(cert_pem: str) -> str:
    """SHA-256 of the certificate's DER bytes, lowercase hex. What a pinning Runner compares."""
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
