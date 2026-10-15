"""inbox_download trusts only certificates that are still valid (2026-10-15: www.7-zip.org failed with
"certificate has expired" because an expired cross-signed certificate sat in the Windows CA store)."""

import datetime as dt
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from host.inbox_download import store_certificates

NOW = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)


def cert(name: str, not_before: dt.datetime, not_after: dt.datetime) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    c = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after)
         .sign(key, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


def test_expired_and_not_yet_valid_certificates_are_left_out():
    valid = cert("valid", NOW - dt.timedelta(days=10), NOW + dt.timedelta(days=10))
    expired = cert("expired", NOW - dt.timedelta(days=400), NOW - dt.timedelta(days=30))
    future = cert("future", NOW + dt.timedelta(days=1), NOW + dt.timedelta(days=100))
    other_use = cert("email-only", NOW - dt.timedelta(days=10), NOW + dt.timedelta(days=10))
    stores = {"ROOT": [(valid, "x509_asn", True), (future, "x509_asn", True)],
              "CA": [(expired, "x509_asn", True), (other_use, "x509_asn", {"1.3.6.1.5.5.7.3.4"}),
                     (b"junk", "x509_asn", True), (valid, "pkcs_7_asn", True)]}
    kept = store_certificates(NOW, lambda store: stores[store])
    assert kept == [valid]


def test_server_auth_purpose_is_kept_like_load_default_certs():
    c = cert("server", NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=1))
    kept = store_certificates(NOW, lambda store: [(c, "x509_asn", {ssl.Purpose.SERVER_AUTH.oid})] if store == "CA" else [])
    assert kept == [c]


def test_a_missing_store_is_skipped():
    def enum(store):
        raise OSError("no such store")
    assert store_certificates(NOW, enum) == []
