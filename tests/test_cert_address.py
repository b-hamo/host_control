"""Host certificate and bootstrap for a real Runner (Lifecycle integration request).

- The Sandbox-side Host address goes into the SAN, for a Runner that checks the host name.
- The certificate is remade when that address changes (it changes between boots).
- Renewing near expiry keeps the requested addresses (it used to fall back to 127.0.0.1 only).
- bootstrap carries the Host address and the certificate's SHA-256, so a Runner can pin it.
"""

import asyncio
import hashlib
import json
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509

from host import tls
from host.bootstrap import write_bootstrap
from host.session_registry import SessionRegistry

ROOT = Path(__file__).resolve().parent.parent
SES = ("SES-001", "RT-SBX-001", 1)


def san_of(cert_path: Path) -> set[str]:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    dns, ips = tls._san(cert)
    return dns | ips


def test_default_san_is_local_only(tmp_path):
    cert, _ = tls.ensure_dev_cert(tmp_path)
    assert san_of(cert) == {"scrp-host", "127.0.0.1"}


def test_sandbox_address_goes_into_the_san_and_is_reused_while_unchanged(tmp_path):
    cert, key = tls.ensure_dev_cert(tmp_path, addresses=["192.168.208.1"])
    assert "192.168.208.1" in san_of(cert)
    first = cert.read_bytes()
    tls.ensure_dev_cert(tmp_path, addresses=["192.168.208.1"])
    assert cert.read_bytes() == first                          # same address: reused


def test_a_changed_address_makes_a_new_certificate_and_key(tmp_path, caplog):
    cert, key = tls.ensure_dev_cert(tmp_path, addresses=["172.20.16.1"])
    old_cert, old_key = cert.read_bytes(), key.read_bytes()
    with caplog.at_level("INFO"):
        tls.ensure_dev_cert(tmp_path, addresses=["192.168.208.1"])
    assert cert.read_bytes() != old_cert and key.read_bytes() != old_key
    assert san_of(cert) == {"scrp-host", "127.0.0.1", "192.168.208.1"}
    assert "addresses changed" in caplog.text                  # never silently


def test_renewal_near_expiry_keeps_the_requested_address(tmp_path, caplog):
    """The bug reported by the Lifecycle side: a certificate with under a day left
    was remade for 127.0.0.1 only, and the Runner then refused the Host."""
    cert, _ = tls.ensure_dev_cert(tmp_path, days=0, addresses=["192.168.208.1"])   # expires right away
    old = cert.read_bytes()
    with caplog.at_level("INFO"):
        tls.ensure_dev_cert(tmp_path, addresses=["192.168.208.1"])
    assert cert.read_bytes() != old
    assert "192.168.208.1" in san_of(cert)
    assert "expires" in caplog.text


def test_unreadable_certificate_is_replaced(tmp_path):
    tls.ensure_dev_cert(tmp_path)
    (tmp_path / tls.CERT_NAME).write_text("garbage")
    cert, _ = tls.ensure_dev_cert(tmp_path)
    assert san_of(cert) == {"scrp-host", "127.0.0.1"}


def test_bootstrap_has_the_host_address_and_the_fingerprint(tmp_path):
    cert, _ = tls.ensure_dev_cert(tmp_path / "c", addresses=["192.168.208.1"])
    pem = cert.read_text()
    rec = SessionRegistry().issue(*SES)
    out = tmp_path / "bootstrap.json"
    write_bootstrap(out, rec, pem, 17443, host="192.168.208.1", upload_port=17444)
    boot = json.loads(out.read_text(encoding="utf-8"))
    assert boot["host"] == "192.168.208.1"
    der = ssl.PEM_cert_to_DER_cert(pem)
    assert boot["host_certificate_sha256"] == hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------- what a real Runner sees on the wire
def _served_cert(certs_dir: Path, addresses, client_ctx_factory, server_hostname):
    """Start a TLS server with the dev certificate and connect to it like a Runner."""
    cert, key = tls.ensure_dev_cert(certs_dir, addresses=addresses)
    pem = cert.read_text()

    async def main():
        async def handle(reader, writer):
            writer.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=tls.server_context(cert, key))
        port = srv.sockets[0].getsockname()[1]

        def connect():
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            with client_ctx_factory(pem).wrap_socket(raw, server_hostname=server_hostname) as s:
                return s.getpeercert(binary_form=True)
        try:
            return await asyncio.to_thread(connect), pem
        finally:
            srv.close()
    return asyncio.run(main())


def strict_client(pem: str) -> ssl.SSLContext:
    """Like Windows' default validation once the certificate is trusted: host name checked too."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)          # check_hostname=True, CERT_REQUIRED
    ctx.load_verify_locations(cadata=pem)
    return ctx


def test_host_name_checking_runner_accepts_the_sandbox_address_once_it_is_in_the_san(tmp_path):
    der, _ = _served_cert(tmp_path / "a", ["192.168.208.1"], strict_client, "192.168.208.1")
    assert der


def test_host_name_checking_runner_refuses_an_address_not_in_the_san(tmp_path):
    """What the Lifecycle side hit: SAN had only 127.0.0.1."""
    with pytest.raises(ssl.SSLCertVerificationError):
        _served_cert(tmp_path / "b", [], strict_client, "192.168.208.1")


def test_pinning_runner_does_not_care_about_the_address(tmp_path):
    """The recommended way: compare the presented certificate with the bootstrap
    fingerprint. No host-name check, nothing installed into the Windows store."""
    def pinning_client(pem):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE                     # like SECURITY_FLAG_IGNORE_UNKNOWN_CA ...
        return ctx

    der, pem = _served_cert(tmp_path / "c", [], pinning_client, "10.99.99.99")
    assert hashlib.sha256(der).hexdigest() == tls.fingerprint(pem)   # ... then this comparison decides


def test_mcp_server_writes_the_advertised_address(tmp_path):
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "host" / "mcp_server.py"), "--port", "0", "--upload-port", "0",
         "--advertise-address", "192.168.208.1", "--bootstrap-out", str(tmp_path / "bootstrap.json"),
         "--cert-dir", str(tmp_path / "certs"), "--audit-dir", str(tmp_path / "audit"),
         "--log-file", str(tmp_path / "mcp.log")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        proc.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
        proc.stdin.flush()
        proc.stdout.readline()
        deadline = time.time() + 20
        while not (tmp_path / "bootstrap.json").exists() and time.time() < deadline:
            time.sleep(0.1)
        boot = json.loads((tmp_path / "bootstrap.json").read_text(encoding="utf-8"))
    finally:
        proc.stdin.close()
        proc.wait(10)
    assert boot["host"] == "192.168.208.1"
    assert "192.168.208.1" in san_of(tmp_path / "certs" / tls.CERT_NAME)
    assert boot["host_certificate_sha256"] == tls.fingerprint(boot["host_certificate_pem"])
