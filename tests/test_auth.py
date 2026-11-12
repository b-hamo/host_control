"""WBS 4.6: TLS, bootstrap token and replay checks on the Host control channel.

Each server test starts the real Host server (host.sender.start_server) on a
free port and connects to it the way a Runner must: wss://, pinned Host
certificate, `Authorization: Bearer <token>`, HELLO first.
"""

import asyncio
import json
import logging
import ssl

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidMessage, InvalidStatus

from host import tls
from host.bootstrap import CONTROL_PATH, write_bootstrap
from host.sender import start_server
from host.session_registry import AuthError, SessionRegistry, bearer_token
from scrp.envelope import Endpoint, new_nonce
from scrp.validate import parse_and_validate

SES = ("SES-001", "RT-SBX-001", 1)


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# --------------------------------------------------------------------- registry
def test_token_is_256_bit_and_bound_to_identity():
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    assert len(rec.token) >= 43                      # 32 random bytes, base64url
    assert rec.identity() == SES
    assert rec.token not in repr(rec)                # never ends up in a log line by accident
    assert reg.issue(*SES).token != rec.token


def test_token_is_single_use():
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    assert reg.check(rec.token) is rec               # check does not use it up
    assert reg.consume(rec.token) is rec
    with pytest.raises(AuthError, match="already used"):
        reg.check(rec.token)
    with pytest.raises(AuthError, match="already used"):
        reg.consume(rec.token)


def test_token_expires_after_five_minutes():
    clock = FakeClock()
    reg = SessionRegistry(clock=clock)
    rec = reg.issue(*SES)
    clock.t += 299
    reg.check(rec.token)
    clock.t += 1
    with pytest.raises(AuthError, match="expired"):
        reg.consume(rec.token)


@pytest.mark.parametrize("token", [None, "", "not-a-token"])
def test_missing_or_unknown_token_is_refused(token):
    reg = SessionRegistry()
    reg.issue(*SES)
    with pytest.raises(AuthError):
        reg.check(token)


@pytest.mark.parametrize("header, expected", [
    ("Bearer abc", "abc"), ("bearer abc", "abc"), ("Bearer  abc ", "abc"),
    (None, None), ("", None), ("Basic abc", None), ("Bearer", None), ("Bearer ", None), ("abc", None),
])
def test_bearer_header_parsing(header, expected):
    assert bearer_token(header) == expected


# --------------------------------------------------------------------- TLS
def test_server_context_refuses_below_tls12(tmp_path):
    cert, key = tls.ensure_dev_cert(tmp_path)
    assert tls.server_context(cert, key).minimum_version == ssl.TLSVersion.TLSv1_2


def test_dev_cert_is_reused_while_valid(tmp_path):
    cert, _ = tls.ensure_dev_cert(tmp_path)
    first = cert.read_bytes()
    cert, _ = tls.ensure_dev_cert(tmp_path)
    assert cert.read_bytes() == first


def test_bootstrap_file_has_what_the_runner_needs(tmp_path):
    cert, _ = tls.ensure_dev_cert(tmp_path / "certs")
    rec = SessionRegistry().issue(*SES)
    out = tmp_path / "boot" / "bootstrap.json"
    write_bootstrap(out, rec, cert.read_text(), 17443)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert (data["session_id"], data["runtime_id"], data["generation"]) == SES
    assert data["token"] == rec.token and data["path"] == CONTROL_PATH and data["port"] == 17443
    assert data["host_certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")


# --------------------------------------------------------------------- server
@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    cert, key = tls.ensure_dev_cert(d)
    other, _ = tls.ensure_dev_cert(tmp_path_factory.mktemp("other"))
    return cert, key, cert.read_text(), other.read_text()


def hello(identity=SES) -> dict:
    return Endpoint(*identity).envelope("HELLO", {
        "supported_versions": ["1.0"],
        "os": {"family": "windows", "build": "26200.9457"},
        "runner_version": "test-0.1.0",
        "capabilities": ["gui.observe", "gui.input"],
        "monitoring_coverage": {"process": False, "file": True, "network": False, "script": False, "registry": False},
        "client_nonce": new_nonce(),
    })


async def with_server(registry, certs, body):
    cert, key, _, _ = certs
    async with start_server(registry, cert, key, run_demo=False, host="127.0.0.1", port=0) as server:
        port = server.sockets[0].getsockname()[1]
        return await body(port)


async def runner(port, certs, token, *, identity=SES, path=CONTROL_PATH, trust=None, scheme="wss"):
    """Connect like a Runner, send HELLO, return the Host's first reply."""
    _, _, cert_pem, _ = certs
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    kwargs = {"ssl": tls.client_context(trust or cert_pem)} if scheme == "wss" else {}
    async with connect(f"{scheme}://127.0.0.1:{port}{path}", additional_headers=headers,
                       open_timeout=5, **kwargs) as ws:
        await ws.send(json.dumps(hello(identity)))
        return parse_and_validate((await asyncio.wait_for(ws.recv(), 5)).encode())


def run(coro):
    return asyncio.run(coro)


def test_valid_token_gets_hello_ack(certs):
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    reply = run(with_server(reg, certs, lambda port: runner(port, certs, rec.token)))
    assert reply["type"] == "HELLO_ACK"
    assert (reply["session_id"], reply["runtime_id"], reply["generation"]) == SES
    creds = reply["payload"]["channel_credentials"]
    assert creds["telemetry"]["token"] != creds["reconnect"]["token"] != rec.token


@pytest.mark.parametrize("token", [None, "wrong-token-" + "x" * 32])
def test_missing_or_wrong_token_gets_401(certs, token):
    reg = SessionRegistry()
    reg.issue(*SES)
    with pytest.raises(InvalidStatus) as e:
        run(with_server(reg, certs, lambda port: runner(port, certs, token)))
    assert e.value.response.status_code == 401


def test_expired_token_gets_401(certs):
    clock = FakeClock()
    reg = SessionRegistry(clock=clock)
    rec = reg.issue(*SES)
    clock.t += 301
    with pytest.raises(InvalidStatus) as e:
        run(with_server(reg, certs, lambda port: runner(port, certs, rec.token)))
    assert e.value.response.status_code == 401


def test_reused_token_gets_401(certs):
    reg = SessionRegistry()
    rec = reg.issue(*SES)

    async def twice(port):
        assert (await runner(port, certs, rec.token))["type"] == "HELLO_ACK"
        await runner(port, certs, rec.token)

    with pytest.raises(InvalidStatus) as e:
        run(with_server(reg, certs, twice))
    assert e.value.response.status_code == 401


def test_racing_connections_with_one_token_only_one_wins(certs):
    reg = SessionRegistry()
    rec = reg.issue(*SES)

    async def race(port):
        return await asyncio.gather(runner(port, certs, rec.token), runner(port, certs, rec.token),
                                    return_exceptions=True)

    results = run(with_server(reg, certs, race))
    wins = [r for r in results if isinstance(r, dict) and r["type"] == "HELLO_ACK"]
    assert len(wins) == 1, results


def test_token_of_another_session_is_rejected_at_hello(certs):
    reg = SessionRegistry()
    reg.issue("SES-002", "RT-SBX-002", 1)
    other = reg.issue(*SES)

    with pytest.raises(ConnectionClosed) as e:
        run(with_server(reg, certs, lambda port: runner(port, certs, other.token,
                                                         identity=("SES-002", "RT-SBX-002", 1))))
    assert e.value.rcvd.code == 1008
    assert other.consumed                           # a failed attempt still burns the token


def test_wrong_generation_is_rejected_at_hello(certs):
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    with pytest.raises(ConnectionClosed) as e:
        run(with_server(reg, certs, lambda port: runner(port, certs, rec.token, identity=(SES[0], SES[1], 2))))
    assert e.value.rcvd.code == 1008


def test_runner_refuses_a_host_with_a_different_certificate(certs):
    _, _, _, other_pem = certs
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    with pytest.raises(ssl.SSLCertVerificationError):
        run(with_server(reg, certs, lambda port: runner(port, certs, rec.token, trust=other_pem)))
    assert not rec.consumed                          # never reached the Host's HTTP layer


def test_plaintext_ws_is_not_served(certs):
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    with pytest.raises((InvalidMessage, ConnectionError, EOFError)):
        run(with_server(reg, certs, lambda port: runner(port, certs, rec.token, scheme="ws")))
    assert not rec.consumed


def test_wrong_path_gets_404(certs):
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    with pytest.raises(InvalidStatus) as e:
        run(with_server(reg, certs, lambda port: runner(port, certs, rec.token, path="/other")))
    assert e.value.response.status_code == 404


def test_replayed_nonce_is_rejected(certs):
    _, _, cert_pem, _ = certs
    reg = SessionRegistry()
    rec = reg.issue(*SES)

    async def replay(port):
        async with connect(f"wss://127.0.0.1:{port}{CONTROL_PATH}", ssl=tls.client_context(cert_pem),
                           additional_headers={"Authorization": f"Bearer {rec.token}"}) as ws:
            me = Endpoint(*SES)
            first = hello()
            me.sequence = 1
            await ws.send(json.dumps(first))
            ack = parse_and_validate((await ws.recv()).encode())
            me.connection_id = ack["connection_id"]
            # A fresh message in every way except the nonce, which repeats HELLO's.
            again = me.error("INTERNAL", "replay probe")
            again["nonce"] = first["nonce"]
            await ws.send(json.dumps(again))
            while True:                                  # skip the Host's startup checks
                err = parse_and_validate((await ws.recv()).encode())
                if err["type"] == "ERROR":
                    break
            with pytest.raises(ConnectionClosed) as closed:
                await ws.recv()
            return err, closed.value.rcvd.code

    err, code = run(with_server(reg, certs, replay))
    assert err["type"] == "ERROR" and "nonce" in err["error"]["message"]
    assert code == 1008


def test_token_never_appears_in_host_logs(certs, caplog):
    """Even at DEBUG, where websockets dumps request headers."""
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    with caplog.at_level(logging.DEBUG):
        run(with_server(reg, certs, lambda port: runner(port, certs, rec.token)))
        with pytest.raises(InvalidStatus):
            run(with_server(reg, certs, lambda port: runner(port, certs, rec.token)))
    host_side = [r for r in caplog.records if not r.name.startswith("websockets.client")]  # the test's own client
    assert any("[REDACTED]" in r.getMessage() for r in host_side)
    assert all(rec.token not in r.getMessage() for r in host_side)
