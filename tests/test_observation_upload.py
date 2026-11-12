"""Screenshot uploads (protocol doc §8): upload_id, the HTTPS receiver, validation,
and the image reaching the Agent only after the Host has checked it."""

import asyncio
import http.client
import json
import logging
import struct
import zlib

import pytest

from host import tls
from host.audit import AuditLog
from host.broker import Broker
from host.observation_store import (MAX_PNG_BYTES, ObservationUploads, UploadError, png_size)
from host.sender import Sessions, start_server
from host.session_registry import SessionRegistry
from host.startup import StartupProfile
from host import upload_server
from host.upload_server import start_upload_server
from mini_runner import MiniRunner, make_png, put_png

SES = ("SES-001", "RT-SBX-001", 1)


class FakeClock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def result_for(png: bytes, upload_id: str, observation_id="OBS-1") -> dict:
    import hashlib
    w, h = png_size(png)
    return {"observation_id": observation_id, "width": w, "height": h, "sha256": hashlib.sha256(png).hexdigest(),
            "captured_at": "2026-09-28T00:00:00.000Z", "upload_id": upload_id}


# --------------------------------------------------------------------- store, unit
def test_upload_id_is_a_long_random_single_use_key():
    u = ObservationUploads()
    a, b = u.issue(SES, "ACT-1"), u.issue(SES, "ACT-2")
    assert a != b and len(a) >= 43                    # 256 bits, base64url
    png = make_png(64, 32)
    u.receive(a, png)
    with pytest.raises(UploadError) as e:
        u.receive(a, png)
    assert e.value.status == 401 and "already used" in e.value.reason


def test_unknown_and_expired_upload_ids_are_refused():
    clock = FakeClock()
    u = ObservationUploads(clock=clock)
    with pytest.raises(UploadError) as e:
        u.receive("nope", make_png(8, 8))
    assert e.value.status == 401
    uid = u.issue(SES, "ACT-1")
    clock.t += 30.0
    with pytest.raises(UploadError) as e:
        u.receive(uid, make_png(8, 8))
    assert e.value.status == 401 and "expired" in e.value.reason


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


@pytest.mark.parametrize("data, status", [
    (b"GIF89a" + b"x" * 100, 415),                                            # not a PNG
    (make_png(16, 16)[:40], 400),                                             # truncated
    (make_png(16, 16)[:-5] + b"\x00\x00\x00\x00\x00", 400),                   # bad CRC at the end
    (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 5000, 5000, 8, 0, 0, 0, 0))
     + _chunk(b"IEND", b""), 413),                                            # 25 MP claimed
    (b"\x89PNG\r\n\x1a\n" + _chunk(b"tEXt", b"hi") + _chunk(b"IEND", b""), 400),  # no IHDR first
])
def test_malformed_pngs_are_refused(data, status):
    u = ObservationUploads()
    with pytest.raises(UploadError) as e:
        u.receive(u.issue(SES, "ACT-1"), data)
    assert e.value.status == status


def test_oversized_upload_is_refused():
    u = ObservationUploads()
    with pytest.raises(UploadError) as e:
        u.receive(u.issue(SES, "ACT-1"), b"\x89PNG\r\n\x1a\n" + b"\x00" * MAX_PNG_BYTES)
    assert e.value.status == 413


def test_validated_only_when_it_matches_the_observe_result():
    u = ObservationUploads()
    png = make_png(64, 32)
    uid = u.issue(SES, "ACT-1")
    u.receive(uid, png)
    state, shot, reason = u.finalize(uid, result_for(png, uid))
    assert state == "VALIDATED" and shot.png == png and reason is None
    assert u.kept(SES)[-1].sha256 == shot.sha256


@pytest.mark.parametrize("change, why", [
    ({"sha256": "0" * 64}, "sha256"),
    ({"width": 65}, "64x32"),
])
def test_mismatch_with_the_observe_result_is_blocked(change, why):
    u = ObservationUploads()
    png = make_png(64, 32)
    uid = u.issue(SES, "ACT-1")
    u.receive(uid, png)
    state, shot, reason = u.finalize(uid, {**result_for(png, uid), **change})
    assert state == "BLOCKED" and shot is None and why in reason


def test_no_upload_means_missing_not_blocked():
    u = ObservationUploads()
    uid = u.issue(SES, "ACT-1")
    state, shot, _ = u.finalize(uid, result_for(make_png(8, 8), uid))
    assert (state, shot) == ("MISSING", None)


def test_inspector_hook_can_block_a_screenshot():
    """Where the W8-9 screenshot prompt-injection detector plugs in."""
    u = ObservationUploads(inspectors=[lambda png: "suspicious text on screen"])
    png = make_png(8, 8)
    uid = u.issue(SES, "ACT-1")
    u.receive(uid, png)
    state, _, reason = u.finalize(uid, result_for(png, uid))
    assert state == "BLOCKED" and reason.startswith("screenshot inspection")


def test_only_the_last_eight_are_kept_and_purge_forgets_everything():
    u = ObservationUploads()
    for i in range(10):
        png = make_png(8, 8, i)
        uid = u.issue(SES, f"ACT-{i}")
        u.receive(uid, png)
        u.finalize(uid, result_for(png, uid, f"OBS-{i}"))
    assert [s.observation_id for s in u.kept(SES)] == [f"OBS-{i}" for i in range(2, 10)]
    u.issue(SES, "ACT-X")
    u.purge(SES)
    assert u.kept(SES) == [] and not u._slots


# --------------------------------------------------------------------- HTTPS receiver
@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    cert, key = tls.ensure_dev_cert(tmp_path_factory.mktemp("certs"))
    return cert, key, cert.read_text()


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


def raw_request(port, cert_pem, method, path, body=b"", headers=None):
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=tls.client_context(cert_pem), timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read().decode()
    finally:
        conn.close()


async def with_upload_server(certs, body, uploads=None):
    cert, key, pem = certs
    uploads = uploads or ObservationUploads()
    server = await start_upload_server(uploads, tls.server_context(cert, key), "127.0.0.1", 0)
    async with server:
        return await body(server.sockets[0].getsockname()[1], uploads, pem)


def test_upload_over_https_with_the_pinned_certificate(certs):
    async def body(port, uploads, pem):
        uid = uploads.issue(SES, "ACT-1")
        png = make_png(32, 16)
        first = await asyncio.to_thread(put_png, port, pem, uid, png)
        again = await asyncio.to_thread(put_png, port, pem, uid, png)
        return first, again, uploads._slots[uid].state

    first, again, state = run(with_upload_server(certs, body))
    assert (first, again, state) == (201, 401, "RECEIVED")


@pytest.mark.parametrize("method, path, headers, status", [
    ("PUT", "/other/x", {"Content-Type": "image/png"}, 404),
    ("GET", "/scrp/v1/observations/x", {}, 405),
    ("PUT", "/scrp/v1/observations/x", {"Content-Type": "text/plain"}, 415),
    ("PUT", "/scrp/v1/observations/x", {"Content-Type": "image/png", "Content-Length": str(MAX_PNG_BYTES + 1)}, 413),
])
def test_receiver_refuses_anything_but_a_png_put(certs, method, path, headers, status):
    async def body(port, uploads, pem):
        return await asyncio.to_thread(raw_request, port, pem, method, path, b"x" if method == "PUT" else b"",
                                       headers)

    got, _ = run(with_upload_server(certs, body))
    assert got == status


def test_slow_body_times_out(certs, monkeypatch):
    monkeypatch.setattr(upload_server, "BODY_TIMEOUT_S", 0.3)

    def slow(port, pem):
        import socket
        import ssl
        raw = socket.create_connection(("127.0.0.1", port))
        s = tls.client_context(pem).wrap_socket(raw)
        s.sendall(b"PUT /scrp/v1/observations/x HTTP/1.1\r\nContent-Type: image/png\r\nContent-Length: 100\r\n\r\nabc")
        data = s.recv(200)
        s.close()
        return data

    async def body(port, uploads, pem):
        return await asyncio.to_thread(slow, port, pem)

    assert b"408" in run(with_upload_server(certs, body))


def test_upload_id_is_not_logged_in_full(certs, caplog):
    async def body(port, uploads, pem):
        uid = uploads.issue(SES, "ACT-1")
        await asyncio.to_thread(put_png, port, pem, uid, make_png(8, 8))
        await asyncio.to_thread(put_png, port, pem, uid, make_png(8, 8))    # refused, also logged
        return uid

    with caplog.at_level(logging.DEBUG):
        uid = run(with_upload_server(certs, body))
    assert uid[:6] in caplog.text and uid not in caplog.text


# --------------------------------------------------------------------- end to end: Runner → Host → Agent
async def with_session(certs, body, runner_kwargs=None, upload=True):
    cert, key, pem = certs
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    uploads = ObservationUploads()
    sessions = Sessions(reg, heartbeat_interval_s=5.0, profile=StartupProfile(step_timeout_s=2.0), uploads=uploads)
    up = await start_upload_server(uploads, tls.server_context(cert, key), "127.0.0.1", 0)
    async with up, start_server(reg, cert, key, run_demo=False, host="127.0.0.1", port=0,
                                sessions=sessions) as server:
        r = MiniRunner(server.sockets[0].getsockname()[1], pem, SES,
                       upload_port=up.sockets[0].getsockname()[1] if upload else None, **(runner_kwargs or {}))
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        while not session.ready.is_set():
            await asyncio.sleep(0.02)
        broker = Broker(session, audit=AuditLog())
        try:
            return await body(broker, r, uploads)
        finally:
            if not serving.done():
                r.drop()
            await serving


def test_agent_gets_the_validated_png(certs):
    async def body(b, r, uploads):
        await b.call("task_submit", {"goal": "g"})
        obs = await b.call("computer_observe", {})
        return obs, r.uploads, b.audit.records

    obs, statuses, audit = run(with_session(certs, body))
    assert obs.ok and obs.data["image"] == "attached" and obs.data["image_state"] == "VALIDATED"
    assert obs.image.startswith(b"\x89PNG") and png_size(obs.image) == (1280, 720)
    assert statuses[-1] == 201
    assert "iVBOR" not in json.dumps(audit)                 # no base64 image in the audit log


def test_runner_that_does_not_upload_still_works_without_an_image(certs):
    async def body(b, r, uploads):
        await b.call("task_submit", {"goal": "g"})
        obs = await b.call("computer_observe", {})
        click = await b.call("computer_click", {"x": 10, "y": 10})
        return obs, click

    obs, click = run(with_session(certs, body, upload=False))
    assert obs.ok and obs.image is None and obs.data["image_state"] == "MISSING"
    assert click.ok


def test_tampered_upload_is_not_shown_and_not_used_for_coordinates(certs):
    async def body(b, r, uploads):
        await b.call("task_submit", {"goal": "g"})
        b.session.last_observation = None                  # forget the startup capture
        r.upload_tamper = True                             # the Runner starts lying after a good start
        obs = await b.call("computer_observe", {})
        click = await b.call("computer_click", {"x": 10, "y": 10})
        return obs, click

    obs, click = run(with_session(certs, body))
    assert not obs.ok and obs.error["error"] == "ACTION_FAILED" and "sha256" in obs.error["message"]
    assert obs.image is None
    assert click.error["error"] == "STALE_OBSERVATION"      # the rejected capture is not a basis for clicks


def test_screenshots_are_forgotten_when_the_session_ends(certs):
    async def body(b, r, uploads):
        await b.call("task_submit", {"goal": "g"})
        await b.call("computer_observe", {})
        before = len(uploads.kept(SES))
        await b.call("session_stop", {"reason": "TASK_COMPLETE"})
        return before, len(uploads.kept(SES)), b.session.last_screenshot

    before, after, last = run(with_session(certs, body))
    assert before >= 1 and after == 0 and last is None


def test_runner_that_tampers_from_the_start_never_becomes_ready(certs):
    """The first capture of Startup Verification goes through the same check."""
    cert, key, pem = certs

    async def body():
        reg = SessionRegistry()
        rec = reg.issue(*SES)
        uploads = ObservationUploads()
        sessions = Sessions(reg, heartbeat_interval_s=5.0, profile=StartupProfile(step_timeout_s=2.0),
                            uploads=uploads)
        up = await start_upload_server(uploads, tls.server_context(cert, key), "127.0.0.1", 0)
        async with up, start_server(reg, cert, key, run_demo=False, host="127.0.0.1", port=0,
                                    sessions=sessions) as server:
            r = MiniRunner(server.sockets[0].getsockname()[1], pem, SES,
                           upload_port=up.sockets[0].getsockname()[1], upload_tamper=True)
            await r.connect(rec.token)
            await r.serve()
            return sessions.get(SES)

    session = run(body())
    assert session.terminated and session.startup.ok is False
    assert session.startup.reason.startswith("first_capture: no usable capture") and "sha256" in session.startup.reason
