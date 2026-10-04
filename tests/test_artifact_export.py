"""artifact-export-v1 on the Host (Runner contract sandbox_runner 3270091).

The Host backend runs as in mcp_server.py with --artifact-export; ArtifactRunner
(tests/artifact_runner.py) plays the Runner over real WSS/HTTPS. Approver and
scanner are injected so each outcome can be forced; the product defaults
(dialog approval, no scanner → BLOCKED) are tested separately.
"""

import argparse
import asyncio
import hashlib
import json
import time
import uuid
from pathlib import Path

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from artifact_runner import ArtifactRunner, put_artifact
from host import tls
from host.artifact_scan import AmsiScanner, NoScanner, Verdict, check_format
from host.mcp_server import HostBackend, load_tool_list
from scrp.validate import ARTIFACT_EXPORT_V1, ProtocolError, validate

ROOT = Path(__file__).resolve().parent.parent
SES = "SES-ART-001"
HANGUL_TXT = "보고서\\결과.txt"
TEXT = "안녕하세요, 반출 시험입니다.\n두 번째 줄\n".encode("utf-8")


class Approver:
    def __init__(self, answer=True):
        self.answer, self.calls = answer, []

    async def __call__(self, summary):
        self.calls.append(summary)
        return self.answer


class Scanner:
    name = "fake"

    def __init__(self, verdict=None, delay=0.0, error=None):
        self.verdict = verdict or Verdict(True, "PASSED", "fake scanner: clean", "fake")
        self.delay, self.error, self.scanned = delay, error, []

    def scan(self, data, content_name):
        self.scanned.append(data)
        if self.delay:
            time.sleep(self.delay)
        if self.error:
            raise self.error
        return self.verdict


def make_args(tmp_path, **kw):
    a = argparse.Namespace(
        host="127.0.0.1", port=0, upload_port=0, session=SES, runtime="RT-SBX-001", generation=1,
        startup_timeout=20.0, advertise_address=None, bootstrap_out=tmp_path / "bootstrap.json",
        runner_exe=None, sandbox_root=None, cert_dir=tmp_path / "certs", audit_dir=tmp_path / "audit",
        artifact_export=True, approval="dialog", artifact_scanner="none", artifact_max_bytes=1024 * 1024,
        artifact_dir=tmp_path / "art", export_dir=tmp_path / "exp", session_tuning={}, artifact_tuning={})
    for k, v in kw.items():
        setattr(a, k, v)
    return a


class Host:
    def __init__(self, tmp_path, approver=None, scanner=None, **kw):
        self.tmp = tmp_path
        self.backend = HostBackend(make_args(tmp_path, **kw), approver=approver, scanner=scanner)
        self.backend.start()
        assert self.backend.ready.wait(20) and not self.backend.error, self.backend.error
        self.boot = json.loads((tmp_path / "bootstrap.json").read_text(encoding="utf-8"))

    async def call(self, tool, arguments=None):
        # stay under the Broker's 5 control calls per second
        gap = 0.22 - (time.monotonic() - getattr(self, "_last", 0.0))
        if gap > 0:
            await asyncio.sleep(gap)
        self._last = time.monotonic()
        r = await asyncio.to_thread(self.backend.call, tool, arguments or {})
        return json.loads(r["content"][-1]["text"])

    async def wait_ready(self, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = await self.call("runtime_get_state")
            if st.get("runtime_state") == "READY":
                return st
            await asyncio.sleep(0.3)
        raise AssertionError(f"not READY: {st}")

    async def wait_artifact(self, artifact_id, statuses=("EXPORTED", "BLOCKED"), timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            lst = await self.call("artifact_list", {})
            art = next(a for a in lst["artifacts"] if a["artifact_id"] == artifact_id)
            if art["status"] in statuses:
                return art
            await asyncio.sleep(0.3)
        raise AssertionError(f"{artifact_id} stuck: {art}")

    def runner(self, **kw):
        b = self.boot
        return ArtifactRunner(b["port"], b["host_certificate_pem"], (b["session_id"], b["runtime_id"], b["generation"]),
                              upload_port=b["observation_upload"]["port"], artifact_port=b["artifact_upload"]["port"],
                              **kw)

    async def start(self, **kw):
        r = self.runner(**kw)
        await r.connect(self.boot["token"])
        serving = asyncio.create_task(r.serve())
        await r.open_telemetry()
        await self.wait_ready()
        assert (await self.call("task_submit", {"goal": "결과 파일 반출"}))["ok"]
        return r, serving

    async def close(self, serving=None):
        await asyncio.to_thread(self.backend.shutdown)
        if serving is not None:
            try:
                await asyncio.wait_for(serving, 10)
            except asyncio.TimeoutError:
                pass


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


def candidate_id(lst, path):
    return next(a["artifact_id"] for a in lst["artifacts"] if a["path"] == path)


# --------------------------------------------------------------------- contract shape
def test_runner_examples_validate_only_under_the_profile():
    ex = json.loads((ROOT / "schema/profiles/artifact-export-v1/examples.json").read_text(encoding="utf-8"))
    msgs = ex["success_messages"] + [a["message"] if "message" in a else a for a in ex["alternate_responses"]]
    for m in msgs:
        validate(m, ARTIFACT_EXPORT_V1)
    assert len(msgs) == 14
    with pytest.raises(ProtocolError):
        validate(next(m for m in msgs if m["type"] == "SECURITY_EVENT"))      # base schema: unchanged
    bad = dict(next(m for m in msgs if m["type"] == "ARTIFACT_REQUEST"))
    bad["payload"] = {**bad["payload"], "url": "https://evil.example/"}
    with pytest.raises(ProtocolError):
        validate(bad, ARTIFACT_EXPORT_V1)


def test_bootstrap_selects_the_profile_only_when_asked(tmp_path):
    on = Host(tmp_path / "on", artifact_export=True)
    off = Host(tmp_path / "off", artifact_export=False)
    on.backend.shutdown(), off.backend.shutdown()
    assert on.boot["control_contract"] == "artifact-export-v1"
    assert on.boot["artifact_upload"] == {"port": on.boot["observation_upload"]["port"], "path": "/scrp/v1/artifacts/"}
    assert "control_contract" not in off.boot and "artifact_upload" not in off.boot
    names_on = {t["name"] for t in load_tool_list({"artifact.export.v1"})}
    names_off = {t["name"] for t in load_tool_list()}
    assert {"artifact_list", "artifact_export"} <= names_on and not {"artifact_list", "artifact_export"} & names_off


# --------------------------------------------------------------------- channel and startup
def test_telemetry_needs_its_own_token_and_is_required_before_ready(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner(), startup_timeout=30.0)
        r = host.runner()
        ack = await r.connect(host.boot["token"])
        assert "artifact.export.v1" in ack["payload"]["allowed_capabilities"]
        serving = asyncio.create_task(r.serve())
        refused = []
        # the bootstrap token (control kind) does not open Telemetry
        try:
            await r.open_telemetry(token=host.boot["token"])
        except InvalidStatus as e:
            refused.append(e.response.status_code)
        # the Telemetry token does not open Control
        try:
            await connect(f"wss://127.0.0.1:{host.boot['port']}/scrp/v1/control",
                          ssl=tls.client_context(host.boot["host_certificate_pem"]),
                          additional_headers={"Authorization": f"Bearer {r.telemetry_token}"}, open_timeout=5)
        except InvalidStatus as e:
            refused.append(e.response.status_code)
        st = await host.call("runtime_get_state")                  # verification waits for Telemetry
        await r.open_telemetry()
        await host.wait_ready()
        try:
            await r.open_telemetry()                                  # single use
        except InvalidStatus as e:
            refused.append(e.response.status_code)
        await host.close(serving)
        return refused, st

    refused, st = run(body())
    assert refused == [401, 401, 401]
    assert st["runtime_state"] == "PREPARING"


def test_startup_fails_without_telemetry_or_without_the_capability(tmp_path):
    async def no_channel():
        host = Host(tmp_path / "a", approver=Approver(), scanner=Scanner(),
                    artifact_tuning={"telemetry_wait_s": 1.0})
        r = host.runner()
        await r.connect(host.boot["token"])
        serving = asyncio.create_task(r.serve())
        await asyncio.wait_for(serving, 15)
        st = await host.call("runtime_get_state")
        await host.close()
        return st

    async def old_runner():
        host = Host(tmp_path / "b", approver=Approver(), scanner=Scanner())
        r = host.runner(capabilities=["gui.observe", "gui.input"])      # an older Runner
        refused = None
        try:
            await r.connect(host.boot["token"])
            await asyncio.wait_for(r.serve(), 10)
        except Exception as e:  # noqa: BLE001
            refused = type(e).__name__
        st = await host.call("runtime_get_state")
        await host.close()
        return st

    a, b = run(no_channel()), run(old_runner())
    assert a["error"] == "SESSION_TERMINATED" and "telemetry" in a["message"]
    assert b["error"] == "SESSION_TERMINATED" and "artifact.export.v1" in b["message"]


def test_duplicate_events_are_stored_once_and_conflicting_ones_rejected(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        r, serving = await host.start()
        ev = str(uuid.uuid4())
        first = await r.report("a.txt", b"x", event_id=ev)
        again = await r.report("a.txt", b"x", event_id=ev,
                               payload_override=None)                 # same id; observed_at differs → other payload
        same_payload = {"event_id": str(uuid.uuid4()), "observed_at": "2026-10-03T03:00:00.123Z",
                        "category": "ARTIFACT_CANDIDATE", "relative_path": "b.txt"}
        b1 = await r.report("b.txt", b"y", event_id=same_payload["event_id"], payload_override=same_payload)
        b2 = await r.report("b.txt", b"y", event_id=same_payload["event_id"], payload_override=same_payload)
        lst = await host.call("artifact_list", {})
        await host.close(serving)
        return first, again, b1, b2, lst

    first, again, b1, b2, lst = run(body())
    assert first["status"] == "STORED" and again["status"] == "REJECTED"
    assert again["error"] == {"code": "STORAGE_REJECTED"}
    assert b1["status"] == b2["status"] == "STORED"
    assert [a["path"] for a in lst["artifacts"]] == ["a.txt", "b.txt"]                 # no duplicate
    pending = lst["artifacts"][0]
    assert pending["status"] == "PENDING" and pending["size_bytes"] is None and pending["sha256"] is None
    assert "unverified" in pending


# --------------------------------------------------------------------- the whole way
@pytest.mark.parametrize("path,data", [(HANGUL_TXT, TEXT), ("빈파일.txt", b"")])
def test_export_korean_text_and_empty_file_end_to_end(tmp_path, path, data):
    approver, scanner = Approver(), Scanner()

    async def body():
        host = Host(tmp_path, approver=approver, scanner=scanner)
        r, serving = await host.start()
        ack = await r.report(path, data)
        lst = await host.call("artifact_list", {})
        aid = candidate_id(lst, path)
        accepted = await host.call("artifact_export", {"artifact_id": aid, "reason": "사용자가 결과 파일을 요청"})
        final = await host.wait_artifact(aid)
        again = await host.call("artifact_export", {"artifact_id": aid})          # idempotent
        await host.close(serving)
        return ack, accepted, final, again, r

    ack, accepted, final, again, r = run(body())
    assert ack["status"] == "STORED"
    assert accepted["ok"] and accepted["accepted"] and accepted["status"] == "PENDING"
    assert final["status"] == "EXPORTED", final
    exported = Path(final["export_path"])
    assert exported.read_bytes() == data and exported.name == Path(path.replace("\\", "/")).name
    assert final["size_bytes"] == len(data) and final["sha256"] == hashlib.sha256(data).hexdigest()
    assert r.puts == [(201, b"")]                                              # empty 201
    assert scanner.scanned == [data]                                           # the same bytes were inspected
    assert again["ok"] and again["status"] == "EXPORTED" and len(r.artifact_requests) == 1, again
    assert len(approver.calls) == 1                                            # asked once, not for the repeat
    assert approver.calls[0]["path"] == path and approver.calls[0]["arguments"]["reason"].startswith("사용자")
    req = r.artifact_requests[0]["payload"]
    assert len(req["upload_token"]) == 43 and req["max_bytes"] == 1024 * 1024
    assert req["upload_token"] not in json.dumps(final) + json.dumps(accepted)  # never shown to the Agent
    assert not list((tmp_path / "art" / "incoming").glob("*"))                 # quarantine empty


def test_denied_approval_sends_nothing(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(answer=False), scanner=Scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"x")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        res = await host.call("artifact_export", {"artifact_id": aid})
        lst = await host.call("artifact_list", {})
        await host.close(serving)
        return res, lst, r

    res, lst, r = run(body())
    assert res["error"] == "POLICY_DENIED" and "did not approve" in res["message"]
    assert r.artifact_requests == [] and lst["artifacts"][0]["status"] == "PENDING"
    assert lst["artifacts"][0]["can_export"]


def test_default_dialog_and_no_scanner_never_export(tmp_path):
    """Product defaults: nobody answers the dialog here (approver=deny), no scanner configured."""
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=None)                 # scanner from --artifact-scanner none
        r, serving = await host.start()
        await r.report("a.txt", b"hello\n")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        final = await host.wait_artifact(aid)
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "SCANNER_UNAVAILABLE"
    assert final["export_path"] is None and not list((tmp_path / "exp").rglob("*.txt"))


# --------------------------------------------------------------------- inspection outcomes
@pytest.mark.parametrize("scanner,path,data,code", [
    (Scanner(Verdict(False, "MALWARE_DETECTED", "fake detection", "fake")), "a.txt", b"x", "MALWARE_DETECTED"),
    (Scanner(error=RuntimeError("engine crashed")), "a.txt", b"x", "SCAN_ERROR"),
    (Scanner(delay=2.0), "a.txt", b"x", "SCAN_TIMEOUT"),
    (Scanner(), "tool.exe", b"MZ", "FORMAT_NOT_ALLOWED"),
    (Scanner(), "a.txt", b"\xff\xfe\x00bad", "NOT_UTF8"),
])
def test_inspection_failures_block_and_publish_nothing(tmp_path, scanner, path, data, code):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=scanner, artifact_tuning={"scan_timeout_s": 0.5})
        r, serving = await host.start()
        await r.report(path, data)
        aid = candidate_id(await host.call("artifact_list", {}), path)
        await host.call("artifact_export", {"artifact_id": aid})
        final = await host.wait_artifact(aid)
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == code, final
    assert final["export_path"] is None and not final["can_export"]
    assert not list((tmp_path / "exp").rglob("*")) or not any(p.is_file() for p in (tmp_path / "exp").rglob("*"))
    assert not list((tmp_path / "art" / "incoming").glob("*"))                    # blocked bytes deleted


# --------------------------------------------------------------------- transfer failures
def test_runner_refusals_and_mismatches(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        r, serving = await host.start()
        out = {}
        # candidate changed or deleted in the Guest
        ack = await r.report("gone.txt", b"x")
        r.unavailable.add(ack["payload"]["event_id"])
        aid = candidate_id(await host.call("artifact_list", {}), "gone.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        out["unavailable"] = await host.wait_artifact(aid)
        # Runner reports a different byte count than the Host received
        await r.report("lie.txt", b"abc")
        r.wrong_bytes_sent = True
        aid = candidate_id(await host.call("artifact_list", {}), "lie.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        out["mismatch"] = await host.wait_artifact(aid)
        r.wrong_bytes_sent = False
        # Runner says UPLOADED without uploading
        await r.report("noput.txt", b"abc")
        r.skip_put = True
        aid = candidate_id(await host.call("artifact_list", {}), "noput.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        out["noput"] = await host.wait_artifact(aid)
        r.skip_put = False
        # a wrong token: 403, the Runner reports UPLOAD_FAILED, a new attempt is allowed
        await r.report("token.txt", b"abc")
        r.put_token_override = "A" * 43
        aid = candidate_id(await host.call("artifact_list", {}), "token.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        out["token"] = await host.wait_artifact(aid)
        out["token_puts"] = list(r.puts)
        r.put_token_override = None
        await host.call("artifact_export", {"artifact_id": aid})                   # retry: new grant
        out["retry"] = await host.wait_artifact(aid)
        await host.close(serving)
        return out

    out = run(body())
    assert out["unavailable"]["result"]["code"] == "CANDIDATE_UNAVAILABLE" and not out["unavailable"]["can_export"]
    assert out["mismatch"]["result"]["code"] == "RESULT_MISMATCH" and "bytes_sent" in out["mismatch"]["result"]["detail"]
    assert out["noput"]["result"]["code"] == "RESULT_MISMATCH" and "not received" in out["noput"]["result"]["detail"]
    assert out["token_puts"][-1][0] == 403
    assert out["token"]["result"]["code"] == "UPLOAD_FAILED" and out["token"]["can_export"]
    assert out["retry"]["status"] == "EXPORTED"
    for k in ("unavailable", "mismatch", "noput", "token"):
        assert out[k]["status"] == "BLOCKED" and out[k]["export_path"] is None


def test_result_never_arrives(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner(),
                    artifact_tuning={"upload_lifetime_s": 1.0, "result_grace_s": 0.5})
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        r.skip_result = True
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        final = await host.wait_artifact(aid)
        await host.close(serving)
        return final, r

    final, r = run(body())
    assert r.puts == [(201, b"")]                                    # the Host had the file ...
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "RESULT_MISSING"     # ... and did not publish it
    assert not list((tmp_path / "art" / "incoming").glob("*"))


def test_session_end_and_lost_channel_cancel_unfinished_exports(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        await r.report("b.txt", b"def")
        lst = await host.call("artifact_list", {})
        a, b = candidate_id(lst, "a.txt"), candidate_id(lst, "b.txt")
        r.hold_put = asyncio.Event()                                 # transfer of a stays open
        await host.call("artifact_export", {"artifact_id": a})
        busy = await host.call("artifact_export", {"artifact_id": b})
        await r.tws.close()                                          # Telemetry lost
        await asyncio.sleep(0.5)
        after = await host.call("artifact_export", {"artifact_id": b})
        lst = await host.call("artifact_list", {})
        r.hold_put.set()
        await asyncio.sleep(0.5)
        await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        await host.close(serving)
        return busy, after, lst, r

    busy, after, lst, r = run(body())
    assert busy.get("error") == "ARTIFACT_BUSY" and busy["retryable"], busy
    # the channel loss cancelled b as well: asking again reports that and starts nothing
    assert after["status"] == "BLOCKED" and after["result"]["code"] == "TELEMETRY_LOST" and not after["can_export"]
    assert len(r.artifact_requests) == 1
    a = lst["artifacts"][0]
    assert a["status"] == "BLOCKED" and a["result"]["code"] == "TELEMETRY_LOST"
    assert r.puts and r.puts[-1][0] in (410, 403)                    # the late PUT is refused
    assert not list((tmp_path / "exp").rglob("*.txt"))


# --------------------------------------------------------------------- receiver rules
def test_receiver_refusals(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner(), artifact_max_bytes=8,
                    artifact_tuning={"upload_lifetime_s": 30.0})
        r, serving = await host.start()
        grants = host.backend.artifacts.grants
        port, pem = host.boot["artifact_upload"]["port"], host.boot["host_certificate_pem"]
        ident = host.backend.session.identity
        g, tok = grants.issue(ident, "ART-X", str(uuid.uuid4()), 8, 30.0)
        res = {}
        res["no_token"] = await asyncio.to_thread(put_artifact, port, pem, g.upload_id, None, b"abc")
        res["bad_token"] = await asyncio.to_thread(put_artifact, port, pem, g.upload_id, "B" * 43, b"abc")
        res["unknown"] = await asyncio.to_thread(put_artifact, port, pem, "u_" + "C" * 30, tok, b"abc")
        res["png_type"] = await asyncio.to_thread(put_artifact, port, pem, g.upload_id, tok, b"abc",
                                                  content_type="image/png")
        res["chunked"] = await asyncio.to_thread(put_artifact, port, pem, g.upload_id, tok, b"abc",
                                                 extra_headers={"Content-Encoding": "gzip"})
        res["ok"] = await asyncio.to_thread(put_artifact, port, pem, g.upload_id, tok, b"abc")   # still usable
        res["reuse"] = await asyncio.to_thread(put_artifact, port, pem, g.upload_id, tok, b"abc")
        g2, tok2 = grants.issue(ident, "ART-Y", str(uuid.uuid4()), 8, 30.0)
        res["too_big"] = await asyncio.to_thread(put_artifact, port, pem, g2.upload_id, tok2, b"123456789")
        res["after_too_big"] = await asyncio.to_thread(put_artifact, port, pem, g2.upload_id, tok2, b"1")
        g3, tok3 = grants.issue(ident, "ART-Z", str(uuid.uuid4()), 8, 0.2)
        await asyncio.sleep(0.4)
        res["expired"] = await asyncio.to_thread(put_artifact, port, pem, g3.upload_id, tok3, b"1")
        g4, tok4 = grants.issue(ident, "ART-W", str(uuid.uuid4()), 8, 30.0)
        grants.cancel(g4)
        res["cancelled"] = await asyncio.to_thread(put_artifact, port, pem, g4.upload_id, tok4, b"1")
        held = g.path.read_bytes() if g.path else None
        await host.close(serving)
        return res, held, g

    res, held, g = run(body())
    assert res["no_token"][0] == 401 and res["bad_token"][0] == 403 and res["unknown"][0] == 403
    assert res["png_type"][0] == 415 and res["chunked"][0] == 415
    assert res["ok"] == (201, b"") and res["reuse"][0] == 409
    assert res["too_big"][0] == 413 and res["after_too_big"][0] == 409          # a refused grant is spent
    assert res["expired"][0] == 410 and res["cancelled"][0] == 410
    assert g.size == 3 and g.sha256 == hashlib.sha256(b"abc").hexdigest()


# --------------------------------------------------------------------- scanner units
def test_amsi_is_trusted_only_after_it_detects_eicar(monkeypatch):
    s = AmsiScanner()
    monkeypatch.setattr(s, "providers", lambda: ["{fake}"])
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr(s, "_scan_raw", lambda data, name: Verdict(True, "PASSED", "no detection (AMSI result 1)"))
    ok, why = s.available()
    assert not ok and "EICAR" in why
    assert s.scan(b"hello", "a.txt").code == "SCANNER_UNAVAILABLE"
    s2 = AmsiScanner()
    monkeypatch.setattr(s2, "providers", lambda: ["{fake}"])
    monkeypatch.setattr(s2, "_scan_raw", lambda data, name: Verdict(False, "MALWARE_DETECTED", "x")
                        if b"EICAR" in data else Verdict(True, "PASSED", "no detection"))
    assert s2.available()[0] and s2.scan(b"hello", "a.txt").ok
    assert NoScanner().scan(b"x", "a.txt").code == "SCANNER_UNAVAILABLE"


def test_format_policy():
    assert check_format("결과.TXT", "한글".encode()) is None
    assert check_format("a.txt", b"") is None
    assert check_format("a.exe", b"x").code == "FORMAT_NOT_ALLOWED"
    assert check_format("a.txt", b"a\x00b").code == "NOT_UTF8"
    assert check_format("a.txt", "x".encode("utf-16")).code == "NOT_UTF8"


def test_control_drop_during_a_transfer_fails_it_and_nothing_is_published(tmp_path):
    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        r.hold_put = asyncio.Event()
        await host.call("artifact_export", {"artifact_id": aid})
        await asyncio.sleep(0.3)
        r.drop()                                                     # Control connection gone mid-transfer
        await serving
        final = await host.wait_artifact(aid)
        r.hold_put.set()                                             # the Runner's PUT arrives late
        await asyncio.sleep(1.0)
        await host.close()
        return final, r

    final, r = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "RUNTIME_UNAVAILABLE"
    assert r.puts and r.puts[-1][0] == 410                           # its grant was revoked
    assert not any(p.is_file() for p in (tmp_path / "exp").rglob("*"))


def test_approval_dialog_text_marks_untrusted_parts():
    from host.approval import describe
    text = describe({"tool": "artifact_export", "session_id": "SES-1", "path": "보고서\결과.txt",
                     "arguments": {"artifact_id": "ART-1", "reason": "줄\n바꿈\x07" + "가" * 500}})
    assert "보고서\결과.txt" in text and "확인되지 않은 내용" in text
    assert "\x07" not in text and "줄 바꿈" in text and len(text) < 1200


# --------------------------------------------------------------------- review 2026-10-04
def test_nothing_is_shown_as_exported_before_the_final_check(tmp_path, monkeypatch):
    """Review finding 1: EXPORTED and export_path were visible while the final hash was still
    being computed. Now the final check runs first; until then: SCANNING, no file, no path."""
    import host.artifacts as artifacts_mod
    real = artifacts_mod._sha_stream

    def slow(f):
        time.sleep(1.5)                                    # the final check takes a while
        return real(f)
    monkeypatch.setattr(artifacts_mod, "_sha_stream", slow)

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"hello\n")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        seen = []
        for _ in range(12):
            art = (await host.call("artifact_list", {}))["artifacts"][0]
            files = [p for p in (tmp_path / "exp").rglob("*") if p.is_file()]
            seen.append((art["status"], art["export_path"], len(files)))
            if art["status"] == "EXPORTED":
                break
        await host.close(serving)
        return seen

    seen = run(body())
    assert seen[-1][0] == "EXPORTED" and seen[-1][1] and seen[-1][2] == 1
    before = seen[:-1]
    assert before and all(s != "EXPORTED" and p is None and n == 0 for s, p, n in before), seen


def test_a_file_that_changed_before_publishing_is_never_shown(tmp_path, monkeypatch):
    import host.artifacts as artifacts_mod
    monkeypatch.setattr(artifacts_mod, "_sha_stream", lambda f: "0" * 64)      # bytes no longer match

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"hello\n")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        final = await host.wait_artifact(aid)
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "CONTENT_CHANGED"
    assert final["export_path"] is None and not any(p.is_file() for p in (tmp_path / "exp").rglob("*"))
    assert not list((tmp_path / "art" / "incoming").glob("*"))


def test_publish_lock_refuses_writers(tmp_path):
    import os
    import stat
    import sys
    from host.artifacts import _open_locked, _sha_stream
    f = tmp_path / "x.part"
    f.write_bytes(b"hello")
    os.chmod(f, stat.S_IREAD)
    locked = _open_locked(f)
    try:
        if sys.platform == "win32":
            os.chmod(f, stat.S_IWRITE)                      # even with the read-only flag cleared
            with pytest.raises(PermissionError):
                open(f, "r+b")
        assert _sha_stream(locked) == hashlib.sha256(b"hello").hexdigest()
        os.rename(f, tmp_path / "final.txt")               # moving it stays possible
    finally:
        locked.close()
    assert (tmp_path / "final.txt").read_bytes() == b"hello"


def test_approval_wait_fits_inside_the_mcp_call_limit():
    """Review finding 2: the dialog waited 120 s while the MCP call gave up after 60 s."""
    from host import approval, mcp_server
    assert approval.APPROVAL_TIMEOUT_S < mcp_server.CALL_TIMEOUT_S
    assert approval.DialogApprover().timeout_s == approval.APPROVAL_TIMEOUT_S


def test_a_cancelled_approval_closes_its_dialog_and_a_late_yes_issues_nothing(tmp_path, monkeypatch):
    import threading
    from host import mcp_server
    from host.approval import DialogApprover

    class FakeDialog(DialogApprover):
        """The real DialogApprover flow; only the native window is replaced."""
        def __init__(self):
            super().__init__(timeout_s=30)
            self.release, self.dismissed = threading.Event(), []

        def _ask(self, text, title=""):
            self.release.wait(10)                          # the user answers late ...
            return True                                    # ... with Yes

        def _dismiss(self, title):
            self.dismissed.append(title)
            self.release.set()

    dialog = FakeDialog()
    monkeypatch.setattr(mcp_server, "CALL_TIMEOUT_S", 1.0)   # the MCP call gives up first

    async def body():
        host = Host(tmp_path, approver=dialog, scanner=Scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"x")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        res = await host.call("artifact_export", {"artifact_id": aid})
        await asyncio.sleep(1.0)
        lst = await host.call("artifact_list", {})
        await host.close(serving)
        return res, lst, r

    res, lst, r = run(body())
    assert res["error"] == "ACTION_TIMEOUT"
    assert dialog.dismissed and dialog.dismissed[0].startswith("SCRP 파일 반출 승인 #")
    assert r.artifact_requests == []                        # the late Yes did not issue a grant
    assert lst["artifacts"][0]["status"] == "PENDING" and lst["artifacts"][0]["can_export"]
