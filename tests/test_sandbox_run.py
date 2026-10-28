"""sandbox_run: GUI mode + Router parts (download on the Host, run inside the Sandbox after approval).

- plan: only files inbox_download fetched in this session, exact command shown, a changed file refused
- the Agent still cannot press Win+R; an approved run gets exactly Win+R, its launch line, Enter
- the file is checked again right before Enter; a change means Enter is never sent
- a result counts only from a matching receipt (exit code, stdout hash); the run's own result
  files need no dialog, anything else still asks
- through the MCP Host end to end: no approval dialog (P-SANDBOX-RUN allows), real WSS Runner stand-in,
  artifact export of the receipt and stdout, audit, inbox helpers removed afterwards
"""

import asyncio
import hashlib
import json
import struct
import zlib
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_runner import ArtifactRunner
from host.broker import ToolResult
from host.mcp_server import HostBackend, load_tool_list
from host.sandbox_run import EMPTY_SHA256, RunError, SandboxRunner, screen_change
from test_inbox_download import BODY, InboxManager, Watcher, downloader, server  # noqa: F401
from test_sandbox_launch import args as launch_args, paths, run

ROOT = Path(__file__).resolve().parent.parent
ID = ("SES-TEST-001", "RT-SBX-001", 1)


def registered(tmp_path, name="ZoomIt64.exe", data=b"MZ fake program"):
    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    (inbox / name).write_bytes(data)
    runner = SandboxRunner(inbox)
    runner.register({"final_url": "https://download.example/ZoomIt64.exe?sig=SECRET",
                     "file": {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}})
    return runner, inbox


def screen(dialog=False, text=False, clock=0, w=64, h=100):
    """A grey desktop; the Run dialog fills rows 50-80, its typed line rows 70-73, the clock the last rows."""
    rows = []
    for y in range(h):
        shade = 40
        if dialog and 50 <= y < 80:
            shade = 200
        if text and 70 <= y < 73:
            shade = 10
        if y >= h - 4:
            shade = 90 + clock
        rows.append(b"\x00" + bytes([shade]) * w)
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))


class FakeBroker:
    """Just enough Broker: every call goes through the runner's policy, inputs are 'delivered',
    and the screen shows what a real Sandbox would (Run dialog after Win+R, the line after typing)."""

    def __init__(self, runner, hooks=None, dialog_opens=True, text_shows=True):
        self.session = SimpleNamespace(identity=ID, actions={})
        self.policy, self.hooks, self.calls, self.n = runner.policy, hooks or {}, [], 0
        self.dialog_opens, self.text_shows = dialog_opens, text_shows
        self.dialog = self.text = False
        self.clock = 0

    async def call(self, tool, args):
        d = self.policy.decide(tool, args)
        self.calls.append((tool, args, d.rule_id))
        if d.result == "DENY":
            return ToolResult(False, error={"error": "POLICY_DENIED"})
        if tool in self.hooks:
            self.hooks[tool]()
        self.n += 1
        if tool == "computer_observe":
            self.clock += 1                                    # the taskbar clock keeps changing
            return ToolResult(True, {"status": "OK"}, action_id=f"A-{self.n}",
                              image=screen(self.dialog, self.text, self.clock))
        if tool == "computer_hotkey":
            self.dialog = self.dialog_opens
        if tool == "computer_type":
            self.text = self.dialog and self.text_shows
        return ToolResult(True, {"status": "SUCCESS", "result": {"input_delivered": True}}, action_id=f"A-{self.n}")


async def launched(runner, broker, file="ZoomIt64.exe", arguments=()):
    plan, shown = runner.plan(file, list(arguments), ID)
    r = await runner.start(broker, plan)
    await r.task
    return r, shown


# --------------------------------------------------------------------- plan
def test_only_downloads_run_and_the_exact_command_is_shown(tmp_path):
    runner, inbox = registered(tmp_path)
    (inbox / "setup.zip").write_bytes(b"PK")
    runner.register({"final_url": "https://x.example/setup.zip",
                     "file": {"name": "setup.zip", "size": 2, "sha256": hashlib.sha256(b"PK").hexdigest()}})
    (inbox / "other.exe").write_bytes(b"MZ")                       # in the folder, but not downloaded
    for name, code in (("other.exe", "INVALID_ARGUMENT"), ("setup.zip", "INVALID_ARGUMENT")):
        with pytest.raises(RunError) as e:
            runner.plan(name, [], ID)
        assert e.value.code == code
    plan, shown = runner.plan("zoomit64.EXE", ["/accepteula"], ID)
    assert shown["command"] == r"C:\Users\WDAGUtilityAccount\Desktop\Input\ZoomIt64.exe /accepteula"
    assert shown["source"] == "https://download.example/ZoomIt64.exe"            # no query (secrets)
    assert shown["sha256"] == hashlib.sha256(b"MZ fake program").hexdigest()
    (inbox / "ZoomIt64.exe").write_bytes(b"MZ swapped")
    with pytest.raises(RunError) as e:
        runner.plan("ZoomIt64.exe", [], ID)
    assert e.value.code == "POLICY_DENIED"


# --------------------------------------------------------------------- launch
def test_an_approved_run_types_exactly_its_command(tmp_path):
    runner, inbox = registered(tmp_path)
    assert runner.policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "ALLOW"    # POL-0.1.1
    broker = FakeBroker(runner)
    r, _ = asyncio.run(launched(runner, broker, arguments=["/accepteula"]))
    assert r.state == "RUNNING" and r.dispatched
    inputs = [(t, a, rule) for t, a, rule in broker.calls if t != "computer_observe"]
    assert [t for t, _, _ in inputs] == ["computer_hotkey", "computer_type", "computer_keypress"]
    assert inputs[0][2] == "P-ALLOW-DEFAULT"
    line = inputs[1][1]["text"]
    assert line.startswith(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") and len(line) < 259
    assert rf"C:\Inbox\run-{r.nonce}.ps1" in line and rf"-Manifest C:\Inbox\run-{r.nonce}.json" in line
    manifest = json.loads((inbox / f"run-{r.nonce}.json").read_text(encoding="utf-8"))
    assert manifest["executable"] == r"C:\Users\WDAGUtilityAccount\Desktop\Input\ZoomIt64.exe"
    assert manifest["argument_line"] == "/accepteula"
    assert manifest["inputs"] == [{"path": manifest["executable"],
                                   "sha256": hashlib.sha256(b"MZ fake program").hexdigest()}]
    assert (inbox / f"run-{r.nonce}.ps1").read_bytes() == (ROOT / "host" / "sandbox_run_guest.ps1").read_bytes()
    # after the launch the base rules are back: admin keys denied, Win+R allowed
    assert runner.policy.decide("computer_hotkey", {"keys": ["win", "x"]}).rule_id == "P-DENY-HOTKEY"
    assert runner.policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "ALLOW"


def test_a_file_changed_before_enter_never_gets_enter(tmp_path):
    runner, inbox = registered(tmp_path)
    broker = FakeBroker(runner, hooks={"computer_type": lambda: (inbox / "ZoomIt64.exe").write_bytes(b"MZ evil")})
    r, _ = asyncio.run(launched(runner, broker))
    assert (r.state, r.reason) == ("DENIED", "REASSESSMENT_REQUIRED") and not r.dispatched
    assert "computer_keypress" not in [t for t, _, _ in broker.calls]


def test_a_changed_helper_in_the_inbox_never_gets_enter(tmp_path):
    runner, inbox = registered(tmp_path)

    def tamper():
        for p in inbox.glob("run-*.json"):
            p.write_text("{}", encoding="utf-8")
    broker = FakeBroker(runner, hooks={"computer_type": tamper})
    r, _ = asyncio.run(launched(runner, broker))
    assert r.state == "DENIED" and "computer_keypress" not in [t for t, _, _ in broker.calls]


def test_the_clock_alone_is_not_a_change_but_a_dialog_and_a_typed_line_are():
    assert screen_change(screen(clock=1), screen(clock=9)) == 0.0             # taskbar left out
    assert screen_change(screen(), screen(dialog=True)) >= 0.05
    assert 0.004 <= screen_change(screen(dialog=True), screen(dialog=True, text=True)) < 0.05
    assert screen_change(b"not a png", screen()) is None


def test_nothing_is_typed_when_the_run_dialog_never_shows(tmp_path):
    runner, _ = registered(tmp_path)
    broker = FakeBroker(runner, dialog_opens=False)
    r, _ = asyncio.run(launched(runner, broker))
    assert (r.state, r.reason) == ("FAILED", "LAUNCH_SURFACE_NOT_SEEN") and not r.dispatched
    sent = [t for t, _, _ in broker.calls if t != "computer_observe"]
    assert sent == ["computer_hotkey"]                                    # no line, no Enter


def test_enter_is_not_pressed_when_the_typed_line_never_shows(tmp_path):
    runner, _ = registered(tmp_path)
    broker = FakeBroker(runner, text_shows=False)
    r, _ = asyncio.run(launched(runner, broker))
    assert (r.state, r.reason) == ("FAILED", "LAUNCH_TEXT_NOT_SEEN") and not r.dispatched
    assert "computer_keypress" not in [t for t, _, _ in broker.calls]


# --------------------------------------------------------------------- results
def receipt(r, **kw):
    a = r.action
    from router.models import digest
    body = {"contract": "sandbox-run-v1", "run_id": r.run_id, "fingerprint": a.fingerprint, "nonce": r.nonce,
            "runtime_id": ID[1], "generation": ID[2], "command_sha256": digest(a.command),
            "sources": {s.source_id: s.sha256 for s in a.sources}, "process_id": 4242, "execution_count": 1,
            "exit_code": 0, "stdout_sha256": EMPTY_SHA256}
    body.update(kw)
    return json.dumps(body).encode()


def test_a_result_counts_only_from_a_receipt_for_this_exact_run(tmp_path):
    runner, inbox = registered(tmp_path)
    r, _ = asyncio.run(launched(runner, FakeBroker(runner)))
    out = "결과 1줄\n".encode()
    ok = runner._validate(r, receipt(r, stdout_sha256=hashlib.sha256(out).hexdigest()))
    assert ok["exit_code"] == 0
    for bad in (receipt(r, nonce="0" * 16), receipt(r, fingerprint="f" * 64), receipt(r, generation=2),
                receipt(r, execution_count=2), receipt(r, process_id=0), b"[]"):
        with pytest.raises(ValueError):
            runner._validate(r, bad)
    not_ready = receipt(r, execution_count=0, failure="INPUT_NOT_READY")
    assert runner._validate(r, not_ready)["failure"] == "INPUT_NOT_READY"


def test_only_the_runs_own_result_files_skip_the_dialog(tmp_path):
    runner, _ = registered(tmp_path)
    r, _ = asyncio.run(launched(runner, FakeBroker(runner)))
    r.exports.add("ART-000007")
    own = {"tool": "artifact_export", "artifact_id": "ART-000007", "session_id": ID[0], "runtime_id": ID[1],
           "path": r.evidence_name}
    assert runner.approve_export(own) is True
    assert runner.approve_export({**own, "path": "secrets.txt"}) is False
    assert runner.approve_export({**own, "artifact_id": "ART-000009"}) is None     # not ours: the dialog asks


# --------------------------------------------------------------------- through the MCP Host
class Approver:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    async def __call__(self, summary):
        self.calls.append(summary)
        return self.answers.pop(0)


class PassScanner:
    name = "fake"

    def scan(self, data, content_name):
        from host.artifact_scan import Verdict
        return Verdict(True, "PASSED", "fake scanner: clean", "fake")


async def artifact_guest(ready_path, bootstrap_path, timeout=15):
    deadline = time.monotonic() + timeout
    while not ready_path.exists():
        assert time.monotonic() < deadline, "no ready marker"
        await asyncio.sleep(0.05)
    b = json.loads(bootstrap_path.read_text(encoding="utf-8"))
    r = ArtifactRunner(b["port"], b["host_certificate_pem"], (b["session_id"], b["runtime_id"], b["generation"]),
                       upload_port=b["observation_upload"]["port"], artifact_port=b["artifact_upload"]["port"])
    await r.connect(b["token"])
    serving = asyncio.create_task(r.serve())
    await r.open_telemetry()
    return r, serving


def test_download_run_and_result_through_the_mcp_host(tmp_path, server):  # noqa: F811
    server.routes["/ZoomIt64.exe"] = ("body", BODY)
    d, _ = downloader(tmp_path, server)
    fake = InboxManager(tmp_path / "sbx")
    approver = Approver([])                     # nobody may be asked: sandbox_run needs no approval
    stdout = "ZoomIt 4.x\n".encode()

    async def body():
        a = launch_args(tmp_path)
        a.inbox, a.inbox_watcher, a.inbox_downloader, a.inbox_skip_exec_check = d.inbox, Watcher, d, True
        a.sandbox_run = True
        for k, v in dict(artifact_export=True, approval="dialog", artifact_scanner="none",
                         artifact_max_bytes=1024 * 1024, artifact_dir=tmp_path / "art", export_dir=tmp_path / "exp",
                         session_tuning={}, artifact_tuning={}).items():
            setattr(a, k, v)
        backend = HostBackend(a, sandbox_manager=fake, approver=approver, scanner=PassScanner())
        backend.start()
        try:
            assert backend.ready.wait(20) and not backend.error, backend.error
            last = [0.0]

            async def call(tool, arguments=None):
                gap = 0.25 - (time.monotonic() - last[0])         # under the Broker's control rate
                if gap > 0:
                    await asyncio.sleep(gap)
                for _ in range(20):
                    last[0] = time.monotonic()
                    res = await asyncio.to_thread(backend.call, tool, arguments or {})
                    got = json.loads(res["content"][-1]["text"])
                    if got.get("error") != "RATE_LIMITED":     # the run's own result checks share the control rate
                        return got
                    await asyncio.sleep(min(float(got.get("retry_after") or 0.3), 1.0))   # retry as an Agent would
                return got

            got = await call("inbox_download", {"url": f"{server.base}/ZoomIt64.exe?sig=SECRET"})
            early = await call("sandbox_run", {"file": got["file"]["name"]})          # before task_submit
            await call("task_submit", {"goal": "ZoomIt 받아서 Sandbox에서 실행"})
            r, serving = await artifact_guest(*paths(tmp_path / "sbx"))
            for _ in range(60):
                if (await call("runtime_get_state"))["runtime_state"] == "READY":
                    break
            own_win_r = await call("computer_hotkey", {"keys": ["win", "r"]})
            started = await call("sandbox_run", {"file": got["file"]["name"], "reason": "실행해 보기"})
            for _ in range(60):                                                         # wait for Enter
                if any(m["payload"]["operation"] == "keyboard.press" for m in r.requests):
                    break
                await asyncio.sleep(0.1)
            # the Guest helper's part: read the manifest from the inbox, report stdout and the receipt
            manifest = json.loads(next(Path(d.inbox).glob("run-*.json")).read_text(encoding="utf-8"))
            nonce = manifest["nonce"]
            receipt = {k: manifest[k] for k in ("run_id", "fingerprint", "nonce", "runtime_id", "generation",
                                                "command_sha256", "sources")}
            receipt.update(contract="sandbox-run-v1", process_id=4242, execution_count=1, exit_code=0,
                           stdout_sha256=hashlib.sha256(stdout).hexdigest())
            await r.report(f"run-{nonce}-stdout.txt", stdout)
            await r.report(f"run-{nonce}-receipt.txt", json.dumps(receipt).encode())
            status = {}
            for _ in range(80):
                status = await call("sandbox_run_status", {"run_id": started["run_id"]})
                if status.get("state") in ("SUCCEEDED", "FAILED", "HELD"):
                    break
                await asyncio.sleep(0.2)
            left = sorted(p.name for p in Path(d.inbox).glob("run-*"))
            stopped = await call("session_stop", {"reason": "TASK_COMPLETE"})
            assert stopped.get("ok") and stopped.get("stopped"), stopped
            await asyncio.wait_for(serving, 10)
            audit = [json.loads(x) for x in (tmp_path / "audit" / "SES-TEST-001.jsonl").read_text(encoding="utf-8").splitlines()]
            return early, own_win_r, started, status, left, r.requests, audit
        finally:
            await asyncio.to_thread(backend.shutdown)

    early, own_win_r, started, status, left, requests, audit = run(body())
    assert early["error"] == "POLICY_DENIED"                                     # task_submit first
    assert own_win_r["ok"]                                                      # POL-0.1.1: allowed
    assert started["ok"] and started["state"] == "ACCEPTED"
    assert status["state"] == "SUCCEEDED" and status["exit_code"] == 0 and status["stdout"] == "ZoomIt 4.x\n"
    assert approver.calls == []                     # neither the run nor its own result exports asked anyone
    ops = [m["payload"]["operation"] for m in requests if m["payload"]["operation"] != "screen.capture"]
    # the Agent's own Win+R, then the run's three inputs, once, never repeated
    assert ops == ["keyboard.hotkey", "keyboard.hotkey", "keyboard.type", "keyboard.press"]
    assert left == []                                                             # helpers removed
    rec = next(x for x in audit if x["tool"] == "sandbox_run" and x["result"]["ok"])
    assert rec["policy"]["rule_id"] == "P-SANDBOX-RUN" and rec["result"]["run"]["command"][0].endswith("ZoomIt64.exe")
    assert "SECRET" not in json.dumps(audit)


def test_sandbox_run_is_listed_and_allowed_only_when_switched_on(tmp_path):
    assert {"sandbox_run", "sandbox_run_status"} <= {t["name"] for t in load_tool_list({"host.sandbox_run"})}
    assert "sandbox_run" not in {t["name"] for t in load_tool_list({"host.inbox"})}
    r = subprocess.run([sys.executable, str(ROOT / "host" / "mcp_server.py"), "--sandbox-run",
                        "--log-file", str(tmp_path / "m.log")],
                       capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    assert r.returncode == 2 and "--sandbox-run needs --inbox" in r.stderr
