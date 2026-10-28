"""router_capture / router_execute in the SCRP MCP (#94): a web page command, captured as data
on this computer, analyzed through sandbox_run's path inside the same Sandbox."""

import asyncio
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from host.mcp_server import HostBackend, load_tool_list
from host.policy import Policy
from host.router_capture import CaptureError, CaptureStore, page_url
from host.sandbox_run import RunError, SandboxRunner
from test_inbox_download import InboxManager, Watcher, downloader, server  # noqa: F401
from test_sandbox_launch import args as launch_args, paths, run
from test_sandbox_run import ID, Approver, FakeBroker, PassScanner, artifact_guest

ROOT = Path(__file__).resolve().parent.parent
SHOWN = "I am not a robot - Ray ID 7721"                                    # what the page shows
COPIED = 'powershell -NoProfile -Command "Write-Output clickfix-sample"'    # what its button copies


class Clipboard:
    def __init__(self, text, sequence=41):
        self.text, self.sequence, self.reads = text, sequence, 0

    def __call__(self):
        self.reads += 1
        return {"sequence": self.sequence, "text": self.text}


def store(tmp_path, text=COPIED):
    return CaptureStore(tmp_path / "captures", clipboard=Clipboard(text))


def capture(cs, rid="C1", **kw):
    return cs.capture({"request_id": rid, "source_url": "https://fake-captcha.example/verify?t=SECRET", **kw})


# --------------------------------------------------------------------- capture
def test_the_host_reads_what_the_page_copied_and_keeps_both(tmp_path):
    cs = store(tmp_path)
    got = capture(cs, text=SHOWN, clipboard=True)
    assert got["source_id"] == "CAP-0001-CLIP"                       # what the page actually copied
    assert got["clipboard_read_by_host"] and got["agent_text_matches_clipboard"] is False
    assert "notice" in got and got["execution_location"] == "SANDBOX" and not got["source_url_verified"]
    assert got["source_url"] == "https://fake-captcha.example/verify"           # no query (secrets)
    kinds = {s["kind"]: s for s in got["sources"]}
    assert kinds["host_clipboard"]["sha256"] == hashlib.sha256(COPIED.encode()).hexdigest()
    assert kinds["host_clipboard"]["clipboard_sequence"] == 41
    assert kinds["agent_text"]["sha256"] == hashlib.sha256(SHOWN.encode()).hexdigest()
    assert COPIED not in json.dumps(got) and SHOWN not in json.dumps(got)    # hashes, not the text
    assert cs.text("CAP-0001-CLIP") == COPIED and cs.text("CAP-0001-AGENT") == SHOWN
    assert "CAP-0001-CLIP" in cs.from_clipboard and "CAP-0001-AGENT" not in cs.from_clipboard


def test_matching_text_and_agent_only_captures(tmp_path):
    cs = store(tmp_path)
    assert capture(cs, "same", text=COPIED, clipboard=True)["agent_text_matches_clipboard"] is True
    only = capture(cs, "agent", text=SHOWN)
    assert only["source_id"] == "CAP-0002-AGENT" and not only["clipboard_read_by_host"]
    assert only["agent_text_matches_clipboard"] is None and cs.clipboard.reads == 1


def test_a_repeat_returns_the_same_capture_and_a_reused_id_is_refused(tmp_path):
    cs = store(tmp_path)
    first = capture(cs, clipboard=True)
    cs.clipboard.text = "something else now"
    again = capture(cs, clipboard=True)
    assert again["repeated"] and again["source_id"] == first["source_id"] and cs.clipboard.reads == 1
    with pytest.raises(CaptureError) as e:
        capture(cs, text="other")
    assert e.value.code == "IDEMPOTENCY_CONFLICT"
    assert cs.query("C1")["source_id"] == first["source_id"] and cs.query("nope") is None


@pytest.mark.parametrize("kw, code", [
    ({}, "INVALID_ARGUMENT"),                                        # neither text nor clipboard
    ({"clipboard": True, "source_url": "file:///C:/x"}, "INVALID_ARGUMENT"),
    ({"clipboard": True, "source_url": "https://user:pw@x.example/"}, "INVALID_ARGUMENT"),
    ({"text": "a\0b"}, "INVALID_ARGUMENT"),
])
def test_bad_captures_are_refused(tmp_path, kw, code):
    cs = store(tmp_path)
    with pytest.raises(CaptureError) as e:
        cs.capture({"request_id": "C1", "source_url": "https://x.example/", **kw})
    assert e.value.code == code


def test_an_empty_clipboard_is_not_a_capture(tmp_path):
    cs = store(tmp_path, text="")
    with pytest.raises(CaptureError) as e:
        capture(cs, clipboard=True)
    assert e.value.code == "INVALID_ARGUMENT" and not list((tmp_path / "captures").iterdir())


def test_a_changed_capture_file_no_longer_verifies(tmp_path):
    cs = store(tmp_path)
    capture(cs, clipboard=True)
    src, path = cs.sources["CAP-0001-CLIP"]
    assert cs.verify(src)
    path.write_text("powershell -Command \"evil\"", encoding="utf-8")
    assert not cs.verify(src)


def test_page_url_keeps_only_scheme_host_and_path():
    assert page_url("https://a.example:8443/p/q?x=1#f") == "https://a.example:8443/p/q"


# --------------------------------------------------------------------- execute (plan + launch)
def runner_with_capture(tmp_path, **kw):
    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    cs = store(tmp_path)
    capture(cs, text=SHOWN, clipboard=True, **kw)
    return SandboxRunner(inbox, captures=cs), cs, inbox


def execute_args(rid="X1", source_id="CAP-0001-CLIP", form="powershell-command", **kw):
    return {"request_id": rid, "source_id": source_id, "form": form, **kw}


def test_the_copied_command_becomes_a_script_in_the_inbox_bound_to_its_capture(tmp_path):
    runner, cs, inbox = runner_with_capture(tmp_path)
    plan, shown = runner.plan_capture(execute_args(), ID)
    script = inbox / "CAP-0001-CLIP.ps1"
    assert script.read_bytes() == b"\xef\xbb\xbf" + b"Write-Output clickfix-sample"
    assert shown["command"].endswith(r"-File C:\Users\WDAGUtilityAccount\Desktop\Input\CAP-0001-CLIP.ps1")
    assert shown["transform"] == "powershell-clipboard-to-batch-v2"
    derived, parent = plan.action.sources
    assert (derived.source_id, derived.parents, derived.origin) == ("CAP-0001-CLIP-PS1", ("CAP-0001-CLIP",),
                                                                    "generated")
    assert parent == cs.sources["CAP-0001-CLIP"][0] and plan.action.command.target_source == derived.source_id
    view = plan.view()
    assert view["request_id"] == "X1" and view["source_id"] == "CAP-0001-CLIP"


@pytest.mark.parametrize("args, code", [
    (execute_args(source_id="CAP-0009-CLIP"), "INVALID_ARGUMENT"),            # not captured
    (execute_args(source_id="CAP-0001-AGENT"), "INVALID_ARGUMENT"),           # -Command only from the clipboard
    (execute_args(source_id="CAP-0001-AGENT", form="powershell-script"), None),   # a script: allowed
    (execute_args(form="powershell-command-literal", start=0, end=5), "INVALID_ARGUMENT"),
    (execute_args(form="powershell-script"), "INVALID_ARGUMENT"),            # clipboard: never as a raw script
])
def test_what_may_be_derived(tmp_path, args, code):
    runner, _, _ = runner_with_capture(tmp_path)
    if code is None:
        runner.plan_capture(args, ID)
        return
    with pytest.raises(RunError) as e:
        runner.plan_capture(args, ID)
    assert e.value.code == code


def test_a_capture_changed_after_capturing_is_not_run(tmp_path):
    runner, cs, _ = runner_with_capture(tmp_path)
    cs.sources["CAP-0001-CLIP"][1].write_text("powershell -Command \"evil\"", encoding="utf-8")
    with pytest.raises(RunError) as e:
        runner.plan_capture(execute_args(), ID)
    assert e.value.code == "POLICY_DENIED"


def test_the_launch_types_exactly_the_derived_scripts_command(tmp_path):
    runner, _, inbox = runner_with_capture(tmp_path)
    broker = FakeBroker(runner)

    async def go():
        plan, _ = runner.plan_capture(execute_args(), ID)
        r = await runner.start(broker, plan)
        await r.task
        return r
    r = asyncio.run(go())
    assert r.state == "RUNNING" and r.dispatched
    manifest = json.loads((inbox / f"run-{r.nonce}.json").read_text(encoding="utf-8"))
    assert manifest["inputs"] == [{"path": r"C:\Users\WDAGUtilityAccount\Desktop\Input\CAP-0001-CLIP.ps1",
                                   "sha256": r.action.sources[0].sha256}]
    assert set(manifest["sources"]) == {"CAP-0001-CLIP-PS1", "CAP-0001-CLIP"}
    assert [t for t, _, _ in broker.calls if t != "computer_observe"] == \
        ["computer_hotkey", "computer_type", "computer_keypress"]


@pytest.mark.parametrize("tamper", ["capture", "script"])
def test_a_change_before_enter_never_gets_enter(tmp_path, tamper):
    runner, cs, inbox = runner_with_capture(tmp_path)

    def change():
        target = cs.sources["CAP-0001-CLIP"][1] if tamper == "capture" else inbox / "CAP-0001-CLIP.ps1"
        target.write_bytes(b"changed")
    broker = FakeBroker(runner, hooks={"computer_type": change})

    async def go():
        plan, _ = runner.plan_capture(execute_args(), ID)
        r = await runner.start(broker, plan)
        await r.task
        return r
    r = asyncio.run(go())
    assert (r.state, r.reason) == ("DENIED", "REASSESSMENT_REQUIRED") and not r.dispatched
    assert "computer_keypress" not in [t for t, _, _ in broker.calls]


def test_a_request_id_runs_once(tmp_path):
    runner, _, _ = runner_with_capture(tmp_path)
    broker = FakeBroker(runner)

    async def go():
        plan, _ = runner.plan_capture(execute_args(), ID)
        r = await runner.start(broker, plan)
        runner.bind_request(execute_args(), r)
        await r.task
        return r
    r = asyncio.run(go())
    assert runner.repeated(execute_args()) is r
    with pytest.raises(RunError) as e:
        runner.repeated(execute_args(form="powershell-script"))
    assert e.value.code == "IDEMPOTENCY_CONFLICT"
    assert runner.repeated(execute_args(rid="X2")) is None


def test_policy_rules():
    p = Policy()
    assert p.decide("router_capture", {}).rule_id == "P-ROUTER-CAPTURE"
    assert p.decide("router_execute", {}).rule_id == "P-ROUTER-EXECUTE"


# --------------------------------------------------------------------- through the MCP Host
def test_capture_execute_and_gui_in_one_sandbox(tmp_path, server):  # noqa: F811
    """One Host, one Sandbox: capture before task_submit, run the copied command there, then keep
    working the same Sandbox with computer_* tools. No second Sandbox, no approval dialog."""
    d, _ = downloader(tmp_path, server)
    fake = InboxManager(tmp_path / "sbx")
    approver = Approver([])
    clip = Clipboard(COPIED)
    stdout = "clickfix-sample\n".encode()

    async def body():
        a = launch_args(tmp_path)
        a.inbox, a.inbox_watcher, a.inbox_downloader, a.inbox_skip_exec_check = d.inbox, Watcher, d, True
        a.sandbox_run, a.router_capture, a.capture_clipboard = True, True, clip
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
                gap = 0.25 - (time.monotonic() - last[0])
                if gap > 0:
                    await asyncio.sleep(gap)
                for _ in range(20):
                    last[0] = time.monotonic()
                    res = await asyncio.to_thread(backend.call, tool, arguments or {})
                    got = json.loads(res["content"][-1]["text"])
                    if got.get("error") != "RATE_LIMITED":
                        return got
                    await asyncio.sleep(min(float(got.get("retry_after") or 0.3), 1.0))
                return got

            cap = await call("router_capture", {"request_id": "C1", "source_url": "https://fake.example/v?s=SECRET",
                                                "text": SHOWN, "clipboard": True})
            early = await call("router_execute", execute_args())                    # before task_submit
            await call("task_submit", {"goal": "가짜 CAPTCHA 명령 분석"})
            r, serving = await artifact_guest(*paths(tmp_path / "sbx"))
            for _ in range(60):
                if (await call("runtime_get_state"))["runtime_state"] == "READY":
                    break
            started = await call("router_execute", execute_args())
            again = await call("router_execute", execute_args())
            conflict = await call("router_execute", execute_args(form="powershell-script"))
            for _ in range(60):
                if any(m["payload"]["operation"] == "keyboard.press" for m in r.requests):
                    break
                await asyncio.sleep(0.1)
            manifest = json.loads(next(Path(d.inbox).glob("run-*.json")).read_text(encoding="utf-8"))
            receipt = {k: manifest[k] for k in ("run_id", "fingerprint", "nonce", "runtime_id", "generation",
                                                "command_sha256", "sources")}
            receipt.update(contract="sandbox-run-v1", process_id=4242, execution_count=1, exit_code=0,
                           stdout_sha256=hashlib.sha256(stdout).hexdigest())
            await r.report(f"run-{manifest['nonce']}-stdout.txt", stdout)
            await r.report(f"run-{manifest['nonce']}-receipt.txt", json.dumps(receipt).encode())
            status = {}
            for _ in range(80):
                status = await call("sandbox_run_status", {"run_id": started["run_id"]})
                if status.get("state") in ("SUCCEEDED", "FAILED", "HELD"):
                    break
                await asyncio.sleep(0.2)
            observed = await call("computer_observe", {})
            follow = await call("computer_click", {"x": 10, "y": 10})                  # same Sandbox, after the run
            stopped = await call("session_stop", {"reason": "TASK_COMPLETE"})
            assert stopped.get("ok"), stopped
            await asyncio.wait_for(serving, 10)
            audit = [json.loads(x) for x in (tmp_path / "audit" / "SES-TEST-001.jsonl").read_text(
                encoding="utf-8").splitlines()]
            return cap, early, started, again, conflict, status, observed, follow, r.requests, audit, fake.calls
        finally:
            await asyncio.to_thread(backend.shutdown)

    cap, early, started, again, conflict, status, observed, follow, requests, audit, calls = run(body())
    assert cap["ok"] and cap["source_id"] == "CAP-0001-CLIP" and cap["agent_text_matches_clipboard"] is False
    assert early["error"] == "POLICY_DENIED"                                   # task_submit first
    assert started["ok"] and started["state"] == "ACCEPTED" and started["request_id"] == "X1"
    assert again["ok"] and again["repeated"] and again["run_id"] == started["run_id"]
    assert conflict["error"] == "IDEMPOTENCY_CONFLICT"
    assert status["state"] == "SUCCEEDED" and status["stdout"] == "clickfix-sample\n"
    assert status["source_id"] == "CAP-0001-CLIP"
    assert observed["ok"] and follow["ok"], follow
    assert approver.calls == []
    ops = [m["payload"]["operation"] for m in requests if m["payload"]["operation"] != "screen.capture"]
    assert ops == ["keyboard.hotkey", "keyboard.type", "keyboard.press", "mouse.click"]    # once, then the GUI
    assert [c for c in calls if c[0] == "start"] == [("start",)]                # one Sandbox for all of it
    text = json.dumps(audit, ensure_ascii=False)
    assert COPIED not in text and SHOWN not in text and "SECRET" not in text
    cap_rec = next(x for x in audit if x["tool"] == "router_capture")
    assert cap_rec["policy"]["rule_id"] == "P-ROUTER-CAPTURE" and cap_rec["arguments"]["text"]["masked"]
    run_rec = next(x for x in audit if x["tool"] == "router_execute" and x["result"]["ok"])
    assert run_rec["policy"]["rule_id"] == "P-ROUTER-EXECUTE"
    assert [s["source_id"] for s in run_rec["result"]["run"]["sources"]] == ["CAP-0001-CLIP-PS1", "CAP-0001-CLIP"]


def test_router_tools_are_listed_only_when_switched_on(tmp_path):
    assert {"router_capture", "router_execute"} <= {t["name"] for t in load_tool_list({"host.router"})}
    assert "router_capture" not in {t["name"] for t in load_tool_list({"host.sandbox_run"})}
    r = subprocess.run([sys.executable, str(ROOT / "host" / "mcp_server.py"), "--router-capture",
                        "--log-file", str(tmp_path / "m.log")],
                       capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    assert r.returncode == 2 and "--router-capture needs --sandbox-run" in r.stderr


# --------------------------------------------------------------------- after the session ended
def test_snapshot_keeps_results_and_never_leaves_a_run_running(tmp_path):
    runner, _, _ = runner_with_capture(tmp_path)
    broker = FakeBroker(runner)

    async def go():
        plan, _ = runner.plan_capture(execute_args(), ID)
        r = await runner.start(broker, plan)
        runner.bind_request(execute_args(), r)
        await r.task
        return r
    r = asyncio.run(go())
    assert r.state == "RUNNING"
    snap = runner.snapshot()
    assert snap["runs"][r.run_id]["state"] == "UNKNOWN"                       # Enter was sent; result unknown
    assert snap["runs"][r.run_id]["reason"] == "SESSION_ENDED_RESULT_UNCONFIRMED"
    assert snap["requests"]["X1"][1] == r.run_id and "C1" in snap["captures"]
    assert r.state == "RUNNING"                                                 # the snapshot changes nothing


class EndedBackend:
    """What McpRuntime sees once a Host retired: no thread, results kept in final_runs."""

    def __init__(self, final_runs):
        from types import SimpleNamespace
        self.final_runs, self.cleanup_confirmed, self.error = final_runs, True, None
        self.session, self.final_status, self.calls = SimpleNamespace(terminated=True), {}, []

    def is_alive(self):
        return False

    def shutdown(self):
        pass

    def call(self, tool, args):
        self.calls.append(tool)
        raise AssertionError("an ended Host is never called")


def test_results_stay_queryable_after_the_session_ended_without_running_again(tmp_path):
    from host.mcp_runtime import McpRuntime
    runner, cs, _ = runner_with_capture(tmp_path)
    broker = FakeBroker(runner)

    async def go():
        plan, _ = runner.plan_capture(execute_args(), ID)
        r = await runner.start(broker, plan)
        runner.bind_request(execute_args(), r)
        await r.task
        return r
    r = asyncio.run(go())
    ended = EndedBackend(runner.snapshot())
    rt = McpRuntime(SimpleArgs(), lambda config: pytest.fail("no new Host for a query"))
    rt.backend = ended

    def call(tool, arguments):
        return json.loads(rt.call(tool, arguments)["content"][-1]["text"])
    status = call("sandbox_run_status", {"run_id": r.run_id})
    assert status["ok"] and status["state"] == "UNKNOWN" and status["session_ended"]
    again = call("router_execute", execute_args())
    assert again["ok"] and again["repeated"] and again["run_id"] == r.run_id
    assert call("router_execute", execute_args(form="powershell-script"))["error"] == "IDEMPOTENCY_CONFLICT"
    cap = call("router_capture", {"request_id": "C1", "source_url": "https://fake-captcha.example/verify?t=SECRET",
                                  "text": SHOWN, "clipboard": True})
    assert cap["ok"] and cap["source_id"] == "CAP-0001-CLIP" and cap["session_ended"]
    assert call("router_execute", execute_args(rid="NEW"))["error"] == "SESSION_TERMINATED"   # new work: task_submit
    assert call("sandbox_run_status", {"run_id": "RUN-0099"})["error"] == "INVALID_ARGUMENT"
    assert ended.calls == []


class SimpleArgs:
    session = None


def test_capture_and_execute_ids_are_separate(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    cs = store(tmp_path)
    capture(cs, "SAME", clipboard=True)
    runner = SandboxRunner(inbox, captures=cs)
    plan, _ = runner.plan_capture(execute_args(rid="SAME"), ID)                # #92: no clash
    assert plan.view()["request_id"] == "SAME" and cs.query("SAME")["source_id"] == "CAP-0001-CLIP"


def test_other_inputs_wait_for_the_launch_then_the_same_sandbox_is_worked_as_usual(tmp_path):
    runner, _, _ = runner_with_capture(tmp_path)
    seen = []

    def interleave():
        async def other_agent_input():
            seen.append(runner.policy.decide("computer_click", {"x": 1, "y": 1}).rule_id)
        asyncio.get_running_loop().create_task(other_agent_input())
    class YieldingBroker(FakeBroker):                                 # a real Broker awaits the Runner
        async def call(self, tool, args):
            await asyncio.sleep(0)
            return await super().call(tool, args)
    broker = YieldingBroker(runner, hooks={"computer_hotkey": interleave})

    async def go():
        plan, _ = runner.plan_capture(execute_args(), ID)
        r = await runner.start(broker, plan)
        await r.task
        return r
    r = asyncio.run(go())
    assert r.state == "RUNNING"
    assert seen == ["P-ROUTER-LAUNCH-BOUNDARY"]                       # refused while the launch holds the input
    assert runner.policy.decide("computer_click", {"x": 1, "y": 1}).result == "ALLOW"   # then the GUI as usual
