"""router_execute / sandbox_run for other languages (배주한 2026-11-05): a Python, JavaScript (Node.js), Ruby or
sh script runs inside the Sandbox, unchanged, with the interpreter program_share lends from this computer.

- a *-script form takes the whole Agent capture as that language's file (no BOM, no transform)
- a clipboard capture still runs only as powershell-command; a range is refused
- the command waits for the interpreter: the Broker shares it right before the run, or refuses
- sandbox_run does the same for a downloaded .py/.js/.rb/.sh
"""

import asyncio
import hashlib
from types import SimpleNamespace

import pytest
from pathlib import Path

from host.broker import Broker, BrokerError
from host.sandbox_run import INTERPRETER_PENDING, RunError, SandboxRunner
from test_router_capture import capture, store
from test_sandbox_run import ID

CODE = "import sys\nprint('hello', sum(range(1, 101)))\n"


def runner_with_agent_capture(tmp_path, text=CODE, clipboard=False):
    inbox = tmp_path / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    cs = store(tmp_path, text=text)
    capture(cs, text=text, clipboard=clipboard)
    return SandboxRunner(inbox, captures=cs), inbox


def execute_args(form, rid="X1", source_id="CAP-0001-AGENT", **kw):
    return {"request_id": rid, "source_id": source_id, "form": form, **kw}


@pytest.mark.parametrize("form, suffix, program", [
    ("python-script", ".py", "python"), ("javascript-script", ".js", "node"),
    ("ruby-script", ".rb", "ruby"), ("sh-script", ".sh", "git")])
def test_a_script_capture_becomes_that_languages_file_unchanged(tmp_path, form, suffix, program):
    runner, inbox = runner_with_agent_capture(tmp_path)
    plan, shown = runner.plan_capture(execute_args(form), ID)
    script = inbox / f"CAP-0001-AGENT{suffix}"
    assert script.read_bytes() == CODE.encode("utf-8")                    # as captured: no BOM, no rewrite
    assert shown["transform"] == "identity" and plan.program == program
    derived, parent = plan.action.sources
    assert derived.source_id == f"CAP-0001-AGENT-{suffix[1:].upper()}" and derived.parents == ("CAP-0001-AGENT",)
    assert derived.sha256 == hashlib.sha256(CODE.encode("utf-8")).hexdigest()
    assert plan.action.command.executable == INTERPRETER_PENDING
    assert plan.action.command.argv == (rf"C:\Users\WDAGUtilityAccount\Desktop\Input\CAP-0001-AGENT{suffix}",)


def test_a_clipboard_capture_or_a_range_is_not_a_script(tmp_path):
    runner, _ = runner_with_agent_capture(tmp_path, text='powershell -Command "x"', clipboard=True)
    with pytest.raises(RunError) as e:
        runner.plan_capture(execute_args("python-script", source_id="CAP-0001-CLIP"), ID)
    assert e.value.code == "INVALID_ARGUMENT"
    runner, _ = runner_with_agent_capture(tmp_path / "b")
    with pytest.raises(RunError) as e:
        runner.plan_capture(execute_args("python-script", start=0, end=3), ID)
    assert e.value.code == "INVALID_ARGUMENT"


def test_the_shared_interpreter_goes_into_the_command(tmp_path):
    runner, _ = runner_with_agent_capture(tmp_path)
    plan, _ = runner.plan_capture(execute_args("python-script"), ID)
    before = plan.action.fingerprint
    runner.with_interpreter(plan, {"exe": r"C:\Tools\python\python.exe"})
    assert plan.action.command.executable == r"C:\Tools\python\python.exe" and plan.program is None
    assert plan.action.fingerprint != before                             # the delegation binds the final command
    sh, _ = runner.plan_capture(execute_args("sh-script", rid="X2"), ID)
    with pytest.raises(RunError):
        runner.with_interpreter(sh, {"exe": r"C:\Tools\git\cmd\git.exe"})   # a Git without a shell
    runner.with_interpreter(sh, {"exe": r"C:\Tools\git\cmd\git.exe", "shell": r"C:\Tools\git\bin\bash.exe"})
    assert sh.action.command.executable == r"C:\Tools\git\bin\bash.exe"


def test_a_downloaded_script_waits_for_its_interpreter_too(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for name in ("tool.py", "app.js", "a.ps1"):
        (inbox / name).write_bytes(b"print(1)")
    runner = SandboxRunner(inbox)
    for name in ("tool.py", "app.js", "a.ps1"):
        runner.register({"final_url": f"https://x.example/{name}",
                         "file": {"name": name, "size": 8, "sha256": hashlib.sha256(b"print(1)").hexdigest()}})
    assert runner.plan("tool.py", ["--fast"], ID)[0].program == "python"
    assert runner.plan("tool.py", ["--fast"], ID)[0].action.command.argv[1:] == ("--fast",)
    assert runner.plan("app.js", [], ID)[0].program == "node"
    assert runner.plan("a.ps1", [], ID)[0].program is None               # PowerShell is in the Sandbox already


class Launcher:
    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.asked = answer, error, []

    async def share_program(self, name):
        self.asked.append(name)
        if self.error:
            raise self.error
        return self.answer


def test_the_broker_lends_the_interpreter_or_refuses(tmp_path):
    from sandbox_manager import SandboxManagerError
    runner, _ = runner_with_agent_capture(tmp_path)
    plan, _ = runner.plan_capture(execute_args("python-script"), ID)
    off = SimpleNamespace(programs=False, launcher=None, runner=runner)
    with pytest.raises(BrokerError) as e:
        asyncio.run(Broker._lend_interpreter(off, plan))
    assert e.value.code == "POLICY_DENIED"
    missing = SimpleNamespace(programs=True, runner=runner,
                              launcher=Launcher(error=SandboxManagerError("INVALID_ARGUMENT", "python is not installed")))
    with pytest.raises(BrokerError) as e:
        asyncio.run(Broker._lend_interpreter(missing, plan))
    assert e.value.code == "INVALID_ARGUMENT"
    on = SimpleNamespace(programs=True, runner=runner, launcher=Launcher({"exe": r"C:\Tools\python\python.exe"}))
    asyncio.run(Broker._lend_interpreter(on, plan))
    assert on.launcher.asked == ["python"] and plan.action.command.executable == r"C:\Tools\python\python.exe"
    asyncio.run(Broker._lend_interpreter(on, plan))                     # nothing left to lend
    assert on.launcher.asked == ["python"]


def test_a_language_run_shows_its_error_output_too(tmp_path):
    """11/7: python/C/... runs ask the Guest helper for stderr after stdout; PowerShell runs stay as they were."""
    runner, _ = runner_with_agent_capture(tmp_path)
    assert runner.plan_capture(execute_args("python-script"), ID)[0].with_stderr
    assert runner.plan_capture(execute_args("c-source", rid="X2"), ID)[0].with_stderr
    assert not runner.plan_capture(execute_args("powershell-script", rid="X3"), ID)[0].with_stderr
    helper = (Path(__file__).resolve().parents[1] / "host" / "sandbox_run_guest.ps1").read_text(encoding="utf-8")
    assert "$request.stderr -eq 'append'" in helper and helper.isascii()     # PowerShell 5.1 reads it as ANSI


def test_status_can_wait_for_the_run_to_end(tmp_path, monkeypatch):
    """11/7: Codex gave up after 14 s on a RUNNING run; wait_ms keeps checking until it ends (capped)."""
    import host.sandbox_run as sr
    runner, _ = runner_with_agent_capture(tmp_path)
    plan, _ = runner.plan_capture(execute_args("python-script"), ID)
    runner.runs[plan.run_id] = plan
    states = iter(["ACCEPTED", "RUNNING", "SUCCEEDED"])

    async def once(broker, run):
        run.state = next(states)
        return run.view()
    monkeypatch.setattr(runner, "_status_once", once)
    monkeypatch.setattr(sr, "STATUS_POLL_S", 0.01)
    assert asyncio.run(runner.status(None, plan.run_id, wait_ms=5000))["state"] == "SUCCEEDED"
    states = iter(["RUNNING"] * 1000)
    assert asyncio.run(runner.status(None, plan.run_id, wait_ms=50))["state"] == "RUNNING"   # time is up
    assert asyncio.run(runner.status(None, plan.run_id))["state"] == "RUNNING"               # default: at once
