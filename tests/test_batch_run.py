"""batch_run (2026-11-26): every program packed in one zip runs in its own runtime, from one conversation.

- the Host reads only the zip's names; each program gets one more Host (tests/batch_child.py stands in for it)
- task_submit goes to one child at a time, so the first program gets the first choice of runtime
- sandbox_run is sent once per child; more programs than the limit start nothing
- session_stop is forwarded, and closing the connection lets every child stop its own runtime
"""

import json
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from host.batch_run import BatchError, BatchRunner, read_programs
from host.mcp_runtime import McpRuntime
from host.mcp_server import load_tool_list
from host.sandbox_project import inspect, script

CHILD = Path(__file__).with_name("batch_child.py")


def make_zip(folder, names, name="tools.zip"):
    folder.mkdir(exist_ok=True)
    path = folder / name
    with zipfile.ZipFile(path, "w") as z:
        for n in names:
            z.writestr(n, "MZ")
    return path


def calls(state):
    out = []
    for path in sorted(state.glob("calls-*.jsonl")):
        out.append([json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()])
    return out


def ended(runner, states, timeout=20):
    """batch_status is settled once every program is RUNNING or ended; wait for the states a test expects."""
    deadline = time.monotonic() + timeout
    while True:
        view = runner.status(1000)
        if [p["state"] for p in view["programs"]] == states or time.monotonic() > deadline:
            return view
        time.sleep(0.05)


@pytest.fixture
def batch(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    made = []

    def make(names, limit=3, *, extra=(), zip_name="tools.zip"):
        make_zip(tmp_path / "Downloads", names, zip_name)
        runner = BatchRunner(limit, tmp_path / "logs", command=[sys.executable, str(CHILD), str(state), *extra],
                             downloads=tmp_path / "Downloads", poll_s=0.05)
        made.append(runner)
        return runner, state
    yield make
    for runner in made:
        runner.shutdown(20)


def test_every_program_runs_in_its_own_host(batch):
    runner, state = batch(["a.exe", "b.exe", "c.exe", "readme.txt"])
    first = runner.start("tools.zip")
    assert first["count"] == 3 and not first["settled"] and "batch_status" in first["message"]
    assert runner.status(20000)["settled"]
    done = ended(runner, ["SUCCEEDED"] * 3)
    assert [(p["index"], p["entry"], p["state"], p["exit_code"]) for p in done["programs"]] == [
        (1, "a.exe", "SUCCEEDED", 0), (2, "b.exe", "SUCCEEDED", 0), (3, "c.exe", "SUCCEEDED", 0)]
    assert [p["stdout"] for p in done["programs"]] == ["hello from a.exe", "hello from b.exe", "hello from c.exe"]
    # the first program got the first choice (Windows Sandbox), the others a micro_VM
    assert [p["runtime_type"] for p in done["programs"]] == [
        "WINDOWS_SANDBOX", "MICRO_VM_APP_WINDOW", "MICRO_VM_APP_WINDOW"]
    assert all(p["runtime_open"] and p["session_id"] for p in done["programs"])
    logs = calls(state)
    assert len(logs) == 3                                  # three child Hosts
    runs = [c for log in logs for c in log if c["tool"] == "sandbox_run"]
    assert sorted(c["arguments"]["entry"] for c in runs) == ["a.exe", "b.exe", "c.exe"]       # once each
    assert all(c["arguments"]["file"] == "tools.zip" and c["child"] == "1" for c in runs)
    for log in logs:                                       # the zip goes in before the run, the run after READY
        tools = [c["tool"] for c in log]
        assert tools.index("task_submit") < tools.index("inbox_import") < tools.index("sandbox_run")


def test_a_host_that_is_still_starting_is_asked_again_but_the_run_is_sent_once(batch):
    runner, state = batch(["a.exe", "gui-b.exe"], extra=("slow",))
    runner.start("tools.zip")
    done = ended(runner, ["SUCCEEDED", "RUNNING"])
    assert [p["state"] for p in done["programs"]] == ["SUCCEEDED", "RUNNING"]       # a GUI program stays RUNNING
    for log in calls(state):
        assert [c["tool"] for c in log].count("task_submit") == 3
        assert [c["tool"] for c in log].count("sandbox_run") == 1


def test_more_programs_than_the_limit_start_nothing(batch):
    runner, state = batch(["a.exe", "b.exe", "c.exe", "d.exe"])
    with pytest.raises(BatchError) as e:
        runner.start("tools.zip")
    assert e.value.code == "POLICY_DENIED" and "at most 3" in e.value.message
    assert calls(state) == [] and runner.batch is None
    done = runner.start("tools.zip", ["d.exe", "b.exe"])    # the Agent may pick some of them
    assert [p["entry"] for p in done["programs"]] == ["d.exe", "b.exe"]


@pytest.mark.parametrize("names, name, entries, code", [
    (["a.exe"], "sub/tools.zip", None, "INVALID_ARGUMENT"),            # a path, not a name
    (["a.exe"], "tools.exe", None, "INVALID_ARGUMENT"),                # not a zip
    (["a.exe"], "other.zip", None, "INVALID_ARGUMENT"),                # not in Downloads
    (["readme.txt"], "tools.zip", None, "INVALID_ARGUMENT"),           # no program
    (["a.exe", "package.json"], "tools.zip", None, "INVALID_ARGUMENT"),   # a project: sandbox_run builds it
    (["a.exe"], "tools.zip", ["b.exe"], "INVALID_ARGUMENT"),           # not in the zip
    (["a.exe", "../b.exe"], "tools.zip", None, "POLICY_DENIED")])      # unsafe name
def test_what_cannot_be_a_batch_is_refused_before_any_host_starts(batch, names, name, entries, code):
    runner, state = batch(names)
    with pytest.raises(BatchError) as e:
        runner.start(name, entries)
    assert e.value.code == code and calls(state) == []


def test_installers_are_programs_too_and_named_scripts_may_run(tmp_path):
    path = make_zip(tmp_path, ["app.exe", "setup.msi", "tool.ps1", "job.py", "notes.txt"])
    assert read_programs(path, None) == ["app.exe", "setup.msi"]            # scripts only when they are named
    assert read_programs(path, ["tool.ps1", "setup.msi", "job.py"]) == ["tool.ps1", "setup.msi", "job.py"]
    with pytest.raises(BatchError) as e:
        read_programs(path, ["notes.txt"])                                  # not something that runs
    assert e.value.code == "INVALID_ARGUMENT"
    msi = script(inspect(path, "setup.msi", []), "tools.zip", "ab" * 32, "0" * 16, {})
    assert ("Invoke-Step 'install setup.msi' '%SystemRoot%\\System32\\msiexec.exe' '/i setup.msi' $true"
            in msi)                                                         # its install window, as for a single .msi
    ps1 = script(inspect(path, "tool.ps1", ["x y"]), "tools.zip", "ab" * 32, "0" * 16, {})
    assert "powershell.exe' '-NoProfile -ExecutionPolicy Bypass -File tool.ps1 \"x y\"' $true" in ps1


def test_programs_in_the_zips_single_top_folder(tmp_path):
    path = make_zip(tmp_path, ["pack/x/one.exe", "pack/two.EXE", "pack/notes.md"])
    assert read_programs(path, None) == ["two.EXE", "x/one.exe"]
    p = inspect(path, "x/one.exe", ["-v"])
    assert (p.kind, p.programs, p.root, p.entry) == ("exe", (), "pack", "x/one.exe")
    text = script(p, "tools.zip", "ab" * 32, "0" * 16, {})
    assert "tar.exe') -xf $zip" in text                      # unpacked inside the Sandbox
    assert "Invoke-Step 'run x/one.exe' 'x\\one.exe' '-v' $true" in text


def test_observe_stop_and_a_second_batch(batch):
    runner, state = batch(["gui-a.exe", "gui-b.exe"])
    with pytest.raises(BatchError):
        runner.status()                                    # nothing started yet
    runner.start("tools.zip")
    assert runner.status(20000)["settled"]
    seen = json.loads(runner.observe(2, 500)["content"][0]["text"])
    assert seen == {"ok": True, "screen": "screen of gui-b.exe", "wait_ms": 500}
    with pytest.raises(BatchError) as e:
        runner.observe(3)
    assert e.value.code == "INVALID_ARGUMENT"
    with pytest.raises(BatchError) as e:
        runner.start("tools.zip")                          # its runtimes are still open
    assert e.value.code == "POLICY_DENIED" and len(calls(state)) == 2
    assert runner.stop("USER_STOP") == [{"index": 1, "stopped": True}, {"index": 2, "stopped": True}]
    deadline = time.monotonic() + 10
    while runner.batch.open_children() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not runner.batch.open_children()
    assert not any(p["runtime_open"] for p in runner.status()["programs"])
    assert runner.stop("USER_STOP") is None                # nothing left to stop
    runner.start("tools.zip")                              # now a new batch may start
    assert runner.status(20000)["settled"]


def test_a_runtime_that_does_not_start_is_an_error_for_that_program_only(batch):
    runner, state = batch(["a.exe"])
    (state / "never-ready").write_text("")
    runner.start("tools.zip")
    assert not runner.status(300)["settled"]
    (state / "closed").write_text("")                      # its runtime ended before it was READY
    done = runner.status(10000)
    assert done["programs"][0]["state"] == "ERROR" and "RUNTIME_START_FAILED" in done["programs"][0]["error"]
    assert not [c for log in calls(state) for c in log if c["tool"] == "sandbox_run"]


def test_closing_the_connection_lets_every_child_stop_itself(batch):
    runner, state = batch(["gui-a.exe", "gui-b.exe"])
    runner.start("tools.zip")
    runner.status(20000)
    children = [c.client.process for c in runner.batch.children]
    runner.shutdown(20)
    assert all(p.poll() == 0 for p in children)            # they exited by themselves (stdin closed), not killed
    assert all(log[-1]["tool"] == "stdin-closed" for log in calls(state))
    with pytest.raises(BatchError) as e:
        runner.start("tools.zip")
    assert e.value.code == "SESSION_TERMINATED"


def body(result):
    return json.loads(result["content"][-1]["text"])


def test_the_tools_exist_only_with_batch_max(tmp_path):
    names = {"batch_run", "batch_status", "batch_observe"}
    assert not names & {t["name"] for t in load_tool_list({"host.inbox", "host.sandbox_run"})}
    assert names <= {t["name"] for t in load_tool_list({"host.batch"})}
    off = McpRuntime(SimpleNamespace(batch_max=0, log_file=tmp_path / "host.log"), None)
    refused = off.call("batch_run", {"name": "tools.zip"})
    assert refused["isError"] and body(refused)["error"] == "POLICY_DENIED"
    assert body(off.call("batch_run", {"name": "x"}))["error"] == "INVALID_ARGUMENT"       # schema first


def test_the_mcp_runtime_serves_the_batch_without_starting_its_own_host(batch, tmp_path):
    runner, state = batch(["a.exe", "gui-b.exe"])
    started = []
    runtime = McpRuntime(SimpleNamespace(batch_max=3, log_file=tmp_path / "host.log", session=None),
                         lambda config: started.append(config))
    runtime.batch = runner
    assert body(runtime.call("batch_run", {"name": "tools.zip"}))["count"] == 2
    assert body(runtime.call("batch_status", {"wait_ms": 20000}))["settled"]
    assert [p["state"] for p in ended(runner, ["SUCCEEDED", "RUNNING"])["programs"]] == ["SUCCEEDED", "RUNNING"]
    assert body(runtime.call("batch_observe", {"index": 2}))["screen"] == "screen of gui-b.exe"
    gone = runtime.call("batch_observe", {"index": 5})
    assert gone["isError"] and body(gone)["error"] == "INVALID_ARGUMENT"
    stopped = body(runtime.call("session_stop", {"reason": "USER_STOP"}))
    assert stopped["stopped"] and stopped["batch"] == [{"index": 1, "stopped": True}, {"index": 2, "stopped": True}]
    assert started == []                                   # this conversation's own Host was never started
    runtime.shutdown()
    assert body(runtime.call("batch_status", {}))["error"] == "SESSION_TERMINATED"
