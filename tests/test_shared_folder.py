"""--shared: a new folder per session, mapped writable into the Sandbox (배주한 요청 2026-10-15).

- the Host makes <root>\\<session> at task_submit and hands it to prepare(shared=...)
- it is swept for links while the session runs (SharedWatcher) and finished at session end:
  a clean folder is copied to Downloads\\SandboxShared and reported in runtime_get_state
- the Agent is told in task_submit's description where to save what should reach this computer
"""

import asyncio
import json

import pytest

from host.mcp_server import HostBackend, SHARED_RULE, load_tool_list, main, shared_description
from test_inbox_download import Watcher
from test_sandbox_launch import FakeManager, args as launch_args, guest, paths, run


class SharedManager(FakeManager):
    def prepare(self, session_id, runtime_id, generation, runner_exe, shared=None):
        self.calls.append(("prepare_shared", str(shared)))
        return super().prepare(session_id, runtime_id, generation, runner_exe)


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr("sandbox_manager.inbox.Path.home", lambda: tmp_path / "home")
    monkeypatch.setattr("sandbox_manager.shared.check_no_execute", lambda folder: None)
    r = tmp_path / "work" / "shared"
    r.mkdir(parents=True)
    return r


def test_task_submit_tells_the_agent_where_to_save():
    tools = load_tool_list()
    shared_description(tools)
    submit = next(t for t in tools if t["name"] == "task_submit")
    assert submit["description"].endswith(SHARED_RULE)
    assert "Desktop\\Shared" in SHARED_RULE and "Downloads\\SandboxShared" in SHARED_RULE


def test_shared_needs_the_runner_and_a_safe_folder(tmp_path):
    with pytest.raises(SystemExit):
        main(["--shared", str(tmp_path)])                   # no --runner-exe


def test_through_the_mcp_host_the_session_folder_is_mapped_and_finished(tmp_path, root):
    fake = SharedManager(tmp_path / "sbx")
    Watcher.made = []
    finished = []

    def finish(share):
        finished.append(share)
        return {"status": "EXPORTED", "share": str(share), "dest": "D:\\Downloads\\SandboxShared\\x",
                "files": [{"name": "note.pdf", "size": 3}], "scan": "clean: ok", "events": []}

    async def body():
        a = launch_args(tmp_path)
        a.shared, a.shared_watcher, a.finish_shared = root, Watcher, finish
        backend = HostBackend(a, sandbox_manager=fake)
        backend.start()
        assert backend.ready.wait(20) and not backend.error, backend.error

        async def call(tool, arguments):
            r = await asyncio.to_thread(backend.call, tool, arguments)
            return json.loads(r["content"][-1]["text"])
        await call("task_submit", {"goal": "PDF 받아서 남기기"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        during = await call("runtime_get_state", {})
        await call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving
        for _ in range(100):
            if finished:
                break
            await asyncio.sleep(0.05)
        after = backend.launcher.status()
        await asyncio.to_thread(backend.shutdown)
        return during, after

    during, after = run(body())
    share = root.resolve() / fake.calls[0][1].rsplit("\\", 1)[-1]
    assert fake.calls[0][0] == "prepare_shared" and share.is_dir()
    assert finished == [share]
    assert Watcher.made and Watcher.made[0].started and Watcher.made[0].stopped
    assert during["sandbox"]["shared"]["host_folder"] == str(share)
    assert during["sandbox"]["shared"]["guest_folder"] == "Desktop\\Shared"
    assert after["shared"]["at_end"]["status"] == "EXPORTED"
