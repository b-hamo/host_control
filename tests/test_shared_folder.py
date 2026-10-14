"""--shared: a new folder per session, mapped writable into the Sandbox (배주한 요청 2026-10-15).

- the Host makes <root>\\<session> at task_submit and hands it to prepare(shared=...)
- it is swept for links while the session runs (SharedWatcher) and finished at session end:
  for a clean folder the person chooses keep (Downloads\\SandboxShared), delete, or hold (no answer)
- the Agent is told in task_submit's description where to save what should reach this computer
"""

import asyncio
import json

import pytest

from host.approval import describe_shared
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


def test_the_dialog_lists_the_files_and_the_three_answers():
    text = describe_shared({"files": [{"name": "App\\7z.exe", "size": 1234}, {"name": "note.pdf", "size": 20}],
                            "share": "C:\\w\\SES-1"})
    assert "App\\7z.exe" in text and "note.pdf" in text and "합계 2개" in text
    assert "예: 다운로드" in text and "아니요: 지움" in text and "무응답: 지우지 않고" in text


def through_host(tmp_path, root, chooser, outcome):
    """One session with --shared; finish_shared is faked but calls decide() like the real one."""
    fake = SharedManager(tmp_path / "sbx")
    Watcher.made = []
    finished, asked = [], []

    def finish(share, decide):
        result = {"share": str(share), "dest": None, "files": [{"name": "note.pdf", "size": 3, "sha256": "ab"}],
                  "scan": "clean: ok", "events": []}
        choice = decide(result | {"status": "CLEAN"})
        finished.append((share, choice))
        return result | {"status": {"keep": "EXPORTED", "delete": "DELETED"}.get(choice, "HELD")}

    async def choose(summary):
        asked.append(summary)
        return outcome

    async def body():
        a = launch_args(tmp_path)
        a.shared, a.shared_watcher, a.finish_shared = root, Watcher, finish
        a.shared_chooser = choose if chooser else None
        backend = HostBackend(a, sandbox_manager=fake, approver=None if chooser else _no_dialog)
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
    assert Watcher.made and Watcher.made[0].started and Watcher.made[0].stopped
    assert during["sandbox"]["shared"]["host_folder"] == str(share)
    assert during["sandbox"]["shared"]["guest_folder"] == "Desktop\\Shared"
    return share, finished, asked, after


async def _no_dialog(summary):
    return False                                            # an approver without choose_shared


@pytest.mark.parametrize("answer, status", [("keep", "EXPORTED"), ("delete", "DELETED"), ("hold", "HELD")])
def test_through_the_mcp_host_the_person_chooses_at_session_end(tmp_path, root, answer, status):
    share, finished, asked, after = through_host(tmp_path, root, True, answer)
    assert finished == [(share, answer)]
    assert asked[0]["share"] == str(share) and asked[0]["files"][0]["name"] == "note.pdf"
    assert after["shared"]["at_end"]["status"] == status


def test_with_nobody_to_ask_a_clean_folder_is_held(tmp_path, root):
    share, finished, asked, after = through_host(tmp_path, root, False, None)
    assert finished == [(share, "hold")] and asked == []
    assert after["shared"]["at_end"]["status"] == "HELD"
