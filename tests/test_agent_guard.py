"""--agent-guard: what Codex did on its own in the app (2026-10-12) now needs the person at the Host.

- session_stop asks first (SUSPICIOUS_CONTENT does not: a security stop is never held up); "no" keeps
  the Sandbox and tells the Agent to stop only when the user says so
- inbox_download asks only when a similar file is already in Downloads; "no" points to inbox_import
- without --agent-guard nothing changes
- the rules are in the tool descriptions too
"""

import asyncio
import json

import pytest

from host.approval import DUPLICATE_TITLE, STOP_TITLE, DialogApprover
from host.inbox_download import Downloader
from host.mcp_server import HostBackend, guard_descriptions, load_tool_list
from test_inbox_download import InboxManager, Watcher, downloader, server  # noqa: F401  (fixture)
from test_sandbox_launch import FakeManager, args as launch_args, guest, paths, run


def host(tmp_path, manager, approver, *, guard=True, inbox=None, dl=None):
    a = launch_args(tmp_path)
    a.agent_guard = guard
    if inbox is not None:
        a.inbox, a.inbox_watcher, a.inbox_skip_exec_check, a.inbox_downloader = inbox, Watcher, True, dl
    backend = HostBackend(a, sandbox_manager=manager, approver=approver)
    backend.start()
    assert backend.ready.wait(20) and not backend.error, backend.error

    async def call(tool, arguments):
        r = await asyncio.to_thread(backend.call, tool, arguments)
        return json.loads(r["content"][-1]["text"])
    return backend, call


def test_session_stop_asks_first_and_no_keeps_the_sandbox(tmp_path):
    fake = FakeManager(tmp_path / "sbx")
    answers, asked = [False, True], []

    async def approver(summary):
        asked.append((summary["tool"], summary.get("stop_reason")))
        return answers.pop(0)

    async def body():
        backend, call = host(tmp_path, fake, approver)
        await call("task_submit", {"goal": "설치"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        no = await call("session_stop", {"reason": "CANNOT_COMPLETE"})
        still = await call("runtime_get_state", {})
        yes = await call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving
        await asyncio.to_thread(backend.shutdown)
        return no, still, yes

    no, still, yes = run(body())
    assert no["error"] == "POLICY_DENIED" and "only when the user says" in no["message"]
    assert still["ok"] and still["runtime_state"] not in ("TERMINATED", "FAILED")   # the Sandbox stayed
    assert still["sandbox"]["state"] not in ("STOPPING", "STOPPED")
    assert yes["ok"] and yes["stopped"]
    assert asked == [("session_stop", "CANNOT_COMPLETE"), ("session_stop", "TASK_COMPLETE")]


def test_a_suspicious_content_stop_is_never_held_up(tmp_path):
    fake = FakeManager(tmp_path / "sbx")
    asked = []

    async def approver(summary):
        asked.append(summary["tool"])
        return False

    async def body():
        backend, call = host(tmp_path, fake, approver)
        await call("task_submit", {"goal": "열기"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        stop = await call("session_stop", {"reason": "SUSPICIOUS_CONTENT"})
        await serving
        await asyncio.to_thread(backend.shutdown)
        return stop

    assert run(body())["ok"] and asked == []


def test_without_the_guard_nothing_is_asked(tmp_path):
    fake = FakeManager(tmp_path / "sbx")

    async def approver(summary):
        raise AssertionError("asked without --agent-guard")

    async def body():
        backend, call = host(tmp_path, fake, approver, guard=False)
        await call("task_submit", {"goal": "열기"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        stop = await call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving
        await asyncio.to_thread(backend.shutdown)
        return stop

    assert run(body())["ok"]


def test_a_download_asks_only_when_a_similar_file_is_in_downloads(tmp_path, server, monkeypatch):
    monkeypatch.setattr("sandbox_manager.inbox.Path.home", lambda: tmp_path)
    server.routes["/tailscale-setup-1.102.4-amd64.msi"] = ("body", b"MSI")
    server.routes["/other-tool.exe"] = ("body", b"MZ")
    d, _ = downloader(tmp_path, server)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (downloads / "tailscale-setup-1.102.4.exe").write_bytes(b"MZ")
    d.downloads = downloads
    asked = []

    async def approver(summary):
        asked.append(summary.get("similar"))
        return False

    async def body():
        backend, call = host(tmp_path, InboxManager(tmp_path / "sbx"), approver, inbox=d.inbox, dl=d)
        dup = await call("inbox_download", {"url": f"{server.base}/tailscale-setup-1.102.4-amd64.msi"})
        other = await call("inbox_download", {"url": f"{server.base}/other-tool.exe"})
        await asyncio.to_thread(backend.shutdown)
        return dup, other

    dup, other = run(body())
    assert dup["error"] == "POLICY_DENIED" and "inbox_import" in dup["message"]
    assert "tailscale-setup-1.102.4.exe" in dup["message"]
    assert other["ok"]                                                     # nothing similar: no question
    assert asked == [["tailscale-setup-1.102.4.exe"]]
    assert not (d.inbox / "tailscale-setup-1.102.4-amd64.msi").exists()


def test_similar_names(tmp_path):
    for n in ("tailscale-setup-1.102.4.exe", "setup.exe", "ZoomIt.zip"):
        (tmp_path / n).write_bytes(b"x")
    d = Downloader(tmp_path / "inbox", downloads=tmp_path)
    assert d.similar("https://x.example/tailscale-setup-1.102.4-amd64.msi") == ["tailscale-setup-1.102.4.exe"]
    assert d.similar("https://x.example/setup-helper.msi") == []           # too short to count
    assert d.similar("https://x.example/other-tool.exe") == []


def test_dialog_texts():
    a = DialogApprover()
    title, text = a._question({"tool": "session_stop", "stop_reason": "CANNOT_COMPLETE"})
    assert title == STOP_TITLE and "끝낼까요" in text and "CANNOT_COMPLETE" in text
    title, text = a._question({"tool": "inbox_download", "url": "https://x/a.msi", "similar": ["a.exe"]})
    assert title == DUPLICATE_TITLE and "a.exe" in text


def test_the_rules_are_in_the_tool_descriptions():
    tools = load_tool_list({"host.inbox"})
    guard_descriptions(tools)
    d = {t["name"]: t["description"] for t in tools}
    assert "끝내" in d["session_stop"] and "never on your own" in d["session_stop"]
    assert "inbox_import" in d["inbox_download"]
    plain = {t["name"]: t["description"] for t in load_tool_list({"host.inbox"})}
    assert "끝내" not in plain["session_stop"]                              # only with the guard
