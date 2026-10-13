"""End of a session with the shared inbox (team request 2026-10-11: default delete, keep = Downloads).

- the Host empties the inbox when the session ends (stop → cleanup), the folder itself stays
- inbox_finish(keep): the kept items are copied to Downloads, marked as from the Internet, the rest is
  deleted; a refused name keeps and deletes nothing (sandbox_manager finish_inbox)
- keeping anything needs the person at the Host (P-INBOX-KEEP); keeping nothing does not
"""

import asyncio
import json

import pytest

from host.approval import KEEP_TITLE, DialogApprover
from host.inbox_download import Downloader, DownloadError
from host.mcp_server import HostBackend, load_tool_list
from host.policy import Policy
from test_inbox_download import InboxManager, Watcher
from test_sandbox_launch import args as launch_args, guest, paths, run


@pytest.fixture
def folders(tmp_path, monkeypatch):
    monkeypatch.setattr("sandbox_manager.inbox.Path.home", lambda: tmp_path)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    inbox = tmp_path / "SecureCUA" / "inbox"
    inbox.mkdir(parents=True)
    (inbox / "tool.exe").write_bytes(b"MZtool")
    (inbox / "ZoomIt").mkdir()
    (inbox / "ZoomIt" / "ZoomIt64.exe").write_bytes(b"MZ64")
    return downloads, inbox


def zone(path):
    try:
        with open(f"{path}:Zone.Identifier", encoding="ascii", newline="") as f:
            return f.read()
    except OSError:
        return ""


def test_kept_items_go_to_downloads_marked_and_the_rest_is_deleted(folders):
    downloads, inbox = folders
    done = Downloader(inbox, downloads=downloads).finish(["ZoomIt"])
    assert (downloads / "ZoomIt" / "ZoomIt64.exe").read_bytes() == b"MZ64"
    assert "ZoneId=3" in zone(downloads / "ZoomIt" / "ZoomIt64.exe")
    assert done["deleted_files"] == 2 and list(inbox.iterdir()) == []
    assert inbox.is_dir()                                                 # the folder stays


def test_a_refused_name_keeps_and_deletes_nothing(folders):
    downloads, inbox = folders
    with pytest.raises(DownloadError) as e:
        Downloader(inbox, downloads=downloads).finish(["tool.exe", "..\\..\\Documents"])
    assert e.value.code == "POLICY_DENIED"
    assert (inbox / "tool.exe").is_file() and list(downloads.iterdir()) == []


def test_keeping_needs_approval_keeping_nothing_does_not():
    p = Policy()
    assert p.decide("inbox_finish", {"keep": ["a.exe"]}).rule_id == "P-INBOX-KEEP"
    assert p.decide("inbox_finish", {"keep": ["a.exe"]}).result == "REQUIRE_APPROVAL"
    assert p.decide("inbox_finish", {"keep": []}).result == "ALLOW"


def test_the_dialog_names_the_files():
    title, text = DialogApprover()._question({"tool": "inbox_finish", "arguments": {"keep": ["ZoomIt", "a.exe"]}})
    assert title == KEEP_TITLE and "ZoomIt" in text and "a.exe" in text and "다운로드 폴더" in text


def test_the_tool_is_listed_only_with_an_inbox():
    assert "inbox_finish" in {t["name"] for t in load_tool_list({"host.inbox"})}
    assert "inbox_finish" not in {t["name"] for t in load_tool_list()}


def test_through_the_mcp_host_no_means_nothing_kept_and_the_session_end_empties_the_inbox(tmp_path, folders):
    downloads, inbox = folders
    fake = InboxManager(tmp_path / "sbx")
    Watcher.made = []
    answers = [False, True]
    asked = []

    async def approver(summary):
        asked.append(summary["tool"])
        return answers.pop(0)

    async def body():
        a = launch_args(tmp_path)
        a.inbox, a.inbox_watcher, a.inbox_skip_exec_check = inbox, Watcher, True
        a.inbox_downloader = Downloader(inbox, downloads=downloads)
        backend = HostBackend(a, sandbox_manager=fake, approver=approver)
        backend.start()
        assert backend.ready.wait(20) and not backend.error, backend.error

        async def call(tool, arguments):
            r = await asyncio.to_thread(backend.call, tool, arguments)
            return json.loads(r["content"][-1]["text"])
        await call("task_submit", {"goal": "설치해 보고 남기기"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        no = await call("inbox_finish", {"keep": ["tool.exe"]})
        after_no = sorted(p.name for p in inbox.iterdir())
        (inbox / "late.txt").write_bytes(b"left over")                     # not kept: the end deletes it
        await call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving
        await asyncio.to_thread(backend.shutdown)
        return no, after_no

    no, after_no = run(body())
    assert no["error"] == "POLICY_DENIED" and asked == ["inbox_finish"]
    assert after_no == ["ZoomIt", "tool.exe"]                               # nothing deleted on "no"
    assert list(downloads.iterdir()) == []                                  # nothing kept on "no"
    assert list(inbox.iterdir()) == [] and inbox.is_dir()                   # emptied at session end
