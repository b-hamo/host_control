"""inbox_import: a file the user already downloaded goes into the shared inbox (team request, sandbox_manager #19).

- only a file directly in the Downloads folder, by name (sandbox_manager import_to_inbox does the checks)
- copied, the original stays; the inbox limits hold
- MCP: listed only with --inbox, through the Broker (policy P-INBOX-IMPORT, audit), and sandbox_run
  may plan a run of the imported file like a download
"""

import asyncio
import hashlib
import json
import os

import pytest

from host.inbox_download import Downloader, DownloadError
from host.mcp_server import HostBackend, load_tool_list
from test_inbox_download import InboxManager, Watcher
from test_sandbox_launch import args as launch_args, run

BODY = b"MZ" + b"tailscale" * 100


@pytest.fixture
def folders(tmp_path):
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    inbox = tmp_path / "SecureCUA" / "inbox"
    inbox.mkdir(parents=True)
    return downloads, inbox


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    # sandbox_manager refuses an inbox inside the user's profile folders; the test home is tmp_path
    monkeypatch.setattr("sandbox_manager.inbox.Path.home", lambda: tmp_path)


def test_a_downloaded_file_is_copied_and_the_original_stays(folders):
    downloads, inbox = folders
    (downloads / "tailscale-setup-1.102.4.exe").write_bytes(BODY)
    got = Downloader(inbox, downloads=downloads).import_local("tailscale-setup-1.102.4.exe")
    assert got["file"] == {"name": "tailscale-setup-1.102.4.exe", "size": len(BODY),
                           "sha256": hashlib.sha256(BODY).hexdigest()}
    assert got["source"] == "Downloads\\tailscale-setup-1.102.4.exe" and "final_url" not in got
    assert got["sandbox_path"] == "Desktop\\Input\\tailscale-setup-1.102.4.exe"
    assert (inbox / "tailscale-setup-1.102.4.exe").read_bytes() == BODY
    assert (downloads / "tailscale-setup-1.102.4.exe").read_bytes() == BODY     # copy, not move


@pytest.mark.parametrize("name, code", [
    ("..\\Documents\\secret.docx", "POLICY_DENIED"),
    ("C:\\Windows\\notepad.exe", "POLICY_DENIED"),
    ("a.exe:stream", "POLICY_DENIED"),
    ("NUL", "POLICY_DENIED"),
    ("missing.exe", "INVALID_ARGUMENT"),
    ("setup.exe.crdownload", "INVALID_ARGUMENT"),
])
def test_paths_and_unfinished_or_missing_files_are_refused(folders, name, code):
    downloads, inbox = folders
    (downloads / "setup.exe.crdownload").write_bytes(b"part")
    with pytest.raises(DownloadError) as e:
        Downloader(inbox, downloads=downloads).import_local(name)
    assert e.value.code == code
    assert list(inbox.iterdir()) == []


def test_a_hard_link_to_another_host_file_is_refused(folders, tmp_path):
    downloads, inbox = folders
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"host secret")
    os.link(secret, downloads / "innocent.txt")
    with pytest.raises(DownloadError) as e:
        Downloader(inbox, downloads=downloads).import_local("innocent.txt")
    assert e.value.code == "POLICY_DENIED" and list(inbox.iterdir()) == []


def test_the_inbox_limits_hold(folders, monkeypatch):
    downloads, inbox = folders
    (downloads / "big.bin").write_bytes(b"x" * 20)
    monkeypatch.setattr("host.inbox_download.TOTAL_MAX", 10)
    with pytest.raises(DownloadError) as e:
        Downloader(inbox, downloads=downloads).import_local("big.bin")
    assert e.value.code == "POLICY_DENIED" and list(inbox.iterdir()) == []


def test_the_tool_is_listed_only_with_an_inbox():
    assert "inbox_import" in {t["name"] for t in load_tool_list({"host.inbox"})}
    assert "inbox_import" not in {t["name"] for t in load_tool_list()}


def test_inbox_import_through_the_mcp_host_and_sandbox_run_may_plan_it(tmp_path, folders):
    downloads, inbox = folders
    (downloads / "tailscale-setup-1.102.4.exe").write_bytes(BODY)
    fake = InboxManager(tmp_path / "sbx")
    Watcher.made = []

    async def body():
        a = launch_args(tmp_path)
        a.inbox, a.inbox_watcher, a.inbox_skip_exec_check = inbox, Watcher, True
        a.inbox_downloader = Downloader(inbox, downloads=downloads)
        a.sandbox_run, a.artifact_export, a.approval = True, True, "deny"
        a.artifact_dir, a.export_dir = tmp_path / "art", tmp_path / "exp"
        a.artifact_scanner, a.artifact_max_bytes = "none", 1024 * 1024
        backend = HostBackend(a, sandbox_manager=fake)
        backend.start()
        assert backend.ready.wait(20) and not backend.error, backend.error

        async def call(tool, arguments):
            r = await asyncio.to_thread(backend.call, tool, arguments)
            return json.loads(r["content"][-1]["text"])
        got = await call("inbox_import", {"name": "tailscale-setup-1.102.4.exe"})
        bad = await call("inbox_import", {"name": "..\\x.exe"})
        known = "tailscale-setup-1.102.4.exe".casefold() in backend.runner._files
        await asyncio.to_thread(backend.shutdown)
        audit = [json.loads(l) for l in (tmp_path / "audit" / "SES-TEST-001.jsonl").read_text(encoding="utf-8").splitlines()]
        return got, bad, known, audit

    got, bad, known, audit = run(body())
    assert got["ok"] and got["file"]["sha256"] == hashlib.sha256(BODY).hexdigest()
    assert bad["error"] == "POLICY_DENIED"
    assert known                                                     # sandbox_run can plan it
    rec = next(x for x in audit if x.get("tool") == "inbox_import" and x["result"]["ok"])
    assert rec["policy"]["rule_id"] == "P-INBOX-IMPORT"
    assert rec["result"]["import"]["source"] == "Downloads\\tailscale-setup-1.102.4.exe"
