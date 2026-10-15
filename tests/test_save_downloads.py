"""--save-downloads: inbox_download also keeps a copy in Downloads that stays after the session
(배주한 결정 2026-10-15: "인터넷에서 받은 건 다운로드 폴더에, 끝나도 그대로")."""

import hashlib

import pytest

from host.mcp_server import SAVE_DOWNLOADS_RULE, load_tool_list, main, save_downloads_description
from test_inbox_download import BODY, downloader, server  # noqa: F401 - server is a fixture


def zone(path):
    try:
        with open(f"{path}:Zone.Identifier", encoding="ascii") as f:
            return f.read()
    except OSError:
        return ""


def test_the_download_is_also_saved_in_downloads_marked(tmp_path, server):
    server.routes["/ZoomIt.exe"] = ("body", BODY)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    d, _ = downloader(tmp_path, server, downloads=downloads, save_to_downloads=True)
    r = d.download(f"{server.base}/ZoomIt.exe")
    assert r["downloads_copy"] == {"path": "Downloads\\ZoomIt.exe", "new": True}
    assert (downloads / "ZoomIt.exe").read_bytes() == BODY
    assert (tmp_path / "inbox" / "ZoomIt.exe").read_bytes() == BODY      # the Sandbox still gets its copy
    import sys
    if sys.platform == "win32":
        assert "ZoneId=3" in zone(downloads / "ZoomIt.exe")


def test_the_copy_stays_when_the_inbox_is_emptied(tmp_path, server, monkeypatch):
    monkeypatch.setattr("sandbox_manager.inbox.Path.home", lambda: tmp_path / "home")
    server.routes["/ZoomIt.exe"] = ("body", BODY)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    d, _ = downloader(tmp_path, server, downloads=downloads, save_to_downloads=True)
    d.download(f"{server.base}/ZoomIt.exe")
    done = d.finish([])                                                   # session end: keep nothing
    assert done["deleted_files"] == 1 and list((tmp_path / "inbox").iterdir()) == []
    assert (downloads / "ZoomIt.exe").read_bytes() == BODY


def test_same_file_again_is_not_duplicated_a_different_one_never_overwrites(tmp_path, server):
    server.routes["/ZoomIt.exe"] = ("body", BODY)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    d, _ = downloader(tmp_path, server, downloads=downloads, save_to_downloads=True)
    d.download(f"{server.base}/ZoomIt.exe")
    again = d.download(f"{server.base}/ZoomIt.exe")
    assert again["downloads_copy"] == {"path": "Downloads\\ZoomIt.exe", "new": False}
    server.routes["/ZoomIt.exe"] = ("body", BODY + b"v2")
    other = d.download(f"{server.base}/ZoomIt.exe")
    assert other["downloads_copy"] == {"path": "Downloads\\ZoomIt-2.exe", "new": True}
    assert (downloads / "ZoomIt.exe").read_bytes() == BODY
    assert hashlib.sha256((downloads / "ZoomIt-2.exe").read_bytes()).hexdigest() == other["file"]["sha256"]


def test_without_the_option_nothing_goes_to_downloads(tmp_path, server):
    server.routes["/ZoomIt.exe"] = ("body", BODY)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    d, _ = downloader(tmp_path, server, downloads=downloads)
    r = d.download(f"{server.base}/ZoomIt.exe")
    assert "downloads_copy" not in r and list(downloads.iterdir()) == []


def test_a_failed_copy_does_not_fail_the_download(tmp_path, server):
    server.routes["/ZoomIt.exe"] = ("body", BODY)
    d, _ = downloader(tmp_path, server, downloads=tmp_path / "missing", save_to_downloads=True)
    r = d.download(f"{server.base}/ZoomIt.exe")
    assert r["downloads_copy"]["path"] is None
    assert (tmp_path / "inbox" / "ZoomIt.exe").is_file()


def test_the_agent_is_told_and_the_option_needs_the_inbox():
    tools = load_tool_list({"host.inbox"})
    save_downloads_description(tools)
    tool = next(t for t in tools if t["name"] == "inbox_download")
    assert tool["description"].endswith(SAVE_DOWNLOADS_RULE)
    with pytest.raises(SystemExit):
        main(["--save-downloads"])


@pytest.mark.parametrize("disposition, url, final, name", [
    (None, "https://www.7-zip.org/a/7z2604-x64.exe",
     "https://release-assets.githubusercontent.com/x/466446150/4c8fc6ce-6afe-4065-a6ff-38b2bf14cadf?sp=r", "7z2604-x64.exe"),
    ("attachment; filename=7z2604-x64.exe", "https://example.com/get?id=1", "https://cdn.example.com/blob/abc", "7z2604-x64.exe"),
    ("attachment; filename=\"../../evil.exe\"", "https://example.com/a", "https://example.com/a", "evil.exe"),
    (None, "https://example.com/download", "https://cdn.example.com/files/tool.zip", "tool.zip"),
    (None, "https://example.com/download", "https://cdn.example.com/blob/abc", "abc"),
])
def test_the_name_comes_from_the_server_or_the_asked_url(disposition, url, final, name):
    from host.inbox_download import pick_name
    assert pick_name(disposition, url, final) == name
