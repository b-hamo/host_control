"""inbox_write: pasted code becomes a file in the inbox, byte for byte (2026-10-31)."""

import hashlib
import json
from pathlib import Path

import pytest

from host.audit import mask
from host.inbox_download import TEXT_MAX, Downloader, DownloadError
from host.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
CODE = 'import getpass\ntotal = 0\nfor i in range(1, 11):\n    total += i\nprint("B1 from", getpass.getuser(), "total =", total)\n'


def downloader(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    return Downloader(inbox), inbox


def test_writes_the_text_unchanged(tmp_path):
    d, inbox = downloader(tmp_path)
    got = d.write_text("main.py", CODE)
    data = (inbox / "main.py").read_bytes()
    assert data == CODE.encode("utf-8")
    assert got["file"] == {"name": "main.py", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assert got["sandbox_path"] == "Desktop\\Input\\main.py" and got["source"] == "chat"


def test_keeps_line_breaks_quotes_and_korean(tmp_path):
    d, inbox = downloader(tmp_path)
    text = 'echo "안녕" \'x\'\r\nexit 0\r\n'
    d.write_text("run.sh", text)
    assert (inbox / "run.sh").read_bytes() == text.encode("utf-8")


def test_never_overwrites(tmp_path):
    d, inbox = downloader(tmp_path)
    first = d.write_text("main.py", "print(1)\n")["file"]["name"]
    second = d.write_text("main.py", "print(2)\n")["file"]["name"]
    assert first == "main.py" and second != first
    assert (inbox / first).read_text() == "print(1)\n"


@pytest.mark.parametrize("name", ["..\\evil.py", "../evil.py", "C:\\x.py", "a/b.py", "noext", ".hidden.py",
                                  "main.py.part", "main.crdownload", "con:.py", "a b.py"])
def test_refuses_bad_names(tmp_path, name):
    d, inbox = downloader(tmp_path)
    with pytest.raises(DownloadError) as e:
        d.write_text(name, "print(1)\n")
    assert e.value.code == "INVALID_ARGUMENT"
    assert list(inbox.iterdir()) == []


def test_size_limit(tmp_path):
    d, inbox = downloader(tmp_path)
    with pytest.raises(DownloadError) as e:
        d.write_text("big.py", "x" * (TEXT_MAX + 1))
    assert e.value.code == "POLICY_DENIED" and list(inbox.iterdir()) == []


def test_audit_keeps_only_a_digest_of_the_text():
    out = mask("inbox_write", {"name": "main.py", "text": CODE})
    assert out["name"] == "main.py"
    assert out["text"]["masked"] and out["text"]["sha256"] == hashlib.sha256(CODE.encode()).hexdigest()


def test_policy_allows_it():
    assert Policy().decide("inbox_write", {"name": "main.py", "text": CODE}).result == "ALLOW"


def test_schema_name_pattern_matches_the_host_check():
    schema = json.loads((ROOT / "schema" / "mcp-tools" / "inbox_write.json").read_text(encoding="utf-8"))
    from host.inbox_download import TEXT_NAME_RE
    assert schema["inputSchema"]["properties"]["name"]["pattern"] == TEXT_NAME_RE.pattern
    assert schema["inputSchema"]["properties"]["text"]["maxLength"] == TEXT_MAX


def test_an_inbox_held_by_a_running_sandbox_says_so(tmp_path, monkeypatch):
    """11/7: a Sandbox left from an earlier conversation mapped the inbox live; the probe's rename failed
    with WinError 32. The Host reclaims such Sandboxes first; if one still holds it, say what to do."""
    import os
    import sys
    from host import inbox_download
    if sys.platform != "win32":
        return
    err = PermissionError(13, "in use")
    err.winerror = 32

    def busy(a, b):
        raise err
    monkeypatch.setattr(inbox_download.os, "replace", busy)
    ok, why = inbox_download.check_no_execute(tmp_path)
    assert not ok and "close that Windows Sandbox window" in why
    assert not list(tmp_path.iterdir())                      # the probe is removed again
    assert os.replace is busy
