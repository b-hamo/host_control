"""Verification must reject misleading success, paths, content and MOTW."""
import hashlib
import sys
from pathlib import Path

import pytest

from host.unified_verification import verify_file, listed, runtime_state


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS alternate data streams")
@pytest.mark.parametrize("fault", [None, "status", "path", "bytes", "hash", "motw"])
def test_verifier_requires_all_export_evidence(tmp_path, fault):
    root = tmp_path / "downloads"
    root.mkdir()
    path = root / "result.bin"
    data = b"verified\x00\xff"
    path.write_bytes(data)
    Path(str(path) + ":Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=3\n")
    item = {"status": "EXPORTED", "export_path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
            "artifact_id": "ART-1", "source": "shared"}
    if fault == "status":
        item["status"] = "SCANNING"
    elif fault == "path":
        root = tmp_path / "elsewhere"
    elif fault == "bytes":
        path.write_bytes(b"different")
    elif fault == "hash":
        item["sha256"] = "0" * 64
    elif fault == "motw":
        Path(str(path) + ":Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=0\n")
    if fault:
        with pytest.raises(RuntimeError):
            verify_file(item, data, root)
    else:
        assert verify_file(item, data, root)["size"] == len(data)


def test_list_verification_reads_all_pages():
    class Client:
        def call(self, tool, **args):
            return {"artifacts": [args["cursor"]], "next_cursor": "second" if args["cursor"] is None else None}
    assert listed(Client()) == [None, "second"]


def test_cleanup_pending_is_repolled_without_restarting(monkeypatch):
    calls = []
    class Client:
        def call(self, tool):
            calls.append(tool)
            if len(calls) == 1:
                raise RuntimeError("CLEANUP_UNCONFIRMED")
            return {"runtime_state": "TERMINATED"}
    monkeypatch.setattr("host.unified_verification.time.sleep", lambda _: None)
    assert runtime_state(Client())["runtime_state"] == "TERMINATED"
    assert calls == ["runtime_get_state", "runtime_get_state"]
