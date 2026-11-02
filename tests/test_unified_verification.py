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
            "artifact_id": "ART-1", "source": "output"}
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


def test_output_sample_uses_shortcut_target_and_refuses_truncated_or_injected_input():
    from host.unified_verification import sample_command
    identity = ("SES-" + "a" * 32, "RT-SBX-001", 1)
    for name, data in [("o-abcdef.bin", b"O\x00\xffabcdef"), ("c-abcdef.txt", b"close abcdef")]:
        command = sample_command(identity, name, data)
        assert len(command) <= 259 and "Output.lnk" in command and "Shared" not in command
    with pytest.raises(ValueError):
        sample_command(identity, "bad';command.bin", b"data")
    with pytest.raises(ValueError):
        sample_command(identity, "large.bin", b"x" * 1000)


@pytest.mark.parametrize("complete", [True, False])
def test_vm_end_alone_does_not_complete_export_verification(monkeypatch, complete):
    from host.unified_verification import wait_for_final_output
    states = iter([
        {"runtime_state": "READY", "sandbox": {"state": "READY"}},
        {"runtime_state": "TERMINATED", "sandbox": {"state": "STOPPING"}},
        {"runtime_state": "TERMINATED", "sandbox": {"state": "STOPPED", "output": {"at_end": None}}},
        {"runtime_state": "TERMINATED", "sandbox": {"state": "STOPPED", "output": {
            "at_end": {"acquisition": {"complete": complete}, "held": 0}}}},
    ])
    calls = []
    class Client:
        def call(self, tool):
            calls.append(tool)
            return next(states)
    monkeypatch.setattr("host.unified_verification.time.sleep", lambda _: None)
    if complete:
        assert wait_for_final_output(Client())["held"] == 0
    else:
        with pytest.raises(RuntimeError, match="acquisition"):
            wait_for_final_output(Client())
    assert calls == ["runtime_get_state"] * 4
