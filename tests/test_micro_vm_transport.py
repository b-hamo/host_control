import base64
from pathlib import Path

import pytest

from host.sandbox_run import select_run_output, transport_wait_command


def test_transport_waits_for_both_bound_hashes_without_replaying_input():
    files = [(Path("run-0123456789abcdef.ps1"), "a" * 64),
             (Path("run-0123456789abcdef.json"), "b" * 64)]
    command = transport_wait_command(files)
    assert len(command.encode()) <= 4096
    script = base64.b64decode(command.split(" -EncodedCommand ")[1]).decode("utf-16le")
    assert str(files[0][0]) in script and str(files[1][0]) in script
    assert "a" * 64 in script and "b" * 64 in script
    assert "ComputeHash" in script and "'Open','Read','Read'" in script
    assert script.count("& $a[0][0] -Manifest $a[1][0]") == 1
    assert "finally{foreach($h in $l){$h.Dispose()}}" in script


def test_transport_rejects_non_generated_shell_text():
    with pytest.raises(ValueError):
        transport_wait_command([(Path("x';Start-Process calc;'.ps1"), "a" * 64),
                                (Path("run-0123456789abcdef.json"), "b" * 64)])


def output(identifier, status="QUARANTINED", sha="a" * 64, stage="STAGED"):
    return {"artifact_id": identifier, "status": status, "sha256": sha, "size_bytes": 42, "stage": stage}


def test_duplicate_snapshot_and_watcher_use_checked_identical_copy():
    exported = output("ART-1", "EXPORTED", stage="EXPORTED")
    assert select_run_output([exported, output("ART-2")]) is exported


def test_conflicting_receipt_versions_are_never_accepted():
    with pytest.raises(ValueError, match="ambiguous"):
        select_run_output([output("ART-1", "EXPORTED"), output("ART-2", sha="b" * 64)])


def test_blocked_current_version_is_not_hidden_by_earlier_export():
    blocked = output("ART-2", "BLOCKED", stage="BLOCKED")
    assert select_run_output([output("ART-1", "EXPORTED"), blocked]) is blocked


def test_superseded_candidate_does_not_ambiguate_verified_replacement():
    replacement = output("ART-2", "EXPORTED", stage="EXPORTED")
    assert select_run_output([output("ART-1", "BLOCKED", stage="SUPERSEDED"), replacement]) is replacement
