"""Real Windows locks and service IPC; Defender and human decisions are test doubles.

These checks do not constitute actual installed-Defender or real user approval.
"""
import asyncio
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows file locks")
pytest.importorskip("win32file")

from test_shared_scanner_service import service, source, finisher
from scanner_helpers import FakeScanner
from scanner_service.models import Verdict
from host.artifacts import ArtifactBroker, ArtifactGrants, SCANNING
from host.artifact_scan import NoScanner
from host.unified_export import UnifiedExport


class Human:
    def __init__(self, scanner, review="keep", final="keep"):
        self.scanner, self.first, self.last = scanner, review, final
        self.events = []

    async def review_export(self, summary):
        self.events.append(("review", len(self.scanner.scanned), summary))
        return self.first

    async def choose_shared(self, summary):
        self.events.append(("final", len(self.scanner.scanned), summary))
        assert summary["status"] == "CLEAN"
        return self.last

    async def notify_shared(self, summary):
        self.events.append(("failure", len(self.scanner.scanned), summary))


def setup(tmp_path, runtime, client, **human):
    share = source(tmp_path, {"결과.pdf": b"%PDF-test\x00binary"})
    broker = ArtifactBroker(ArtifactGrants(tmp_path / "incoming"), tmp_path / "unused", NoScanner())
    person = Human(runtime.scanner, **human)
    session = SimpleNamespace(identity=(share.name, "RT-1", 1), terminated=False)
    unified = UnifiedExport(broker, finisher(client), person, SimpleNamespace(shared=share, session=session),
                            destination=tmp_path / "Downloads" / "SandboxShared")
    return share, broker, person, session, unified


def test_shared_candidate_review_scan_final_download_and_shutdown_dedup(tmp_path, service):
    runtime, client = service()
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client)
        await unified.refresh(session)
        view = broker.list(session)["artifacts"][0]
        assert view["source"] == "shared" and view["sha256"]
        art = broker.get(view["artifact_id"])
        assert await unified.review(unified.summary(art)) == "keep"
        await broker.export(session, art.artifact_id)
        await art.task
        assert art.stage == "EXPORTED", art.result
        assert art.export_path.is_relative_to(tmp_path / "Downloads" / "SandboxShared" / share.name)
        assert art.export_path.read_bytes() == (share / "결과.pdf").read_bytes()
        assert "ZoneId=3" in Path(str(art.export_path) + ":Zone.Identifier").read_text()
        assert [(e[0], e[1]) for e in human.events] == [("review", 0), ("final", 1)]
        await unified.refresh(session)
        assert len(broker.list(session)["artifacts"]) == 1
        assert (await unified.finish_closed(share))["status"] == "EMPTY"
        assert len(human.events) == 2
        # Changing the same file creates a new candidate rather than suppressing it.
        (share / "결과.pdf").write_bytes(b"%PDF-changed")
        await unified.refresh(session)
        assert len(broker.list(session)["artifacts"]) == 2
    asyncio.run(run())


@pytest.mark.parametrize("review,final,expected", [("hold", "keep", "HELD"),
                                                   ("delete", "keep", "DELETED"),
                                                   ("keep", "hold", "HELD"),
                                                   ("keep", "delete", "DELETED"),
                                                   ("keep", "keep", "EXPORTED")])
def test_shutdown_keeps_both_gates_and_delete_hold_semantics(tmp_path, service, review, final, expected):
    runtime, client = service()
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client, review=review, final=final)
        result = await unified.finish_closed(share)
        assert result["status"] == expected, result
        assert [e[0] for e in human.events] == (["review", "final"] if review == "keep" else ["review"])
        assert len(runtime.scanner.scanned) == (1 if review == "keep" else 0)
        assert share.exists() == (expected == "HELD")
        assert bool(list((tmp_path / "Downloads").rglob("*.pdf"))) == (expected == "EXPORTED")
    asyncio.run(run())


def test_changed_candidate_never_scans_or_gets_final_approval(tmp_path, service):
    runtime, client = service()
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client)
        await unified.refresh(session)
        art = broker.get(broker.list(session)["artifacts"][0]["artifact_id"])
        await unified.review(unified.summary(art))
        (share / "결과.pdf").write_bytes(b"changed after list review")
        await broker.export(session, art.artifact_id)
        await art.task
        assert art.stage == "BLOCKED"
        assert not runtime.scanner.scanned
        assert [e[0] for e in human.events] == ["review", "failure"]
        assert not (tmp_path / "Downloads").exists()
    asyncio.run(run())


@pytest.mark.parametrize("verdict", [Verdict.DETECTED, Verdict.ERROR, Verdict.UNVERIFIABLE])
def test_failed_scan_notifies_without_final_approval(tmp_path, service, verdict):
    runtime, client = service(FakeScanner(verdict))
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client)
        result = await unified.finish_closed(share)
        assert result["status"] in ("BLOCKED", "QUARANTINED")
        assert [e[0] for e in human.events] == ["review", "failure"]
        assert not (tmp_path / "Downloads").exists()
        assert share.exists()
    asyncio.run(run())


def test_output_binary_uses_same_service_gates_destination_and_motw(tmp_path, service):
    runtime, client = service()
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client)
        data = b"PK\x00binary-output"
        payload = {"event_id": "output-event", "relative_path": "result.zip", "observed_at": "now"}
        assert broker.store(session.identity, payload)
        art = broker.get("ART-000001")
        assert await unified.review(unified.summary(art)) == "keep"
        grant, token = broker.grants.issue(session.identity, art.artifact_id, art.event_id, 1024)
        broker.grants.claim(grant.upload_id, token, len(data))
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        await broker.grants.receive(grant, reader, len(data))
        art.grant, art.stage, art.size, art.sha256 = grant, SCANNING, grant.size, grant.sha256
        await unified.received(art, grant)
        assert art.stage == "EXPORTED", art.result
        assert art.export_path.read_bytes() == data
        assert art.export_path.is_relative_to(tmp_path / "Downloads" / "SandboxShared" / share.name)
        assert "ZoneId=3" in Path(str(art.export_path) + ":Zone.Identifier").read_text()
        assert broker.grants.bytes_held == 0
        assert [e[0] for e in human.events] == ["review", "final"]
        assert not list((tmp_path / "incoming").rglob("*.part"))
    asyncio.run(run())


def test_review_paginates_all_names_and_cancel_stops_remaining_pages():
    from host.approval import DialogApprover, IDYES, IDCANCEL
    human = DialogApprover()
    seen = []
    def answer(text, title, buttons):
        seen.append(text)
        return IDYES if len(seen) == 1 else IDCANCEL
    human._ask_code = answer
    files = [{"name": f"file-{n}.txt", "size": n} for n in range(25)]
    assert asyncio.run(human.review_export({"files": files})) == "hold"
    assert len(seen) == 2 and "file-19.txt" in seen[1]
    assert "file-20.txt" not in "".join(seen)


def test_shutdown_deletes_only_remaining_selected_files_after_live_export(tmp_path, service):
    runtime, client = service()
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client)
        await unified.refresh(session)
        art = broker.get("ART-000001")
        await unified.review(unified.summary(art))
        await broker.export(session, art.artifact_id)
        await art.task
        (share / "later.txt").write_bytes(b"remaining")
        human.first = "delete"
        result = await unified.finish_closed(share)
        assert result["status"] == "DELETED", result
        assert not result["events"], result
        assert not (share / "later.txt").exists()
        assert (share / "결과.pdf").exists() and art.export_path.exists()
    asyncio.run(run())


def test_cancel_during_final_approval_cannot_publish(tmp_path, service):
    runtime, client = service()
    async def run():
        share, broker, human, session, unified = setup(tmp_path, runtime, client)
        final_entered = asyncio.Event()
        async def wait_final(summary):
            final_entered.set()
            await asyncio.Future()
        human.choose_shared = wait_final
        await unified.refresh(session)
        art = broker.get("ART-000001")
        await unified.review(unified.summary(art))
        await broker.export(session, art.artifact_id)
        await asyncio.wait_for(final_entered.wait(), 5)
        broker.cancel_identity(session.identity, "test session ended")
        await asyncio.gather(art.task, return_exceptions=True)
        assert art.stage == "CANCELLED" and not (tmp_path / "Downloads").exists()
        # Cancel releases the source lock as well as the service job.
        (share / "결과.pdf").write_bytes(b"released")
    asyncio.run(run())


@pytest.mark.parametrize("first,last", [("keep", "keep"), ("hold", "keep"), ("keep", "hold")])
def test_mcp_broker_runner_upload_uses_two_real_gates(tmp_path, service, first, last):
    from test_artifact_export import Host
    runtime, client = service()
    human = Human(runtime.scanner, first, last)
    async def run():
        host = Host(tmp_path / "host", approver=human)
        async def install():
            share = tmp_path / "shared"
            share.mkdir()
            return UnifiedExport(host.backend.artifacts, finisher(client), human,
                                 SimpleNamespace(shared=share, session=host.backend.session),
                                 destination=tmp_path / "Downloads")
        await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(install(), host.backend.loop))
        runner, serving = await host.start()
        try:
            await runner.report("bundle.zip", b"PK\x00binary content")
            listed = await host.call("artifact_list")
            art = listed["artifacts"][0]
            assert art["source"] == "output"
            accepted = await host.call("artifact_export", {"artifact_id": art["artifact_id"]})
            if first == "hold":
                assert not accepted["ok"] and accepted["error"] == "POLICY_DENIED"
                assert not runtime.scanner.scanned
                assert [e[0] for e in human.events] == ["review"]
            else:
                assert accepted["ok"], accepted
                result = await host.wait_artifact(art["artifact_id"])
                assert result["status"] == ("EXPORTED" if last == "keep" else "BLOCKED"), result
                assert [e[0] for e in human.events] == ["review", "final"]
                if last == "keep":
                    assert Path(result["export_path"]).read_bytes() == b"PK\x00binary content"
            if first != "keep" or last != "keep":
                assert not (tmp_path / "Downloads").exists()
        finally:
            await host.close(serving)
    asyncio.run(run())


def test_retired_mcp_lists_completed_exports_without_new_runtime():
    from host.mcp_runtime import McpRuntime
    import json
    backend = SimpleNamespace(final_artifacts=[{"artifact_id": "ART-000001", "status": "EXPORTED",
                                                "export_path": "download/result.pdf"}])
    result = McpRuntime._ended_query(backend, "artifact_list", {"status": "EXPORTED", "limit": 50, "cursor": None})
    data = json.loads(result["content"][0]["text"])
    assert data["session_ended"] and len(data["artifacts"]) == 1
