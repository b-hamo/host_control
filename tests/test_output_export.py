"""Output receipts, real Windows scanner IPC and pre-termination ordering.

The service scanner and dialog decisions below are doubles. Installed Defender
and actual user approval are verified separately by the integration session.
"""
import asyncio
import hashlib
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from host.artifacts import ArtifactBroker, ArtifactGrants, SCANNING
from host.artifact_scan import NoScanner
from host.output_export import OutputExport
from host.runtime_session import RuntimeSession
from scrp.validate import ProtocolError
from test_shared_scanner_service import service, finisher
from scanner_helpers import FakeScanner
from scanner_service.models import Verdict


class Human:
    def __init__(self, scanner, review="keep", final="keep"):
        self.scanner, self.first, self.last, self.events = scanner, review, final, []

    async def review_export(self, summary):
        self.events.append(("review", len(self.scanner.scanned)))
        return self.first

    async def choose_shared(self, summary):
        assert summary["status"] == "CLEAN"
        self.events.append(("final", len(self.scanner.scanned)))
        return self.last

    async def notify_output(self, summary):
        self.events.append((summary["status"], len(self.scanner.scanned)))


def setup(tmp_path, runtime, client, **choices):
    broker = ArtifactBroker(ArtifactGrants(tmp_path / "output"), tmp_path / "unused", NoScanner())
    session = RuntimeSession(("SES-OUTPUT", "RT-1", 1))
    human = Human(runtime.scanner, **choices)
    output = OutputExport(broker, finisher(client), human, SimpleNamespace(session=session),
                          destination=tmp_path / "Downloads" / "SandboxOutput")
    return broker, session, human, output


async def receive(broker, output, session, data=b"arbitrary binary\x00\xff"):
    payload = dict(event_id=str(uuid.uuid4()), relative_path="nested/result.bin",
                   observed_at="2026-11-03T00:00:00Z", category="OUTPUT_SNAPSHOT")
    assert broker.store(session.identity, payload)
    art = broker._by_event[(session.identity, payload["event_id"])]
    grant, token = broker.grants.issue(session.identity, art.artifact_id, art.event_id, 1000)
    broker.grants.claim(grant.upload_id, token, len(data))
    stream = asyncio.StreamReader()
    stream.feed_data(data)
    stream.feed_eof()
    await broker.grants.receive(grant, stream, len(data))
    art.grant, art.stage, art.size, art.sha256 = grant, SCANNING, grant.size, grant.sha256
    await output.received(art, grant)
    return art


@pytest.mark.parametrize("review,final,stage", [
    ("keep", "keep", "EXPORTED"), ("hold", "keep", "HELD"),
    ("delete", "keep", "DELETED"), ("keep", "hold", "HELD"), ("keep", "delete", "DELETED")])
def test_received_copy_survives_vm_end_and_obeys_both_gates(tmp_path, service, review, final, stage):
    runtime, client = service()
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client, review=review, final=final)
        art = await receive(broker, output, session)
        path = output.receipts[art.artifact_id].folder / "result.bin"
        broker.cancel_identity(session.identity, "VM ended")
        assert art.stage == "STAGED" and path.exists()
        assert broker.grants.bytes_held == art.size
        session.terminated = True
        output._captured = session.identity
        output.acquisition = {"status": "CAPTURED", "complete": True, "artifacts": [art.artifact_id]}
        await output.finish_closed()
        assert art.stage == stage, art.result
        gates = [event for event in human.events if event[0] in ("review", "final")]
        assert gates == ([("review", 0), ("final", 1)] if review == "keep" else [("review", 0)])
        assert path.exists() == (stage == "HELD")
        if stage == "EXPORTED":
            assert art.export_path.read_bytes() == b"arbitrary binary\x00\xff"
            assert hashlib.sha256(art.export_path.read_bytes()).hexdigest() == art.sha256
            assert "ZoneId=3" in Path(str(art.export_path) + ":Zone.Identifier").read_text()
        else:
            assert not list((tmp_path / "Downloads").rglob("result.bin"))
        assert broker.grants.bytes_held == (art.size if stage == "HELD" else 0)
        saved = json.loads((broker.grants.incoming_dir / "output-state.json").read_text(encoding="utf-8"))
        assert len(saved["files"]) == (1 if stage == "HELD" else 0)
    asyncio.run(run())


@pytest.mark.parametrize("verdict", [Verdict.DETECTED, Verdict.ERROR, Verdict.UNVERIFIABLE])
def test_failed_scan_never_asks_final_or_publishes(tmp_path, service, verdict):
    runtime, client = service(FakeScanner(verdict))
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        art = await receive(broker, output, session)
        await output._publish(art)
        assert art.stage == "BLOCKED"
        assert human.events[0][0] == "review"
        assert [e[0] for e in human.events][1:] in (["BLOCKED"], ["QUARANTINED"])
        assert output.owns(art) and not (tmp_path / "Downloads").exists()
    asyncio.run(run())


@pytest.mark.parametrize("first,last", [("keep", "keep"), ("hold", "keep"), ("keep", "hold")])
def test_mcp_broker_https_upload_and_both_gates(tmp_path, service, first, last):
    """Real MCP/WSS/HTTPS and service IPC. Snapshot, VM, scanner and human are doubles."""
    from test_artifact_export import Host
    runtime, client = service()
    human = Human(runtime.scanner, first, last)
    async def run():
        host = Host(tmp_path / "host", approver=human)
        async def install():
            output = OutputExport(host.backend.artifacts, finisher(client), human,
                                  SimpleNamespace(session=host.backend.session), destination=tmp_path / "Downloads")
            async def no_snapshot(*args, **kwargs):
                pass  # this fixture exercises transport/gates, not final manifest acquisition
            output.refresh = no_snapshot
            return output
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
            else:
                assert accepted["ok"], accepted
                for _ in range(100):
                    result = next(a for a in (await host.call("artifact_list"))["artifacts"] if a["artifact_id"] == art["artifact_id"])
                    if result["stage"] in ("HELD", "EXPORTED", "BLOCKED"):
                        break
                    await asyncio.sleep(.05)
                assert result["stage"] == ("EXPORTED" if last == "keep" else "HELD"), result
                assert [e[0] for e in human.events if e[0] in ("review", "final")] == ["review", "final"]
                if last == "keep":
                    assert Path(result["export_path"]).read_bytes() == b"PK\x00binary content"
            if first != "keep" or last != "keep":
                assert not (tmp_path / "Downloads").exists()
        finally:
            await host.close(serving)
    asyncio.run(run())


def test_termination_is_not_sent_when_capture_fails():
    async def run():
        session = RuntimeSession(("SES-1", "RT-1", 1))
        called = []
        async def acquire(s, reason):
            called.append((s.identity, reason))
            raise ProtocolError("ARTIFACT_BLOCKED", "file still being written")
        session.before_terminate = acquire
        with pytest.raises(ProtocolError, match="file still being written"):
            await session.terminate("USER_STOP")
        assert called == [(session.identity, "USER_STOP")]
        assert not session.terminated and session.end_reason is None
    asyncio.run(run())


def test_repeated_manifest_reuses_verified_copy_without_upload_or_extra_candidates(tmp_path, service, monkeypatch):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        art = await receive(broker, output, session)
        calls = []
        async def snapshot(s, operation, snapshot_id):
            calls.append(operation)
            return {"files": [{"candidate_event_id": str(uuid.uuid4()), "relative_path": art.relative_path,
                               "size_bytes": art.size, "sha256": art.sha256}]} if operation == "CAPTURE" else {}
        async def unexpected(*args):
            pytest.fail("identical bytes were uploaded again")
        monkeypatch.setattr(output, "_snapshot", snapshot)
        monkeypatch.setattr(broker, "transfer", unexpected)
        for _ in range(3):
            output._last_refresh = 0
            await output.refresh(session)
            assert output.acquisition["artifacts"] == [art.artifact_id]
        assert len(broker._by_id) == 1 and len(output.receipts) == 1
        assert broker.grants.bytes_held == art.size
        assert calls == ["CAPTURE", "VERIFY", "RELEASE"] * 3
    asyncio.run(run())


def test_matching_copy_rejects_same_size_tampering_and_remembers_delete(tmp_path, service):
    runtime, client = service()
    async def run():
        from pathlib import PureWindowsPath
        broker, session, _, output = setup(tmp_path, runtime, client)
        art = await receive(broker, output, session, b"first")
        path = PureWindowsPath(art.relative_path)
        receipt = output.receipts[art.artifact_id]
        import stat
        (receipt.folder / receipt.name).chmod(stat.S_IWRITE)
        (receipt.folder / receipt.name).write_bytes(b"other")
        assert await output._matching_copy(session.identity, path, art.size, art.sha256) is None
        await output.decline_review(art.artifact_id, "delete")
        assert await output._matching_copy(session.identity, path, art.size, art.sha256) is art
        assert await output._matching_copy(session.identity, path, art.size, "0" * 64) is None
    asyncio.run(run())


def test_new_verified_version_replaces_only_unreviewed_staging(tmp_path, service):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        first = await receive(broker, output, session, b"first")
        second = await receive(broker, output, session, b"second")
        assert first.stage == "SUPERSEDED" and not output.owns(first)
        assert broker.grants.bytes_held == len(b"second")
        output._reviewing.add(second.artifact_id)
        third = await receive(broker, output, session, b"third")
        assert output.owns(second) and output.owns(third)
        assert broker.grants.bytes_held == len(b"secondthird")
    asyncio.run(run())


def test_successful_export_with_cleanup_failure_keeps_receipt_and_accounting(tmp_path, service, monkeypatch):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        art = await receive(broker, output, session)
        async def exported(*args, **kwargs):
            return {"status": "EXPORTED", "dest": str(tmp_path / "published"), "scan": "clean", "files": []}
        monkeypatch.setattr(output.finisher, "_finish", exported)
        await output._publish(art)
        assert art.stage == "EXPORTED" and output.owns(art)
        assert art.result["cleanup_pending"] and broker.grants.bytes_held == art.size
    asyncio.run(run())


def test_release_failure_is_not_reported_as_complete_and_is_retried(tmp_path, service, monkeypatch):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        calls, fail = [], True
        async def snapshot(s, operation, snapshot_id):
            calls.append((operation, snapshot_id))
            if operation == "RELEASE" and fail:
                raise ProtocolError("ARTIFACT_BLOCKED", "lost release reply")
            return {"files": []}
        monkeypatch.setattr(output, "_snapshot", snapshot)
        with pytest.raises(ProtocolError):
            await output.refresh(session)
        assert not output.acquisition["complete"] and output._lease is not None
        old_id = output._lease[1]
        fail = False
        output._last_refresh = 0
        await output.refresh(session)
        assert calls[3] == ("RELEASE", old_id)
        assert output.acquisition["complete"] and output._lease is None
    asyncio.run(run())


@pytest.mark.parametrize("release_fails", [False, True])
def test_lost_capture_reply_releases_same_id_without_recapturing(tmp_path, service, monkeypatch, release_fails):
    runtime, client = service()
    async def run():
        _, session, _, output = setup(tmp_path, runtime, client)
        calls = []
        async def snapshot(s, operation, snapshot_id):
            calls.append((operation, snapshot_id))
            if operation == "CAPTURE":
                raise ProtocolError("ACTION_TIMEOUT", "capture reply lost")
            if release_fails:
                raise ProtocolError("ACTION_TIMEOUT", "release reply lost")
            return {"files": []}
        monkeypatch.setattr(output, "_snapshot", snapshot)
        with pytest.raises(ProtocolError):
            await output.refresh(session, closing=True)
        assert [operation for operation, _ in calls] == ["CAPTURE", "RELEASE"]
        assert calls[0][1] == calls[1][1]
        assert not output.acquisition["complete"] and output._captured is None
        assert output._lease == ((session.identity, calls[0][1]) if release_fails else None)
        assert not session.terminated
    asyncio.run(run())
