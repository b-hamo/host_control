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
                          destination=tmp_path / "Downloads" / "SandboxOutput", automatic=False)
    return broker, session, human, output


async def receive(broker, output, session, data=b"arbitrary binary\x00\xff", path="nested/result.bin"):
    payload = dict(event_id=str(uuid.uuid4()), relative_path=path,
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


@pytest.mark.parametrize("blocked", [None, "legacy", "lease", "busy", "retired"])
def test_authenticated_artifact_reconnect_keeps_old_grants_dead(tmp_path, service, blocked):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        identity = session.identity
        broker.begin_control(identity, "CONN-old")
        assert broker.channel_up(identity, "TEL-old", "CONN-old")
        checked = await receive(broker, output, session, b"already verified on Host")
        retained = output.receipts[checked.artifact_id].folder / "result.bin"
        payload = dict(event_id=str(uuid.uuid4()), relative_path="pending.txt",
                       observed_at="2026-11-08T00:00:00Z", category="OUTPUT_SNAPSHOT")
        assert broker.store(identity, payload)
        pending = broker._by_event[(identity, payload["event_id"])]
        grant, token = broker.grants.issue(identity, pending.artifact_id, pending.event_id, 1000)
        pending.grant = grant
        broker.channel_down(identity, "transport lost", "TEL-old")
        assert pending.stage == "CANCELLED"
        old_grant_state = grant.state
        if blocked == "lease": output._lease = (identity, "unconfirmed-snapshot")
        if blocked == "busy": await output._transfer_lock.acquire()
        if blocked == "retired": broker.cancel_identity(identity, "security termination")
        broker.begin_control(identity, "CONN-new", resumable=blocked != "legacy")
        assert not broker.channel_up(identity, "TEL-forged", "CONN-old")
        assert broker.channel_up(identity, "TEL-new", "CONN-new") == (blocked is None)
        if blocked is None:
            broker.channel_down(identity, "late old close", "TEL-old")
            assert identity not in broker._channel_lost
            assert broker.current_channel(identity, "TEL-new")
            assert not broker.current_channel(identity, "TEL-old")
            assert not output.acquisition["complete"]
            assert broker.store(identity, dict(payload, event_id=str(uuid.uuid4()), relative_path="fresh.txt"))
        else:
            assert identity in broker._channel_lost
        assert pending.stage == "CANCELLED" and grant.state == old_grant_state
        assert retained.read_bytes() == b"already verified on Host"
        if blocked == "busy": output._transfer_lock.release()
    asyncio.run(run())


def test_reset_reconnect_waits_for_acquisition_and_retires_unknown_lease(tmp_path, service):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        identity = session.identity
        broker.begin_control(identity, "old")
        assert broker.channel_up(identity, "old-telemetry", "old")
        checked = await receive(broker, output, session, b"checked receipt")
        retained = output.receipts[checked.artifact_id].folder / 'result.bin'
        output._lease = (identity, "reply-was-lost")
        await output._transfer_lock.acquire()
        started = asyncio.Event()
        async def reconnect():
            started.set()
            await broker.begin_reset_control(identity, "new")
        task = asyncio.create_task(reconnect())
        await started.wait()
        assert not task.done()
        assert not broker.channel_up(identity, "too-early", "new")
        output._transfer_lock.release()
        await task
        assert broker.channel_up(identity, "new-telemetry", "new")
        assert output._lease is None and not output.acquisition['complete']
        assert retained.read_bytes() == b"checked receipt"
        broker.channel_down(identity, "late old close", "old-telemetry")
        assert identity not in broker._channel_lost
        broker.cancel_identity(identity, "SECURITY_VIOLATION")
        await broker.begin_reset_control(identity, "after-retirement")
        assert not broker.channel_up(identity, "forged", "after-retirement")
    asyncio.run(run())


def test_cancel_during_scanner_write_releases_storage_reservation_once(tmp_path):
    from host.observation_store import UploadError
    async def run():
        writing, resume = asyncio.Event(), asyncio.Event()
        aborted = []
        class Stream:
            async def begin(self, *_): return 'owned-job'
            async def write(self, _):
                writing.set()
                await resume.wait()
            async def complete(self, _): pytest.fail('cancelled bytes must not complete')
            async def close(self): pass
        service = SimpleNamespace(upload=lambda _: Stream(), abort_soon=lambda *a: aborted.append(a))
        grants = ArtifactGrants(tmp_path / 'partial', service=service)
        grant, token = grants.issue(('SES-output', 'RT-1', 1), 'ART-1', str(uuid.uuid4()), 100)
        grants.claim(grant.upload_id, token, 8)
        reader = asyncio.StreamReader()
        reader.feed_data(b'partial!')
        task = asyncio.create_task(grants.receive(grant, reader, 8))
        await writing.wait()
        grants.cancel(grant)
        assert grants.bytes_held == 8
        resume.set()
        with pytest.raises(UploadError): await task
        assert grants.bytes_held == 0 and len(aborted) == 1
        grants.cancel(grant)
        assert grants.bytes_held == 0 and len(aborted) == 1
    asyncio.run(run())


@pytest.mark.parametrize('blocked', ['closing', 'generation', 'busy'])
def test_reset_reconnect_never_discards_unsettled_host_work(tmp_path, service, blocked):
    runtime, client = service()
    async def run():
        broker, session, _, output = setup(tmp_path, runtime, client)
        output._lease = (session.identity, 'keep')
        identity = session.identity
        if blocked == 'closing': output._closing = True
        if blocked == 'generation': identity = (identity[0], identity[1], identity[2] + 1)
        if blocked == 'busy': await output._transfer_lock.acquire()
        assert not await output.reconnect_reset(identity, timeout=.001)
        assert output._lease == (session.identity, 'keep')
        if blocked == 'busy': output._transfer_lock.release()
    asyncio.run(run())


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
                                  SimpleNamespace(session=host.backend.session), destination=tmp_path / "Downloads", automatic=False)
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


def test_replacement_generation_can_capture_without_reusing_old_lease_or_losing_receipts(tmp_path, service, monkeypatch):
    runtime, client = service()
    async def run():
        broker, old, _, output = setup(tmp_path, runtime, client)
        art = await receive(broker, output, old)
        output._lease = (old.identity, str(uuid.uuid4()))
        output._captured, output._closing = old.identity, True
        new = RuntimeSession((*old.identity[:2], old.identity[2] + 1))
        output.launcher.session = new
        output.bind(new)
        assert output.owns(art) and broker.grants.bytes_held == art.size
        assert not output.acquisition["complete"] and output._captured is None
        calls = []
        async def snapshot(session, operation, snapshot_id):
            assert session is new
            calls.append(operation)
            return {"files": []}
        monkeypatch.setattr(output, "_snapshot", snapshot)
        await output.refresh(new)
        assert calls == ["CAPTURE", "VERIFY", "RELEASE"]
        assert output.acquisition["identity"] == list(new.identity)
        assert output.acquisition["artifacts"] == [] and output.owns(art)
    asyncio.run(run())


@pytest.mark.parametrize("switch_at", ["CAPTURE", "VERIFY"])
def test_late_snapshot_reply_from_retired_generation_never_completes_current_capture(tmp_path, service, monkeypatch, switch_at):
    from host.artifacts import ArtifactError
    runtime, client = service()
    async def run():
        _, old, _, output = setup(tmp_path, runtime, client)
        new = RuntimeSession((*old.identity[:2], old.identity[2] + 1))
        calls = []
        async def snapshot(session, operation, snapshot_id):
            calls.append((session.identity, operation))
            if session is old and operation == switch_at:
                output.launcher.session = new
                output.bind(new)
            return {"files": []}
        monkeypatch.setattr(output, "_snapshot", snapshot)
        with pytest.raises(ArtifactError, match="retired Runner generation"):
            await output.refresh(old, closing=True)
        assert output._captured is None and not output.acquisition["complete"]
        assert calls[-1] == (old.identity, "RELEASE")
        await output.refresh(new, closing=True)
        assert output._captured == new.identity and output.acquisition["complete"]
        assert output.acquisition["identity"] == list(new.identity)
    asyncio.run(run())


@pytest.mark.parametrize("verdict", [Verdict.CLEAN, Verdict.DETECTED, Verdict.ERROR, Verdict.UNVERIFIABLE])
def test_automatic_exit_scan_has_no_dialogs_and_only_clean_is_saved(tmp_path, service, verdict):
    runtime, client = service(FakeScanner(verdict))
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        output.automatic = True
        art = await receive(broker, output, session)
        session.terminated = True
        output._captured = session.identity
        output.acquisition = {"complete": True, "artifacts": [art.artifact_id]}
        result = await output.finish_closed()
        view = result["artifacts"][0]
        assert human.events == []
        assert view["completed"] and view["notification"] == "mcp"
        assert art.stage == ("EXPORTED" if verdict == Verdict.CLEAN else "BLOCKED")
        assert bool(view["export_path"]) == (verdict == Verdict.CLEAN)
        files = list((tmp_path / "Downloads").rglob("result.bin"))
        assert len(files) == (1 if verdict == Verdict.CLEAN else 0)
        if files:
            assert files[0].read_bytes() == b"arbitrary binary\x00\xff"
            assert "ZoneId=3" in Path(str(files[0]) + ":Zone.Identifier").read_text()
        await output.finish_closed()
        assert len(runtime.scanner.scanned) == 1
    asyncio.run(run())


def test_automatic_incomplete_manifest_keeps_received_bytes_unpublished(tmp_path, service):
    runtime, client = service()
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        output.automatic = True
        art = await receive(broker, output, session)
        session.terminated = True
        await output.finish_closed()
        assert art.stage == "HELD" and output.owns(art)
        assert not runtime.scanner.scanned and not human.events
        assert not (tmp_path / "Downloads").exists()
    asyncio.run(run())


def test_mcp_automatic_export_returns_terminal_result_without_approver(tmp_path, service):
    from test_artifact_export import Host
    runtime, client = service()
    human = Human(runtime.scanner, "hold", "hold")
    async def run():
        host = Host(tmp_path / "host", approver=human)
        async def install():
            output = OutputExport(host.backend.artifacts, finisher(client), human,
                                  SimpleNamespace(session=host.backend.session), destination=tmp_path / "Downloads")
            async def no_snapshot(*args, **kwargs):
                pass
            output.refresh = no_snapshot
        await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(install(), host.backend.loop))
        runner, serving = await host.start()
        try:
            await runner.report("bundle.zip", b"PK\x00binary")
            art = (await host.call("artifact_list"))["artifacts"][0]
            result = await host.call("artifact_export", {"artifact_id": art["artifact_id"]})
            assert result["ok"] and result["accepted"] and result["completed"] and result["status"] == "EXPORTED", result
            assert Path(result["export_path"]).read_bytes() == b"PK\x00binary"
            assert not human.events
            repeat = await host.call("artifact_export", {"artifact_id": art["artifact_id"]})
            assert repeat["export_path"] == result["export_path"] and repeat["completed"]
            assert len(runtime.scanner.scanned) == 1
        finally:
            await host.close(serving)
    asyncio.run(run())


def test_wait_timeout_and_cancel_do_not_cancel_export():
    async def run():
        output = object.__new__(OutputExport)
        gate = asyncio.Event()
        task = asyncio.create_task(gate.wait())
        output._exports = {"ART-1": task}
        await output.wait(1, "ART-1")
        assert not task.done()
        waiter = asyncio.create_task(output.wait(30000))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not task.cancelled()
        gate.set()
        await task
    asyncio.run(run())


def test_exit_processes_each_file_after_malware_error_and_explicit_export(tmp_path, service):
    class MixedScanner(FakeScanner):
        def scan_file(self, path, cancel=None):
            self.verdict = {b"bad": Verdict.DETECTED, b"error": Verdict.ERROR}.get(
                path.read_bytes(), Verdict.CLEAN)
            return super().scan_file(path, cancel)

    runtime, client = service(MixedScanner())
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        output.automatic = True
        arts = [await receive(broker, output, session, data, path=f"{index}.bin")
                for index, data in enumerate([b"requested", b"bad", b"error", b"remaining"])]
        await output.export(session, arts[0])
        await output.wait(30000)
        assert arts[0].stage == "EXPORTED"
        session.terminated = True
        output._captured = session.identity
        output.acquisition = {"complete": True, "artifacts": [a.artifact_id for a in arts]}
        result = await output.finish_closed()
        assert [a.stage for a in arts] == ["EXPORTED", "BLOCKED", "BLOCKED", "EXPORTED"]
        assert all(v["completed"] for v in result["artifacts"])
        assert not human.events and len(runtime.scanner.scanned) == 4
        assert sorted(p.read_bytes() for p in (tmp_path / "Downloads").rglob("*.bin")) == [b"remaining", b"requested"]
        await output.finish_closed()
        assert len(runtime.scanner.scanned) == 4
    asyncio.run(run())


def test_unexpected_file_failure_does_not_abort_other_exit_exports(tmp_path, service, monkeypatch):
    runtime, client = service()
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        output.automatic = True
        failed = await receive(broker, output, session, path="failed.bin")
        good = await receive(broker, output, session, path="good.bin")
        finish = output.finisher._finish
        async def fail_one(share, *args, **kwargs):
            if share == output.receipts[failed.artifact_id].folder:
                raise RuntimeError("injected scanner failure")
            return await finish(share, *args, **kwargs)
        monkeypatch.setattr(output.finisher, "_finish", fail_one)
        session.terminated = True
        output._captured = session.identity
        output.acquisition = {"complete": True, "artifacts": [failed.artifact_id, good.artifact_id]}
        await output.finish_closed()
        assert failed.stage == "BLOCKED" and failed.result["code"] == "OUTPUT_FAILED"
        assert good.stage == "EXPORTED" and not human.events
        assert not list((tmp_path / "Downloads").rglob("failed.bin"))
    asyncio.run(run())


def test_journal_failure_after_publication_preserves_real_export(tmp_path, service, monkeypatch):
    runtime, client = service()
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        output.automatic = True
        art = await receive(broker, output, session)
        def fail_journal():
            raise OSError("injected journal failure")
        monkeypatch.setattr(output, "_persist", fail_journal)
        await output.export(session, art)
        await output.wait(30000)
        view = output.result_view(art)
        assert view["status"] == "EXPORTED" and view["completed"]
        assert Path(view["export_path"]).read_bytes() == b"arbitrary binary\x00\xff"
        assert "journal failure" in view["result"]["post_export_error"]
        assert not broker.needs_new_attempt(art) and not human.events
    asyncio.run(run())


@pytest.mark.parametrize("problem", ["unavailable", "changed"])
def test_automatic_unavailable_scanner_and_changed_bytes_never_publish(tmp_path, service, monkeypatch, problem):
    runtime, client = service()
    async def run():
        broker, session, human, output = setup(tmp_path, runtime, client)
        output.automatic = True
        art = await receive(broker, output, session, b"first")
        if problem == "unavailable":
            async def unavailable():
                raise ConnectionError("scanner service unavailable")
            monkeypatch.setattr(output.finisher, "_health", unavailable)
        else:
            import stat
            receipt = output.receipts[art.artifact_id]
            path = receipt.folder / receipt.name
            path.chmod(stat.S_IWRITE)
            path.write_bytes(b"other")
        await output.export(session, art)
        await output.wait(30000)
        assert output.result_view(art)["completed"] and art.stage == "BLOCKED"
        assert not human.events and not runtime.scanner.scanned
        assert not (tmp_path / "Downloads").exists()
    asyncio.run(run())
