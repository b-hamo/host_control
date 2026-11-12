"""Output is staged over HTTPS, scanned and automatically published only on CLEAN.

Staging is never publication. A received copy survives VM retirement and a
failed scan. MCP carries results; no writable Host folder is mapped into the Guest.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from host.artifacts import (ArtifactError, AUTHORIZED, BLOCKED, CANDIDATE, EXPORTED,
                            FAILED, SCANNING, _safe_name, _check_published)
from scrp.validate import ProtocolError

log = logging.getLogger("host-output")
OUTPUT_CAPABILITY = "artifact.output.v1"
STAGED, HELD, DELETED = "STAGED", "HELD", "DELETED"


@dataclass
class Receipt:
    folder: Path
    name: str
    size: int
    sha256: str


class OutputExport:
    output_only = True

    def __init__(self, artifacts, finisher, approver, launcher, *, destination=None, automatic=True):
        self.automatic = automatic
        self._exports: dict[str, asyncio.Task] = {}
        self.artifacts, self.finisher, self.approver, self.launcher = artifacts, finisher, approver, launcher
        self.destination = destination
        self.receipts: dict[str, Receipt] = {}
        self._transfer_lock, self._finish_lock = asyncio.Lock(), asyncio.Lock()
        self._prefetch: set[asyncio.Task] = set()
        self.requested: set[str] = set()
        self._reviewing: set[str] = set()
        self._closing = False
        self._captured: tuple | None = None
        self._last_refresh = 0.0
        self._lease: tuple | None = None
        self.acquisition: dict = {"status": "NOT_STARTED", "complete": False}
        artifacts.unified = self
        launcher.output = self
        self.bind(launcher.session)

    def bind(self, session):
        previous = getattr(self, "_identity", None)
        self._identity = session.identity
        if previous is not None and previous != session.identity:
            # The replacement Runner has its own Output tree and snapshot IDs.
            # Manager retires the old Runner; never send its lease to the new
            # generation or describe its already received copies as current.
            self._lease = self._captured = None
            self._closing = False
            self._last_refresh = 0.0
            self.acquisition = {"status": "INCOMPLETE", "complete": False,
                                "identity": list(session.identity),
                                "detail": "Runner generation changed; earlier received copies retained"}
            self._persist()
        session.before_terminate = self.before_terminate

    def _require_current(self, session):
        if session.identity != self._identity:
            raise ArtifactError("ARTIFACT_BLOCKED", "Output snapshot belongs to a retired Runner generation")

    def reconnect_idle(self, identity):
        """Resume only at a quiescent boundary; retain all checked Host copies."""
        if (identity != self._identity or self._closing or self._lease is not None or
                self._transfer_lock.locked() or any(not task.done() for task in self._prefetch)):
            return False
        self._captured = None
        self._last_refresh = 0.0
        self.acquisition = {"status": "INCOMPLETE", "complete": False,
                            "identity": list(identity), "detail": "Control reconnected; fresh Output snapshot required"}
        self._persist()
        return True

    async def reconnect_reset(self, identity, *, timeout=5.0):
        """Fresh authenticated Runner promises old file workers/leases ended.

        Wait for Host acquisition to unwind too. No partial bytes, old grants,
        snapshot IDs or input actions are resumed. A new capture must rehash all
        files; verified Host receipts remain available for their normal scan.
        """
        if identity != self._identity or self._closing:
            return False
        try:
            await asyncio.wait_for(self._transfer_lock.acquire(), timeout)
        except asyncio.TimeoutError:
            return False
        try:
            if identity != self._identity or self._closing:
                return False
            self._lease = self._captured = None
            self._last_refresh = 0.0
            self.acquisition = {"status": "INCOMPLETE", "complete": False, "identity": list(identity),
                                "detail": "File transport reset; partial attempts cancelled; fresh snapshot required"}
            self._persist()
            return True
        finally:
            self._transfer_lock.release()

    def owns(self, art):
        return art.artifact_id in self.receipts

    def is_shared(self, art):
        return False

    def destination_for(self, session_id):
        from sandbox_manager.importer import downloads_folder
        return (Path(self.destination) if self.destination else downloads_folder() / "SandboxOutput") / session_id

    def summary(self, art):
        return {"files": [{"name": art.relative_path, "size": art.size}],
                "unified_export": True, "output_only": True,
                "preserve_source": False}

    async def review(self, summary):
        callback = getattr(self.approver, "review_export", None)
        return await callback(summary | {"unified_export": True, "output_only": True}) if callback else "hold"

    async def decide(self, summary):
        if self.automatic:
            # The scanner calls this only after all bytes have a verified CLEAN receipt.
            return "keep" if summary.get("status") == "CLEAN" else "hold"
        callback = getattr(self.approver, "choose_shared", None)
        return await callback(summary | {"unified_export": True, "output_only": True}) if callback else "hold"

    async def prepare_review(self, session, artifact_id):
        art = self.artifacts.get(artifact_id)
        self._reviewing.add(artifact_id)
        try:
            async with self._transfer_lock:
                await self._receive(session, art)
        except BaseException:
            self._reviewing.discard(artifact_id)
            raise
        receipt = self.receipts[artifact_id]
        return self.summary(art) | {"share": str(receipt.folder),
                                   "planned_destination": str(self.destination_for(art.identity[0]) / artifact_id)}

    async def decline_review(self, artifact_id, choice):
        self._reviewing.discard(artifact_id)
        art = self.artifacts.get(artifact_id)
        if choice == "delete":
            self._discard_receipt(art)
            art.stage, art.result = DELETED, {"code": "DELETED", "detail": "user declined list review and deleted received copy"}
        else:
            art.stage, art.result = HELD, {"code": "HELD", "detail": "list review deferred; received copy retained"}
        self._persist()
        await self.notify({"status": art.stage, "share": str(self.artifacts.grants.incoming_dir), "files": [], "dest": None})

    def _discard_receipt(self, art):
        receipt = self.receipts[art.artifact_id]
        self.artifacts.grants._discard_path(receipt.folder / receipt.name)
        receipt.folder.rmdir()
        del self.receipts[art.artifact_id]
        self.artifacts.grants.bytes_held -= receipt.size

    async def notify(self, result):
        if self.automatic:
            return  # MCP responses replace all Output result dialogs.
        callback = getattr(self.approver, "notify_output", None)
        if callback:
            await callback(result)
        elif result["status"] in ("BLOCKED", "QUARANTINED"):
            callback = getattr(self.approver, "notify_shared", None)
            if callback:
                await callback(result)

    def candidate(self, identity, art):
        if self._closing or identity != self.launcher.session.identity:
            return
        task = asyncio.create_task(self._prefetch_one(self.launcher.session, art))
        self._prefetch.add(task)
        task.add_done_callback(self._prefetch.discard)

    async def _prefetch_one(self, session, art):
        try:
            async with self._transfer_lock:
                if self._closing or session.terminated:
                    return
                await self._receive(session, art)
        except (ArtifactError, ProtocolError, OSError) as exc:
            log.warning("Output prefetch incomplete for %s: %s", art.artifact_id, exc)

    async def _receive(self, session, art):
        if self.owns(art) or art.stage == EXPORTED:
            return
        if art.stage == AUTHORIZED and art.task:
            await asyncio.shield(art.task)
        else:
            if art.stage != CANDIDATE:
                raise ArtifactError("ARTIFACT_BLOCKED", f"{art.artifact_id}: no verified received copy")
            await self.artifacts.transfer(session, art)
            await asyncio.shield(art.task)
        if not self.owns(art):
            raise ArtifactError("ARTIFACT_BLOCKED", f"{art.artifact_id}: transfer did not produce a verified copy")

    async def received(self, art, grant):
        if art.stage != SCANNING or grant.path is None:
            raise ArtifactError("ARTIFACT_BLOCKED", "missing verified Output upload")
        folder = self.artifacts.grants.incoming_dir / art.artifact_id
        folder.mkdir()
        name = _safe_name(art.relative_path)
        destination = folder / name
        grant.path.rename(destination)
        receipt = Receipt(folder, name, grant.size, grant.sha256)
        # Ownership moves from an expiring grant to the durable Output queue.
        # Its bytes remain charged against the receive limit until disposition.
        grant.path = None
        art.grant = None
        self.receipts[art.artifact_id] = receipt
        art.stage = STAGED
        art.result = {"code": "STAGED", "detail": "received and hashed; not scanned or approved"}
        # A newer verified copy replaces only unattended staging, never a copy
        # held by a user or currently undergoing review/scan.
        for aid in list(self.receipts):
            previous = self.artifacts.get(aid)
            if (aid != art.artifact_id and previous.identity == art.identity and
                    PureWindowsPath(previous.relative_path) == PureWindowsPath(art.relative_path) and
                    previous.stage == STAGED and aid not in self.requested and aid not in self._reviewing):
                self._discard_receipt(previous)
                previous.stage = "SUPERSEDED"
                previous.result = {"code": "SUPERSEDED", "replacement": art.artifact_id}
        self._persist()

    async def _matching_copy(self, identity, path, size, sha256):
        """Reuse only identical received bytes or an exact prior disposition.

        A Guest hash is a lookup hint, never a scan verdict. Retained bytes are
        hashed on the Host again; publication still scans that locked Host copy.
        """
        for art in reversed(list(self.artifacts._by_id.values())):
            if (art.identity != identity or PureWindowsPath(art.relative_path) != path or
                    (art.size, art.sha256) != (size, sha256)):
                continue
            if art.stage == DELETED:
                return art
            receipt = self.receipts.get(art.artifact_id)
            target = receipt.folder / receipt.name if receipt else art.export_path if art.stage == EXPORTED else None
            if target is not None and await asyncio.to_thread(_check_published, target, target, size, sha256) is None:
                return art
        return None

    def _persist(self):
        root = self.artifacts.grants.incoming_dir
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        for aid, receipt in self.receipts.items():
            art = self.artifacts.get(aid)
            rows.append({"artifact_id": aid, "identity": list(art.identity), "path": art.relative_path,
                         "file": str(receipt.folder / receipt.name), "size": receipt.size,
                         "sha256": receipt.sha256, "stage": art.stage, "result": art.result})
        pending = root / "output-state.json.tmp"
        with pending.open("w", encoding="utf-8") as stream:
            json.dump({"acquisition": self.acquisition, "files": rows}, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(root / "output-state.json")

    async def _snapshot(self, session, operation, snapshot_id):
        if OUTPUT_CAPABILITY not in session.granted_capabilities:
            raise ArtifactError("ARTIFACT_BLOCKED", "Runner requires artifact.output.v1; update sandbox_runner")
        conn = session._live()
        request = conn.me.envelope("OUTPUT_SNAPSHOT_REQUEST", {
            "snapshot_id": snapshot_id, "operation": operation,
            "max_file_bytes": self.artifacts.max_bytes,
            "max_total_bytes": min(self.artifacts.grants.store_limit, 209715200)})
        reply = await conn.request(request, ("OUTPUT_SNAPSHOT_RESULT",), timeout=60.0)
        payload = reply["payload"]
        if (reply["status"] != "OK" or payload["snapshot_id"] != snapshot_id or
                payload["operation"] != operation or not payload["complete"]):
            raise ArtifactError("ARTIFACT_BLOCKED", f"Output {operation} failed: {payload.get('problem')}")
        return payload

    async def refresh(self, session, *, closing=False):
        if not closing and (self._closing or self._transfer_lock.locked() or
                            asyncio.get_running_loop().time() - self._last_refresh < 5):
            return
        async with self._transfer_lock:
            self._require_current(session)
            if self._lease is not None:
                identity, lease_id = self._lease
                if identity != session.identity:
                    raise ArtifactError("ARTIFACT_BLOCKED", "unreleased Output snapshot belongs to another generation")
                await self._snapshot(session, "RELEASE", lease_id)
                self._lease = None
            if closing:
                self._captured = None
            snapshot_id = str(uuid.uuid4())
            # CAPTURE may succeed in the Runner even if its reply is lost.
            # Retain the requested ID before sending so cleanup never requires
            # a second CAPTURE or replacement of an unknown locked snapshot.
            self._lease = (session.identity, snapshot_id)
            try:
                manifest = await self._snapshot(session, "CAPTURE", snapshot_id)
                self._require_current(session)
                seen, events, current = set(), set(), []
                for item in manifest["files"]:
                    path = PureWindowsPath(item["relative_path"])
                    key = str(path).casefold()
                    if (path.is_absolute() or path.drive or ".." in path.parts or
                            key in seen or item["candidate_event_id"] in events):
                        raise ArtifactError("ARTIFACT_BLOCKED", "invalid or duplicate Output manifest path/event")
                    seen.add(key)
                    events.add(item["candidate_event_id"])
                    previous = await self._matching_copy(session.identity, path, item["size_bytes"], item["sha256"])
                    if previous is not None:
                        current.append(previous.artifact_id)
                        continue
                    payload = {"event_id": item["candidate_event_id"], "relative_path": str(path),
                               "observed_at": datetime.now(timezone.utc).isoformat(), "category": "OUTPUT_SNAPSHOT"}
                    if not self.artifacts.store(session.identity, payload):
                        raise ArtifactError("ARTIFACT_BUSY", "Output manifest exceeds candidate storage")
                    art = self.artifacts._by_event[(session.identity, payload["event_id"])]
                    await self._receive(session, art)
                    if (art.size, art.sha256) != (item["size_bytes"], item["sha256"]):
                        raise ArtifactError("ARTIFACT_BLOCKED", "received Output bytes differ from locked manifest")
                    current.append(art.artifact_id)
                await self._snapshot(session, "VERIFY", snapshot_id)
                self._require_current(session)
                self.acquisition = {"status": "CAPTURED", "complete": True, "snapshot_id": snapshot_id,
                                    "identity": list(session.identity), "artifacts": current}
                self._captured = session.identity if closing else None
                self._last_refresh = asyncio.get_running_loop().time()
                self._persist()
            except BaseException as exc:
                self.acquisition = {"status": "INCOMPLETE", "complete": False, "detail": str(exc)}
                self._persist()
                raise
            finally:
                # A closing snapshot stays locked until Runner TERMINATE. A
                # failed capture/verify is released, without publishing anything.
                if not closing or self._captured != session.identity:
                    try:
                        await self._snapshot(session, "RELEASE", snapshot_id)
                        self._lease = None
                    except (ArtifactError, ProtocolError) as exc:
                        log.error("Output snapshot release unconfirmed: %s", exc)
                        self.acquisition = {"status": "INCOMPLETE", "complete": False,
                                            "detail": "Output snapshot release unconfirmed"}
                        self._persist()
                        raise

    async def before_terminate(self, session, reason):
        if reason == "SECURITY_VIOLATION":
            self._captured = None
            return
        self._closing = True
        try:
            await self.refresh(session, closing=True)
        except (ArtifactError, ProtocolError, OSError) as exc:
            self._closing = False
            await self.notify({"status": "INCOMPLETE", "scan": str(exc), "files": [],
                               "share": str(self.artifacts.grants.incoming_dir), "dest": None})
            raise ProtocolError("ARTIFACT_BLOCKED", f"Output acquisition incomplete; Sandbox kept running: {exc}") from exc

    async def export(self, session, art):
        self.requested.add(art.artifact_id)
        self._reviewing.discard(art.artifact_id)
        async def finish():
            try:
                async with self._transfer_lock:
                    await self._receive(session, art)
                await self._publish(art, reviewed=True)
            except asyncio.CancelledError:
                self._record_failure(art, "export interrupted during Host shutdown")
                raise
            except Exception as exc:  # Each failed file must have a terminal MCP result.
                self._record_failure(art, str(exc))
            finally:
                self.requested.discard(art.artifact_id)
        # Automatic Output uses the explicit MCP request; legacy mode reviewed the ID.
        task = asyncio.create_task(finish())
        self._exports[art.artifact_id] = task
        self._prefetch.add(task)
        task.add_done_callback(self._prefetch.discard)
        return self.artifacts.view(art) | {"accepted": True}

    def _record_failure(self, art, detail):
        if art.stage == EXPORTED:
            # A journal/notification failure after publication must not hide a
            # real download or make the next request publish it a second time.
            art.result = dict(art.result or {}, post_export_error=detail)
        else:
            art.result = {"code": "OUTPUT_FAILED", "detail": detail}
            art.stage = BLOCKED if self.automatic else HELD if self.owns(art) else FAILED
        try:
            self._persist()
        except OSError:
            log.exception("Output result journal unavailable for %s", art.artifact_id)

    async def wait(self, wait_ms, artifact_id=None):
        tasks = [task for aid, task in self._exports.items()
                 if not task.done() and (artifact_id is None or aid == artifact_id)]
        if tasks and wait_ms:
            # A client timeout/cancellation must not cancel or repeat publication.
            await asyncio.wait(tasks, timeout=wait_ms / 1000)

    def result_view(self, art):
        view = self.artifacts.view(art)
        terminal = art.stage in (EXPORTED, BLOCKED, FAILED, HELD, DELETED, "SUPERSEDED", "CANCELLED")
        completed = terminal and art.artifact_id not in self.requested
        return view | {"completed": completed,
                       "next_step": None if completed else "artifact_list",
                       "notification": "mcp", "automatic_export": self.automatic}

    async def _publish(self, art, *, reviewed=False):
        async with self._finish_lock:
            if art.stage in (EXPORTED, BLOCKED, DELETED):
                return
            receipt = self.receipts.get(art.artifact_id)
            if receipt is None:
                return
            if not reviewed:
                for previous in self.artifacts._by_id.values():
                    if (previous.stage == EXPORTED and previous.identity == art.identity and
                            previous.relative_path == art.relative_path and
                            (previous.size, previous.sha256) == (receipt.size, receipt.sha256) and
                            await asyncio.to_thread(_check_published, previous.export_path, previous.export_path,
                                                    receipt.size, receipt.sha256) is None):
                        self._discard_receipt(art)
                        art.stage, art.export_path, art.result = EXPORTED, previous.export_path, dict(previous.result)
                        self._persist()
                        return
            art.stage = SCANNING
            result = await self.finisher._finish(
                receipt.folder, self.destination_for(art.identity[0]), self.decide,
                review=None if reviewed or self.automatic else self.review,
                expected={receipt.name: (receipt.size, receipt.sha256)},
                target_name=art.artifact_id, session_identity=art.identity)
            status = result["status"]
            if status == "EXPORTED":
                art.stage, art.export_path = EXPORTED, Path(result["dest"]) / receipt.name
                art.result = {"code": "EXPORTED", "detail": result["scan"], "engine": "defender-service"}
            else:
                art.stage = DELETED if status == "DELETED" else HELD if status == "HELD" else BLOCKED
                art.result = {"code": status, "detail": result.get("scan") or "user disposition"}
            if status in ("EXPORTED", "DELETED", "EMPTY"):
                if receipt.folder.exists():
                    # Publication succeeded, but deletion can fail (for example
                    # an AV handle). Keep both accounting and recovery evidence.
                    art.result["cleanup_pending"] = str(receipt.folder)
                else:
                    self.receipts.pop(art.artifact_id)
                    self.artifacts.grants.bytes_held -= receipt.size
            self._persist()
            await self.notify(result)

    async def finish_closed(self):
        self._closing = True
        self._lease = None  # VM retirement released the Guest's pinned handles.
        await asyncio.gather(*self._prefetch, return_exceptions=True)
        current = set(self.acquisition.get("artifacts", [])) if self.acquisition["complete"] else None
        if self._captured != self.launcher.session.identity:
            current = None
            self.acquisition = {"status": "INCOMPLETE", "complete": False,
                                "detail": "VM ended without verified final Output capture; received copies may be older"}
            await self.notify({"status": "INCOMPLETE", "scan": self.acquisition["detail"], "files": [],
                               "share": str(self.artifacts.grants.incoming_dir), "dest": None})
        # A verified full manifest selects current copies. Older prefetched
        # versions remain held, never silently represented as the latest file.
        for aid in list(self.receipts):
            art = self.artifacts.get(aid)
            if art.stage in (EXPORTED, DELETED):
                try:
                    self._discard_receipt(art)
                    art.result.pop("cleanup_pending", None)
                except OSError:
                    log.warning("Output cleanup pending for %s", aid, exc_info=True)
                continue
            if art.stage == BLOCKED:
                continue
            if (self.automatic and current is None) or (current is not None and aid not in current):
                art.stage = HELD
                art.result = {"code": "OLDER_COPY_HELD", "detail": "not selected by final Output manifest"}
                continue
            try:
                await self._publish(art)
            except Exception as exc:  # One failure must not skip the remaining Output files.
                self._record_failure(art, str(exc))
        self._persist()
        return {"acquisition": self.acquisition, "held": len(self.receipts), "completed": True,
                "artifacts": [self.result_view(a) for a in self.artifacts._by_id.values()]}

    def cancel(self):
        self._closing = True
        self.finisher.cancel()
