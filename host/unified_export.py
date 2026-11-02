"""Shared and Runner Output use one review/scan/approval/publication transaction.

Only Host-owned candidate IDs cross MCP. Paths never come from export arguments.
Output still uses the existing one-use HTTPS grant; its temporary receive folder
must inherit the installation's deny-execute ACL. The service scans both sources
using its Shared profile. No scanner fallback or automatic user approval exists.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

from host.artifacts import (AUTHORIZED, BLOCKED, CANCELLED, EXPORTED, FAILED,
                            SCANNING, Artifact, ArtifactError, _safe_name)
from host.shared_scanner import ServiceSharedFinisher, _directory_lock, _manifest
from scanner_service import winfile

log = logging.getLogger("unified-export")


def inventory(root: Path, max_bytes: int) -> list[dict]:
    """Hash only regular files reached under pinned directories, never link targets."""
    if not root.exists():
        return []
    handles = []
    try:
        handles.append(_directory_lock(root))
        files = _manifest(root)
        pinned = {root}
        for item in files:
            path = root / item["name"]
            for parent in reversed(path.parents):
                if root in parent.parents and parent not in pinned:
                    handles.append(_directory_lock(parent))
                    pinned.add(parent)
            handle = winfile.open_locked(path, share_delete=False)
            try:
                info = winfile.identity(handle)
                if (info.links != 1 or info.attributes & (0x400 | 0x10)
                        or not winfile.same_path(winfile.final_path(handle), path)):
                    raise OSError("candidate changed or resolves through a link")
                if info.size > max_bytes:
                    item.update(size=info.size, sha256=None, blocked="FILE_TOO_LARGE")
                else:
                    size, sha = winfile.hash_handle(handle, max_bytes)
                    item.update(size=size, sha256=sha)
            finally:
                winfile.close(handle)
        return files
    finally:
        for handle in reversed(handles):
            winfile.close(handle)


class UnifiedExport:
    # Lifecycle must not turn the old pre-scan "keep" into final authorization.
    requires_post_scan_approval = True

    def __init__(self, artifacts, finisher: ServiceSharedFinisher, approver, launcher, *, destination=None):
        self.artifacts, self.finisher = artifacts, finisher
        self.approver, self.launcher = approver, launcher
        self.destination = destination
        self.loop = asyncio.get_running_loop()
        self._lock = asyncio.Lock()
        self._shared: dict[str, dict] = {}
        self._versions: dict[tuple, str] = {}
        self._exported: dict[tuple, tuple[str, str]] = {}
        artifacts.unified = self

    def cancel(self):
        self.finisher.cancel()

    def is_shared(self, art):
        return art.artifact_id in self._shared

    def destination_for(self, session_id):
        from sandbox_manager.importer import downloads_folder
        base = Path(self.destination) if self.destination else downloads_folder() / "SandboxShared"
        return base / session_id

    async def refresh(self, session):
        root = self.launcher.shared
        if root is None:
            return
        try:
            files = await asyncio.to_thread(inventory, root, self.artifacts.max_bytes)
        except OSError as exc:
            raise ArtifactError("ARTIFACT_BUSY", f"Shared is changing or unavailable: {exc}", retryable=True)
        current = set()
        for item in files:
            key = (session.identity, item["name"], item["size"], item["sha256"])
            aid = self._versions.get(key)
            if aid and (self.artifacts.get(aid).result or {}).get("code") == "CONTENT_CHANGED":
                aid = None
            if aid is None:
                event = secrets.token_hex(16)
                payload = {"event_id": event, "category": "ARTIFACT_CANDIDATE",
                           "relative_path": item["name"],
                           "observed_at": datetime.now(timezone.utc).isoformat()}
                if not self.artifacts.store(session.identity, payload):
                    raise ArtifactError("ARTIFACT_BUSY", "candidate storage is full")
                art = self.artifacts._by_event[(session.identity, event)]
                aid = art.artifact_id
                self._versions[key] = aid
                self._shared[aid] = dict(item)
                art.size, art.sha256 = item["size"], item["sha256"]
                if item.get("blocked"):
                    self.artifacts._end(art, BLOCKED, item["blocked"], "Shared file exceeds export limit")
            current.add(aid)
        for aid in self._shared:
            art = self.artifacts.get(aid)
            if art.identity == session.identity and aid not in current and self.artifacts.needs_new_attempt(art):
                self.artifacts._end(art, CANCELLED, "CONTENT_CHANGED", "Shared candidate was changed or removed")

    def summary(self, art):
        return {"files": [{"name": art.relative_path, "size": art.size}],
                "preserve_source": True, "unified_export": True}

    async def review(self, summary):
        callback = getattr(self.approver, "review_export", None)
        return await callback(summary) if callback else "hold"

    async def decide(self, summary):
        callback = getattr(self.approver, "choose_shared", None)
        return await callback(summary | {"unified_export": True}) if callback else "hold"

    async def notify(self, result):
        callback = getattr(self.approver, "notify_shared", None)
        if result["status"] in ("BLOCKED", "QUARANTINED") and callback:
            await callback(result)

    async def start_shared(self, session, art):
        art.stage, art.attempts = AUTHORIZED, art.attempts + 1
        art.task = asyncio.create_task(self._shared_run(session, art))
        return self.artifacts.view(art) | {"accepted": True}

    async def _shared_run(self, session, art):
        item = self._shared[art.artifact_id]
        try:
            async with self._lock:
                if session.terminated or art.stage != AUTHORIZED:
                    return
                art.stage = SCANNING
                result = await self.finisher._finish(
                    self.launcher.shared, self.destination_for(session.identity[0]),
                    lambda r: self.decide(r | {"preserve_source": True}),
                    selected=[item["name"]], expected={item["name"]: (item["size"], item["sha256"])},
                    preserve_source=True, target_name=art.artifact_id,
                    session_identity=session.identity,
                    cancelled=lambda: session.terminated or art.stage != SCANNING)
                self._record(art, result)
                if result["status"] == "EXPORTED":
                    self._exported[(session.identity[0], item["name"], item["sha256"])] = (
                        str(art.export_path), item["sha256"])
                await self.notify(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.artifacts._end(art, FAILED, "EXPORT_FAILED", str(exc), retry=False)

    async def received(self, art, grant):
        """Runner upload was cross-checked against ARTIFACT_RESULT; now use the common path."""
        folder = None
        try:
            async with self._lock:
                if art.stage != SCANNING or grant.path is None:
                    return
                # New directory under the same protected receive root; never a Guest path.
                folder = grant.path.parent / ("export-" + secrets.token_hex(16))
                folder.mkdir()
                name = _safe_name(art.relative_path)
                moved = folder / name
                grant.path.rename(moved)
                grant.path = moved
                result = await self.finisher._finish(
                    folder, self.destination_for(art.identity[0]), self.decide,
                    expected={name: (grant.size, grant.sha256)}, target_name=art.artifact_id,
                    session_identity=art.identity,
                    cancelled=lambda: art.stage != SCANNING)
                self._record(art, result)
                self.artifacts.grants.discard(grant)
                await self.notify(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.artifacts._end(art, FAILED, "EXPORT_FAILED", str(exc), retry=False)
        finally:
            if folder and folder.exists():
                # Only our generated receive directory. No Shared/user folder is removed.
                self.artifacts.grants.discard(grant)
                try:
                    folder.rmdir()
                except OSError:
                    log.warning("unpublished receive directory remains: %s", folder)

    def _record(self, art, result):
        if art.stage != SCANNING:
            return
        if result["status"] == "EXPORTED":
            item = result["files"][0]
            art.stage, art.export_path = EXPORTED, Path(result["dest"]) / item["name"]
            art.size, art.sha256 = item["size"], item["sha256"]
            art.result = {"code": "EXPORTED", "detail": result["scan"], "engine": "defender-service"}
            log.info("UNIFIED %s EXPORTED %s sha256=%s", art.artifact_id, art.export_path, art.sha256)
        else:
            self.artifacts._end(art, BLOCKED if result["status"] == "BLOCKED" else FAILED,
                                result["status"], result.get("scan") or "user did not approve final export",
                                retry=False)

    def __call__(self, share, dest=None, decide=None):
        # Called by the lifecycle worker after VM shutdown/cleanup is confirmed.
        return asyncio.run_coroutine_threadsafe(self.finish_closed(Path(share), dest), self.loop).result(900)

    async def finish_closed(self, share, dest=None):
        async with self._lock:
            files = await asyncio.to_thread(inventory, share, self.artifacts.max_bytes)
            pending = []
            for item in files:
                saved = self._exported.get((share.name, item["name"], item["sha256"]))
                if saved:
                    from host.artifacts import _check_published
                    path = Path(saved[0])
                    if await asyncio.to_thread(_check_published, path, path, item["size"], item["sha256"]) is None:
                        continue
                pending.append(item)
            # A normal shutdown with no previously exported files retains delete/hold semantics.
            selected = [f["name"] for f in pending] if len(pending) != len(files) else None
            if not pending:
                return {"status": "EMPTY", "share": str(share), "dest": None,
                        "files": [], "scan": None, "events": []}
            result = await self.finisher._finish(
                share, dest or self.destination_for(share.name), self.decide, review=self.review, selected=selected,
                target_name="remaining-" + secrets.token_hex(6),
                session_identity=self.launcher.session.identity,
                expected={f["name"]: (f["size"], f["sha256"]) for f in pending})
            # Preserve automatic shutdown results for artifact_list after runtime retirement.
            for item in result["files"]:
                self.artifacts._seq += 1
                aid = f"ART-{self.artifacts._seq:06d}"
                art = Artifact(aid, self.launcher.session.identity, secrets.token_hex(16), item["name"],
                               datetime.now(timezone.utc).isoformat(), {}, stage=SCANNING)
                self.artifacts._by_id[aid] = art
                self._shared[aid] = dict(item)
                self._record(art, result | {"files": [item]})
            await self.notify(result)
            return result
