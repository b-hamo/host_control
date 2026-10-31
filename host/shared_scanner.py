"""Shared -> service quarantine/Defender -> Downloads/SandboxShared.

Called by SandboxLauncher only after VM shutdown is confirmed. Unlike the legacy
finish_shared scan callback, this owns the entire scan/choice/copy transaction:
the source handles stay locked until the last checked byte has been copied.
No service failure falls back to sandbox_manager's direct MpCmdRun scanner.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import shutil
import stat
import threading
import time
from pathlib import Path

from host.scanner_client import ScannerServiceClient, job_identity
from scanner_service import winfile

log = logging.getLogger("shared-scanner")
ACCOUNT = "NT SERVICE\\SecureArtifactScanner"
CHUNK = 64 * 1024


class SharedScanError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _directory_lock(path: Path):
    """Pin a directory against rename/deletion; child reads/writes are still possible."""
    import win32con
    import win32file
    winfile.check_plain_dir(path)
    handle = win32file.CreateFile(str(path), winfile.FILE_READ_ATTRIBUTES,
                                  winfile.FILE_SHARE_READ | winfile.FILE_SHARE_WRITE, None,
                                  win32con.OPEN_EXISTING,
                                  winfile.FILE_FLAG_BACKUP_SEMANTICS | winfile.FILE_FLAG_OPEN_REPARSE_POINT, None)
    if not winfile.same_path(winfile.final_path(handle), path.absolute()):
        handle.Close()
        raise SharedScanError("CONTENT_CHANGED", "directory resolves through a link")
    return handle


def _manifest(root: Path) -> list[dict]:
    """Reject links, special files, ADS-like names and ambiguous Windows names; never follow them."""
    from sandbox_manager.importer import check_name
    from sandbox_manager.config import SHARED_FILES_MAX, SHARED_TOTAL_MAX
    files, total = [], 0

    def walk(folder: Path):
        nonlocal total
        winfile.check_plain_dir(folder)
        with os.scandir(folder) as entries:
            for entry in entries:
                check_name(entry.name)
                p = Path(entry.path)
                info = p.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise SharedScanError("LINK_REFUSED", "Shared contains a link or reparse point")
                if stat.S_ISDIR(info.st_mode):
                    walk(p)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                    files.append({"name": str(p.relative_to(root)), "size": info.st_size})
                    if len(files) > SHARED_FILES_MAX or total > SHARED_TOTAL_MAX:
                        raise SharedScanError("LIMIT_EXCEEDED", "Shared file count or total size exceeds policy")
                else:
                    raise SharedScanError("LINK_REFUSED", "Shared contains a hard link or special file")
    walk(root)
    return sorted(files, key=lambda f: f["name"].casefold())


class ServiceSharedFinisher:
    """finish_shared-compatible callable, invoked in a lifecycle worker thread.

    Service PUBLISH is intentionally unavailable to Shared jobs. The Host copies
    only its still-locked originals matching the service's size/SHA-256 receipt;
    the service needs no filesystem access to Shared or the user's Downloads.
    """
    def __init__(self, client=None, *, expected_account=ACCOUNT, timeout_s=600.0):
        self.client = client or ScannerServiceClient()
        self.expected_account = expected_account
        self.timeout_s = timeout_s
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()

    def _check_cancelled(self):
        if self._cancelled.is_set():
            raise SharedScanError("CANCELLED", "Host shutdown cancelled Shared export")

    def __call__(self, share, dest=None, decide=None):
        return asyncio.run(self._finish(Path(share).absolute(), dest, decide))

    async def check_available(self):
        """Fail before launching the integrated solution if Shared scanning is unavailable."""
        await self._health()

    async def _health(self):
        h = await self.client.health()
        token = h.get("token") or {}
        shared = h.get("shared_scan") or {}
        if self.expected_account and (str(token.get("account", "")).casefold() != self.expected_account.casefold()
                                     or token.get("is_admin") or token.get("is_local_system")
                                     or token.get("administrators_group")):
            raise SharedScanError("SCANNER_UNAVAILABLE", "scanner service account is not the dedicated non-admin account")
        if not h.get("accepting") or not (h.get("defender") or {}).get("available"):
            raise SharedScanError("SCANNER_UNAVAILABLE", "scanner service or Defender is unavailable")
        if shared.get("enabled") is not True:
            raise SharedScanError("SHARED_SCAN_DISABLED", "rebuild/install the service with -EnableSharedScan")
        limit = shared.get("max_file_bytes")
        chunk = (h.get("limits") or {}).get("max_chunk_bytes")
        if type(limit) is not int or limit <= 0 or type(chunk) is not int or chunk <= 0:
            raise SharedScanError("SCANNER_UNAVAILABLE", "invalid scanner limits")
        return limit, min(CHUNK, chunk)

    async def _scan(self, handle, item, ident, limit, chunk, deadline):
        self._check_cancelled()
        if time.monotonic() >= deadline:
            raise SharedScanError("SCAN_TIMEOUT", "Shared scan deadline exceeded")
        stream = self.client.upload(ident)
        primary_error = False
        try:
            await stream.begin(Path(item["name"]).name, item["size"], scan_profile="shared")
            digest, size = hashlib.sha256(), 0
            for block in winfile.read_blocks(handle, limit):
                digest.update(block)
                size += len(block)
                for offset in range(0, len(block), chunk):
                    self._check_cancelled()
                    if time.monotonic() >= deadline:
                        raise SharedScanError("SCAN_TIMEOUT", "Shared scan deadline exceeded")
                    await stream.write(block[offset:offset + chunk])
            if size != item["size"]:
                raise SharedScanError("CONTENT_CHANGED", "source size changed")
            sha = digest.hexdigest()
            await stream.complete(sha)
            await stream.close()       # free the upload pipe before scan/status/abort
            view = await self.client.scan(ident, stream.job_id)
            while view.get("state") == "SCANNING":
                self._check_cancelled()
                if time.monotonic() >= deadline:
                    raise SharedScanError("SCAN_TIMEOUT", "Shared scan deadline exceeded")
                await asyncio.sleep(0.05)
                view = await self.client.status(ident, stream.job_id)
            if view.get("state") != "SCANNED" or (view.get("scan") or {}).get("verdict") != "CLEAN":
                error = view.get("error") or {}
                raise SharedScanError(error.get("code", "SCAN_UNVERIFIABLE"),
                                      error.get("message", "no confirmed CLEAN verdict"))
            if (view.get("size"), view.get("sha256"), view.get("scan_profile")) != (size, sha, "shared"):
                raise SharedScanError("RESPONSE_MISMATCH", "scan receipt does not match uploaded Shared bytes")
            item["sha256"] = sha
            item["scanner_job_id"] = stream.job_id
        except BaseException:
            primary_error = True
            raise
        finally:
            await stream.close()
            if stream.job_id:
                try:
                    await self.client.abort(ident, stream.job_id, "Shared scan finished; Host retains locked original")
                except Exception:
                    log.warning("Shared scanner cleanup failed for %s", stream.job_id, exc_info=True)
                    if not primary_error:
                        raise

    async def _finish(self, share, dest, decide):
        from sandbox_manager.importer import downloads_folder, unique_path
        from sandbox_manager.shared import _remove
        result = {"share": str(share), "dest": None, "files": [], "scan": None,
                  "engine": "defender-service", "events": []}
        handles, dirs = [], []
        stage = None
        remove_source = False
        deadline = time.monotonic() + self.timeout_s
        try:
            dirs.append(_directory_lock(share))
            manifest = _manifest(share)
            result["files"] = [dict(f) for f in manifest]
            if not manifest:
                remove_source = True
                return result | {"status": "EMPTY"}
            limit, chunk = await self._health()
            identity = ("SHARED-" + secrets.token_hex(12), "RT-SHARED", 1)
            pinned = {share}
            for item in result["files"]:
                if item["size"] > limit:
                    raise SharedScanError("FILE_TOO_LARGE", f"Shared file exceeds service limit {limit}: {item['name']}")
                path = share / item["name"]
                for parent in reversed(path.parents):
                    if parent != share and share in parent.parents and parent not in pinned:
                        dirs.append(_directory_lock(parent))
                        pinned.add(parent)
                handle = winfile.open_locked(path, share_delete=False)
                handles.append(handle)
                info = winfile.identity(handle)
                if (info.links != 1 or info.attributes & (0x400 | 0x10) or info.size != item["size"]
                        or not winfile.same_path(winfile.final_path(handle), path)):
                    raise SharedScanError("CONTENT_CHANGED", "Shared file identity or path changed")
            # All originals remain locked through scan, user choice and copy. Never rescan by path.
            for index, (handle, item) in enumerate(zip(handles, result["files"])):
                await self._scan(handle, item, job_identity(identity, f"SHARED-{index}"), limit, chunk, deadline)
            result["scan"] = "clean: SecureArtifactScanner verified all Shared files"
            if _manifest(share) != manifest:
                raise SharedScanError("CONTENT_CHANGED", "Shared contents changed during scanning")
            try:
                choice = decide(result | {"status": "CLEAN"}) if decide else "hold"
            except Exception:
                choice = "hold"
            if _manifest(share) != manifest:
                raise SharedScanError("CONTENT_CHANGED", "Shared contents changed during approval")
            self._check_cancelled()
            if choice == "delete":
                remove_source = True
                return result | {"status": "DELETED"}
            if choice != "keep":
                return result | {"status": "HELD"}
            base = Path(dest).absolute() if dest is not None else downloads_folder() / "SandboxShared"
            base.mkdir(parents=True, exist_ok=True)
            dirs.append(_directory_lock(base))
            target = unique_path(base, share.name)
            stage = base / (".scanner-" + secrets.token_hex(16) + ".partial")
            stage.mkdir()       # new, never reuse an existing directory
            for handle, item in zip(handles, result["files"]):
                output = stage / item["name"]
                output.parent.mkdir(parents=True, exist_ok=True)
                digest, size = hashlib.sha256(), 0
                with output.open("xb") as out:
                    for block in winfile.read_blocks(handle, limit):
                        self._check_cancelled()
                        out.write(block)
                        digest.update(block)
                        size += len(block)
                    out.flush()
                    os.fsync(out.fileno())
                if (size, digest.hexdigest()) != (item["size"], item["sha256"]):
                    raise SharedScanError("CONTENT_CHANGED", "copy differs from the scanned bytes")
                # Fail closed if MOTW cannot be written; do not copy source ACLs or alternate streams.
                with open(str(output) + ":Zone.Identifier", "x", encoding="ascii", newline="") as zone:
                    zone.write("[ZoneTransfer]\r\nZoneId=3\r\n")
                with output.open("rb") as copied:
                    if hashlib.file_digest(copied, "sha256").hexdigest() != item["sha256"]:
                        raise SharedScanError("CONTENT_CHANGED", "destination verification failed")
            if _manifest(share) != manifest:
                raise SharedScanError("CONTENT_CHANGED", "Shared contents changed before publication")
            self._check_cancelled()
            stage.rename(target)   # Windows rename refuses an existing target; publish whole tree at once
            stage = None
            remove_source = True
            return result | {"status": "EXPORTED", "dest": str(target)}
        except Exception as exc:
            code = getattr(exc, "code", "SCAN_ERROR")
            result["scan"] = f"{code}: {exc}"
            blocked = code in {"MALWARE_DETECTED", "FILE_TOO_LARGE", "LIMIT_EXCEEDED", "LINK_REFUSED", "CONTENT_CHANGED"}
            return result | {"status": "BLOCKED" if blocked else "QUARANTINED"}
        finally:
            for handle in reversed(handles + dirs):
                winfile.close(handle)
            if stage is not None:
                try:
                    shutil.rmtree(stage)
                except OSError:
                    log.warning("Shared partial copy cleanup failed: %s", stage, exc_info=True)
            if remove_source:
                _remove(share)
                if share.exists():
                    result["events"].append({"kind": "SHARED_CLEANUP_PENDING", "path": str(share)})
