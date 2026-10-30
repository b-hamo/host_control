"""Per-job private storage under the quarantine root.

    <Quarantine>\\session-<session_id>\\job-<32 hex>\\payload.part   the received bytes
                                                   \\job.json       state record (for recovery logs)

Names come only from the validated session_id and a random job id the service made;
nothing the Guest sent (file name, path) ever becomes part of a Host path. A job
directory is created new for every job and never reused.

The quarantine root is created and locked down by the installer (SYSTEM, Administrators,
the service; no Users). This module adds the checks that do not rely on that ACL:
reparse points refused at every level, handles compared with their expected final
path, CREATE_NEW for every file, and a read lock without write sharing from upload
completion until the job's storage is deleted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from scanner_service import winfile
from scanner_service.models import JOB_RE, SESSION_RE, ScannerError

log = logging.getLogger("scanner.quarantine")

PAYLOAD = "payload.part"
META = "job.json"
META_MAX_BYTES = 16 * 1024
SESSION_PREFIX = "session-"
SELFTEST_PREFIX = "_selftest-"
VIRUS_ERRORS = (225, 226)          # ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED: an antivirus refused the file


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(eq=False)
class JobStorage:
    job_id: str
    session_id: str
    job_dir: Path
    payload_path: Path
    declared_size: int
    write_handle: object | None = None
    lock_handle: object | None = None
    file_id: winfile.FileId | None = None
    written: int = 0
    sha: "hashlib._Hash" = field(default_factory=hashlib.sha256)
    size: int | None = None
    sha256: str | None = None
    meta: dict = field(default_factory=dict)
    deleted: bool = False

    @property
    def finalized(self) -> bool:
        return self.lock_handle is not None


@dataclass
class CleanupReport:
    removed: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)


class QuarantineManager:
    def __init__(self, root: Path, *, max_file_bytes: int, store_limit_bytes: int, min_free_bytes: int,
                 max_jobs: int, create_root: bool = False):
        self.root = Path(root)
        self.max_file_bytes = max_file_bytes
        self.store_limit_bytes = store_limit_bytes
        self.min_free_bytes = min_free_bytes
        self.max_jobs = max_jobs
        self.create_root = create_root          # tests / debug only; the installer owns the real root
        self.root_final: str | None = None
        self.reserved = 0
        self._jobs: dict[str, JobStorage] = {}
        self._selftests: set[str] = set()       # self-test directories in use (cleanup leaves them)
        self._lock = threading.RLock()

    # -- root ----------------------------------------------------------------
    def ensure_root(self) -> None:
        """The root must exist as a real directory reached without any link."""
        if self.create_root and winfile.attributes(self.root) is None:
            self.root.mkdir(parents=True)
        winfile.check_plain_dir(self.root)
        final = winfile.dir_final_path(self.root)
        if not winfile.same_path(final, self.root.absolute()):
            raise OSError(f"quarantine root {self.root} resolves to {final}: a link in the path; refused")
        self.root_final = final
        log.info("quarantine root ready: %s", self.root)

    def _real(self, p: Path) -> Path:
        """Expected final path of an entry below the root."""
        return Path(self.root_final) / p.relative_to(self.root)

    # -- jobs ----------------------------------------------------------------
    def create_job(self, session_id: str, declared_size: int, meta: dict | None = None,
                   job_id: str | None = None) -> JobStorage:
        if self.root_final is None:
            raise ScannerError("SERVICE_UNAVAILABLE", "quarantine is not ready", retryable=True)
        if not SESSION_RE.fullmatch(session_id or ""):
            raise ScannerError("INVALID_ARGUMENT", "invalid session_id")
        job_id = job_id or "job-" + secrets.token_hex(16)
        if not JOB_RE.fullmatch(job_id):
            raise ScannerError("INVALID_ARGUMENT", "invalid job_id")
        if not 0 <= declared_size <= self.max_file_bytes:
            raise ScannerError("FILE_TOO_LARGE", f"size must be 0..{self.max_file_bytes} bytes")
        with self._lock:
            live = [s for s in self._jobs.values() if not s.deleted]
            if len(live) >= self.max_jobs:
                raise ScannerError("TOO_MANY_JOBS", f"{self.max_jobs} jobs are already in quarantine",
                                   retryable=True)
            if self.reserved + declared_size > self.store_limit_bytes:
                raise ScannerError("STORAGE_FULL", "quarantine storage limit reached", retryable=True)
            try:
                free = winfile.free_bytes(self.root)
            except OSError as e:
                raise ScannerError("STORAGE_ERROR", f"free space unknown ({e.strerror})") from None
            if free - declared_size < self.min_free_bytes:
                raise ScannerError("DISK_FULL", "not enough free disk space for quarantine", retryable=True)
            self.reserved += declared_size
        session_dir = self.root / (SESSION_PREFIX + session_id)
        job_dir = session_dir / job_id
        st = JobStorage(job_id, session_id, job_dir, job_dir / PAYLOAD, declared_size)
        made_dir = False
        try:
            try:
                winfile.make_new_dir(session_dir)
            except FileExistsError:
                pass
            winfile.check_plain_dir(session_dir)
            if not winfile.same_path(winfile.dir_final_path(session_dir), self._real(session_dir)):
                raise OSError("session directory is redirected; refused")
            winfile.make_new_dir(job_dir)                  # FileExistsError: never reuse a job directory
            made_dir = True
            winfile.check_plain_dir(job_dir)
            if not winfile.same_path(winfile.dir_final_path(job_dir), self._real(job_dir)):
                raise OSError("job directory is redirected; refused")
            st.meta = {"job_id": job_id, "session_id": session_id, "declared_size": declared_size,
                       "created_utc": _utc(), **(meta or {})}
            self._write_meta(st)
            st.write_handle = winfile.create_new(st.payload_path)
            if not winfile.same_path(winfile.final_path(st.write_handle), self._real(st.payload_path)):
                raise OSError("payload file is redirected; refused")
            fid = winfile.identity(st.write_handle)
            if fid.links != 1 or fid.attributes & winfile.FILE_ATTRIBUTE_REPARSE_POINT:
                raise OSError("payload file is linked; refused")
            st.file_id = fid
        except OSError as e:
            with self._lock:
                self.reserved -= declared_size
            winfile.close(st.write_handle)
            if made_dir:
                try:
                    self._delete_storage(st)
                except OSError:
                    pass                                  # an orphan now; the next cleanup retries
            log.error("JOB %s quarantine directory could not be created: %s", job_id, e)
            if isinstance(e, FileExistsError):
                raise ScannerError("JOB_EXISTS", "job directory already exists; refused") from None
            raise ScannerError("STORAGE_ERROR", "quarantine directory could not be created") from None
        with self._lock:
            self._jobs[job_id] = st
        log.info("JOB %s quarantine created (session %s, up to %d bytes)", job_id, session_id, declared_size)
        return st

    def get_job(self, job_id: str) -> JobStorage | None:
        with self._lock:
            return self._jobs.get(job_id)

    def write_chunk(self, st: JobStorage, offset: int, data: bytes) -> int:
        """Append one chunk. Only in order (offset == bytes so far), never past the declared size."""
        if st.write_handle is None or st.deleted:
            raise ScannerError("INVALID_STATE", "upload is not open")
        if offset != st.written:
            raise ScannerError("BAD_OFFSET", f"expected offset {st.written}, got {offset}")
        if st.written + len(data) > st.declared_size:
            raise ScannerError("SIZE_EXCEEDED", f"more than the declared {st.declared_size} bytes")
        try:
            winfile.write_all(st.write_handle, data)
        except OSError as e:
            raise ScannerError("STORAGE_ERROR", f"write failed ({e.strerror})") from None
        st.sha.update(data)
        st.written += len(data)
        return st.written

    def finalize_upload(self, st: JobStorage, expected_sha256: str) -> tuple[int, str]:
        """Close the upload and lock the file for reading. Size and SHA-256 must be what was declared.

        Raises ScannerError: SIZE_MISMATCH / HASH_MISMATCH (bytes wrong), MALWARE_DETECTED (real-time
        protection refused the file), CONTENT_REMOVED (gone or unreadable otherwise), CONTENT_CHANGED
        (another file).
        """
        if st.write_handle is None:
            raise ScannerError("INVALID_STATE", "upload is not open")
        if st.written != st.declared_size:
            raise ScannerError("SIZE_MISMATCH", f"received {st.written} of {st.declared_size} bytes")
        if st.sha.hexdigest() != expected_sha256:
            raise ScannerError("HASH_MISMATCH", "SHA-256 of the received bytes differs from the declared one")
        try:
            winfile.flush(st.write_handle)
            written_id = winfile.identity(st.write_handle)
        except OSError as e:
            raise ScannerError("STORAGE_ERROR", f"flush failed ({e.strerror})") from None
        finally:
            winfile.close(st.write_handle)
            st.write_handle = None
        try:
            lock = winfile.open_locked(st.payload_path)
        except OSError as e:
            if getattr(e, "winerror", None) in VIRUS_ERRORS:
                raise ScannerError("MALWARE_DETECTED", "Defender real-time protection blocked the received file "
                                   f"(winerror {e.winerror})") from None
            raise ScannerError("CONTENT_REMOVED", f"received file can no longer be opened (winerror "
                               f"{getattr(e, 'winerror', None)})") from None
        try:
            fid = winfile.identity(lock)
            if not fid.same_file(written_id) or fid.links != 1 or fid.attributes & winfile.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ScannerError("CONTENT_CHANGED", "received file was replaced after it was written")
            if not winfile.same_path(winfile.final_path(lock), self._real(st.payload_path)):
                raise ScannerError("CONTENT_CHANGED", "received file is redirected")
            size, sha = winfile.hash_handle(lock, self.max_file_bytes)
        except ScannerError:
            winfile.close(lock)
            raise
        except OSError as e:
            winfile.close(lock)
            raise ScannerError("CONTENT_REMOVED", f"received file can no longer be read ({e.strerror})") from None
        if (size, sha) != (st.declared_size, expected_sha256):
            winfile.close(lock)
            raise ScannerError("CONTENT_CHANGED", "received file changed after it was written")
        st.lock_handle, st.file_id, st.size, st.sha256 = lock, fid, size, sha
        return size, sha

    def verify_unchanged(self, st: JobStorage) -> str | None:
        """None if the locked file is still the received bytes at its place; else why not."""
        if st.lock_handle is None:
            return "file is not locked"
        if winfile.attributes(st.payload_path) is None:
            return "removed"
        try:
            probe = winfile.open_entry(st.payload_path)
        except OSError as e:
            return f"unreadable (winerror {getattr(e, 'winerror', None)})"
        try:
            if not winfile.identity(probe).same_file(st.file_id):
                return "replaced"
        finally:
            winfile.close(probe)
        try:
            size, sha = winfile.hash_handle(st.lock_handle, self.max_file_bytes)
        except OSError as e:
            return f"unreadable ({e.strerror})"
        if (size, sha) != (st.size, st.sha256):
            return "content changed"
        return None

    def read_payload(self, st: JobStorage) -> bytes:
        return winfile.read_all(st.lock_handle, self.max_file_bytes)

    def update_meta(self, st: JobStorage, **values) -> None:
        if st.deleted:
            return
        st.meta.update(values, updated_utc=_utc())
        try:
            self._write_meta(st)
        except OSError as e:
            log.warning("JOB %s state record not written: %s", st.job_id, e)

    def _write_meta(self, st: JobStorage) -> None:
        data = json.dumps(st.meta, ensure_ascii=True, sort_keys=True).encode()
        tmp = st.job_dir / (META + ".new")
        winfile.delete_file(tmp)
        h = winfile.create_new(tmp)
        try:
            winfile.write_all(h, data)
            winfile.flush(h)
        finally:
            winfile.close(h)
        winfile.replace_file(tmp, st.job_dir / META)

    def delete_job(self, st: JobStorage) -> None:
        """Close the handles and delete the job directory. Raises OSError; retry later."""
        winfile.close(st.write_handle)
        winfile.close(st.lock_handle)
        st.write_handle = st.lock_handle = None
        self._delete_storage(st)
        with self._lock:
            if not st.deleted:
                st.deleted = True
                self.reserved -= st.declared_size
                self._jobs.pop(st.job_id, None)

    def _delete_storage(self, st: JobStorage) -> None:
        self._delete_dir(st.job_dir)
        self._remove_if_empty(st.job_dir.parent)

    def _delete_dir(self, d: Path, depth: int = 0) -> None:
        """Delete a job directory without ever following a link out of it."""
        a = winfile.attributes(d)
        if a is None:
            return
        if a & winfile.FILE_ATTRIBUTE_REPARSE_POINT or not a & winfile.FILE_ATTRIBUTE_DIRECTORY:
            (winfile.remove_dir if a & winfile.FILE_ATTRIBUTE_DIRECTORY else winfile.delete_file)(d)
            return
        if depth > 2:
            raise OSError(f"{d}: unexpected nesting in quarantine")
        for entry in list(d.iterdir()):
            ea = winfile.attributes(entry)
            if ea is None:
                continue
            if ea & winfile.FILE_ATTRIBUTE_DIRECTORY and not ea & winfile.FILE_ATTRIBUTE_REPARSE_POINT:
                self._delete_dir(entry, depth + 1)
            elif ea & winfile.FILE_ATTRIBUTE_DIRECTORY:
                winfile.remove_dir(entry)                 # a directory link: remove the link only
            else:
                winfile.delete_file(entry)
        winfile.remove_dir(d)

    def _remove_if_empty(self, session_dir: Path) -> None:
        if session_dir == self.root:
            return
        try:
            if winfile.attributes(session_dir) is not None and not any(session_dir.iterdir()):
                winfile.remove_dir(session_dir)
        except OSError:
            pass                                          # another job of the session was just created

    # -- housekeeping --------------------------------------------------------
    def list_job_dirs(self) -> list[Path]:
        """Every job directory on disk (including ones from an earlier run)."""
        out = []
        if self.root_final is None or winfile.attributes(self.root) is None:
            return out
        for s in self.root.iterdir():
            if s.name.startswith(SESSION_PREFIX) and not winfile.is_reparse(s) and s.is_dir():
                out.extend(j for j in s.iterdir() if j.name.startswith("job-"))
        return out

    def read_meta(self, job_dir: Path) -> dict | None:
        """Best-effort read of a job's record (for logs only; never trusted to resume anything)."""
        p = job_dir / META
        try:
            if winfile.is_reparse(p) or p.stat().st_size > META_MAX_BYTES:
                return None
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def cleanup_expired_jobs(self, active_job_ids: set[str]) -> CleanupReport:
        """Delete every job directory no live job owns: leftovers of a crash, failed deletions,
        self-test directories. Called at start and on every sweep, so a failed delete is retried."""
        report = CleanupReport()
        if self.root_final is None or winfile.attributes(self.root) is None:
            return report
        for entry in list(self.root.iterdir()):
            name = entry.name
            try:
                if name.startswith(SELFTEST_PREFIX):
                    if name in self._selftests:
                        continue
                    self._delete_dir(entry)
                    report.removed.append(name)
                elif name.startswith(SESSION_PREFIX):
                    if winfile.is_reparse(entry):
                        winfile.remove_dir(entry)
                        report.removed.append(name)
                        continue
                    for job_dir in list(entry.iterdir()):
                        if job_dir.name in active_job_ids:
                            continue
                        self._delete_dir(job_dir)
                        report.removed.append(f"{name}/{job_dir.name}")
                        st = self._jobs.get(job_dir.name)
                        if st is not None:
                            with self._lock:
                                if not st.deleted:
                                    st.deleted = True
                                    self.reserved -= st.declared_size
                                    self._jobs.pop(st.job_id, None)
                    self._remove_if_empty(entry)
            except OSError as e:
                report.failed[name] = str(e)
        if report.removed:
            log.info("quarantine cleanup removed %d entr%s", len(report.removed),
                     "y" if len(report.removed) == 1 else "ies")
        for name, why in report.failed.items():
            log.warning("quarantine cleanup could not remove %s (retried later): %s", name, why)
        return report

    def new_selftest_dir(self) -> Path:
        d = self.root / (SELFTEST_PREFIX + secrets.token_hex(8))
        with self._lock:
            self._selftests.add(d.name)
        winfile.make_new_dir(d)
        winfile.check_plain_dir(d)
        return d

    def remove_selftest_dir(self, d: Path) -> None:
        try:
            for attempt in range(5):
                try:
                    self._delete_dir(d)
                    return
                except OSError:
                    time.sleep(0.2 * (attempt + 1))
        finally:
            with self._lock:
                self._selftests.discard(d.name)
        log.warning("self-test directory %s not removed yet (retried by cleanup)", d.name)
