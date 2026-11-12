"""Publishing a scanned file into the export root, only on a valid approval.

    <export_root>\\<session_id>\\<artifact_id>\\<safe file name>

Conditions (all checked here or by the job manager just before):
upload complete with the declared size and SHA-256, Defender verdict CLEAN, format policy
passed, job SCANNED and never published, the quarantined bytes unchanged, and an
approval that names exactly this job, artifact, session and SHA-256.

The copy is made from the service's locked quarantine handle into a new hidden
`.<job_id>.partial` file in the destination directory, hashed again through its own
handle, and only then renamed to the final name (never replacing anything). Nothing
appears under the final name before the bytes were verified, and nothing that was not
scanned is ever written to the export root. Every directory on the way must be a real
directory whose final path stays inside the export root.

Approval: the service does not decide on its own whether a user approved an export.
Until the Artifact Broker integration, HostAssertedApproval accepts the Host's statement
(the pipe is limited to the Host user, SYSTEM and Administrators) but binds it to the
job, artifact, session and SHA-256, so an approval can never be applied to other bytes.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from pathlib import Path, PureWindowsPath

from scanner_service import winfile
from scanner_service.models import Job, ScannerError
from scanner_service.quarantine_manager import JobStorage

log = logging.getLogger("scanner.publish")

APPROVAL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
APPROVAL_KEYS = {"approved", "approval_id", "approved_by", "job_id", "artifact_id", "session_id", "sha256"}
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_name(relative_path: str) -> str:
    """Same rule as host/artifacts.py _safe_name: the Guest's file name, never a Host path."""
    name = PureWindowsPath(relative_path).name
    name = "".join(ch if ch.isprintable() and ch not in '\\/:*?"<>|' else "_" for ch in name).strip(" .")
    if not name or name.split(".")[0].upper() in _RESERVED:
        name = "_" + (name or "artifact")
    return name[:200]


class HostAssertedApproval:
    mode = "host_asserted"

    def verify(self, job: Job, approval) -> str:
        if not isinstance(approval, dict):
            raise ScannerError("APPROVAL_INVALID", "approval must be an object")
        unknown = set(approval) - APPROVAL_KEYS
        if unknown:
            raise ScannerError("APPROVAL_INVALID", f"unknown approval field(s): {', '.join(sorted(unknown))}")
        if approval.get("approved") is not True:
            raise ScannerError("APPROVAL_DENIED", "export was not approved")
        aid = approval.get("approval_id")
        if not isinstance(aid, str) or not APPROVAL_ID_RE.fullmatch(aid):
            raise ScannerError("APPROVAL_INVALID", "approval_id missing or malformed")
        by = approval.get("approved_by")
        if not isinstance(by, str) or not 1 <= len(by) <= 64 or not by.isprintable():
            raise ScannerError("APPROVAL_INVALID", "approved_by missing or malformed")
        expected = {"job_id": job.job_id, "artifact_id": job.identity.artifact_id,
                    "session_id": job.identity.session_id, "sha256": job.sha256}
        wrong = [k for k, v in expected.items() if approval.get(k) != v]
        if wrong:
            raise ScannerError("APPROVAL_MISMATCH", f"approval does not match this job ({', '.join(wrong)})")
        return aid


class NoApproval:
    mode = "disabled"

    def verify(self, job: Job, approval) -> str:
        raise ScannerError("PUBLISH_DISABLED", "publishing is disabled by configuration")


class PublishCancelled(Exception):
    pass


class ArtifactPublisher:
    def __init__(self, export_root: Path | None, approval, *, max_file_bytes: int):
        self.export_root = Path(export_root) if export_root else None
        self.approval = approval
        self.max_file_bytes = max_file_bytes
        self.root_final: str | None = None
        self.problem: str | None = "no export_root configured" if export_root is None else None

    def ensure_root(self) -> None:
        """Check the export root once at start. A bad root disables publishing, not the service."""
        if self.export_root is None:
            return
        try:
            winfile.check_plain_dir(self.export_root)
            final = winfile.dir_final_path(self.export_root)
        except OSError as e:
            self.problem = f"export root unusable: {e}"
            log.error("PUBLISH disabled: %s", self.problem)
            return
        self.root_final, self.problem = final, None
        log.info("export root ready")

    @property
    def enabled(self) -> bool:
        return self.root_final is not None and self.approval.mode != "disabled"

    def check(self, job: Job, approval) -> str:
        """Before anything moves: the approval and the export root. Returns the approval id."""
        if self.approval.mode == "disabled":
            raise ScannerError("PUBLISH_DISABLED", "publishing is disabled by configuration")
        if not self.enabled:
            raise ScannerError("PUBLISH_DISABLED", self.problem or "export root not ready")
        return self.approval.verify(job, approval)

    def _real_dir(self, d: Path) -> None:
        try:
            winfile.make_new_dir(d)
        except FileExistsError:
            pass
        winfile.check_plain_dir(d)
        final = winfile.dir_final_path(d)
        if not winfile.is_within(final, self.root_final):
            raise OSError(f"{d.name} leads outside the export root")

    def publish(self, job: Job, st: JobStorage, cancel: threading.Event) -> tuple[str, str]:
        """Copy the locked, scanned bytes to the export root. Returns (full path, path below the root).

        Raises ScannerError (PUBLISH_CONFLICT / PUBLISH_FAILED / CONTENT_CHANGED) or PublishCancelled.
        """
        if st.lock_handle is None:
            raise ScannerError("CONTENT_CHANGED", "quarantined file is not locked")
        session_dir = self.export_root / job.identity.session_id
        dest_dir = session_dir / job.identity.artifact_id
        name = safe_name(job.file_name)
        dest = dest_dir / name
        tmp = dest_dir / f".{job.job_id}.partial"
        try:
            self._real_dir(session_dir)
            self._real_dir(dest_dir)
        except OSError as e:
            raise ScannerError("PUBLISH_FAILED", f"export directory: {e}") from None
        if winfile.attributes(dest) is not None:
            raise ScannerError("PUBLISH_CONFLICT", "a file with this name was already exported for the artifact")
        try:
            out = winfile.create_new(tmp)
        except OSError as e:
            raise ScannerError("PUBLISH_FAILED", f"export file not created ({e.strerror})") from None
        done = renamed = False
        check = None
        try:
            sha, n = hashlib.sha256(), 0
            try:
                for block in winfile.read_blocks(st.lock_handle, self.max_file_bytes):
                    winfile.write_all(out, block)
                    sha.update(block)
                    n += len(block)
                winfile.flush(out)
            finally:
                winfile.close(out)
            if (n, sha.hexdigest()) != (st.size, st.sha256):
                raise ScannerError("CONTENT_CHANGED", "quarantined file changed while it was copied")
            check = winfile.open_locked(tmp)        # what is on disk now, locked against writers
            if not winfile.is_within(winfile.final_path(check), self.root_final):
                raise ScannerError("PUBLISH_FAILED", "export file left the export root")
            if winfile.hash_handle(check, self.max_file_bytes) != (st.size, st.sha256):
                raise ScannerError("CONTENT_CHANGED", "export copy differs from the scanned bytes")
            if cancel.is_set():
                raise PublishCancelled()
            try:
                winfile.move_no_replace(tmp, dest)
            except OSError as e:
                if isinstance(e, FileExistsError):
                    raise ScannerError("PUBLISH_CONFLICT", "a file with this name appeared meanwhile") from None
                raise ScannerError("PUBLISH_FAILED", f"rename failed ({e.strerror})") from None
            renamed = True
            final = winfile.final_path(check)
            if not winfile.same_path(final, Path(self.root_final) / dest.relative_to(self.export_root)):
                raise ScannerError("PUBLISH_FAILED", "published file is not where it was expected")
            done = True
        except OSError as e:
            raise ScannerError("PUBLISH_FAILED", f"export copy failed ({e.strerror})") from None
        finally:
            winfile.close(check)
            if not done:
                try:
                    if not renamed:
                        winfile.delete_file(tmp)
                    elif self._is_ours(dest, st):
                        winfile.delete_file(dest)
                except OSError as e:
                    log.warning("JOB %s partial export not removed: %s", job.job_id, e)
        rel = str(dest.relative_to(self.export_root))
        return str(dest), rel

    def _is_ours(self, path: Path, st: JobStorage) -> bool:
        """Only remove a final-name file if it holds exactly the job's bytes (we just renamed it)."""
        try:
            h = winfile.open_locked(path)
        except OSError:
            return False
        try:
            return winfile.hash_handle(h, self.max_file_bytes) == (st.size, st.sha256)
        except OSError:
            return False
        finally:
            winfile.close(h)
