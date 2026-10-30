"""Job lifecycle: upload → scan → (publish) → dispose, one independent job per request.

Rules enforced here:
- a state change happens only along models.TRANSITIONS (anything else: INVALID_STATE)
- one live job per (session, runtime, generation, artifact): a second one is DUPLICATE_JOB
- every request must name the job's exact identity; any mismatch looks like JOB_NOT_FOUND
- a newer generation of a runtime cancels the older generation's jobs; older ones are refused
- SCAN and PUBLISH run once per job; a failed scan, unknown verdict or error never publishes
- a job busy in a scan or publish thread is cancelled by that thread (cancel event), so the
  state it ends in is the one that really happened (e.g. EXPORTED if the rename already ran)
- finished jobs are disposed (quarantine deleted); a failed delete stays recorded and is
  retried by sweep(). Nothing survives a restart (recovery_manager discards it all).

The scanner never decides whether a user approved an export: PUBLISH needs an approval
the publisher accepts (artifact_publisher.HostAssertedApproval for now).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from host.artifact_scan import check_format          # the existing format policy (UTF-8 .txt), stdlib only
from scanner_service.artifact_publisher import ArtifactPublisher, PublishCancelled
from scanner_service.config import ScannerConfig
from scanner_service.models import (BLOCK_CODES, FINISHED, SHA256_RE, Identity, Job, JobState, ScannerError,
                                    ScanOutcome, Verdict, check_transition)
from scanner_service.quarantine_manager import QuarantineManager

log = logging.getLogger("scanner.jobs")
audit = logging.getLogger("scanner.audit")

S = JobState
FILE_NAME_MAX = 255
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


class ScanJobManager:
    def __init__(self, config: ScannerConfig, quarantine: QuarantineManager, scanner, publisher: ArtifactPublisher,
                 *, clock=time.monotonic):
        self.config = config
        self.quarantine = quarantine
        self.scanner = scanner
        self.publisher = publisher
        self.clock = clock
        self.accepting = True
        self._jobs: dict[str, Job] = {}
        self._generations: dict[tuple[str, str], int] = {}
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=config.max_concurrent_scans, thread_name_prefix="scan")

    # -- helpers -------------------------------------------------------------
    def _set(self, job: Job, to: JobState, *, code: str | None = None, message: str | None = None) -> None:
        """State change under the lock; terminal states record outcome, error and an audit line."""
        with self._lock:
            check_transition(job.job_id, job.state, to)
            job.state = to
            job.updated_at = self.clock()
            if to in (S.EXPORTED, S.BLOCKED, S.FAILED, S.CANCELLED):
                job.outcome = to
                job.finished_at = job.updated_at
                if code:
                    job.error = {"code": code, "message": message or code}
        st = self.quarantine.get_job(job.job_id)
        if st is not None:
            self.quarantine.update_meta(st, state=to.value)
        if to in (S.EXPORTED, S.BLOCKED, S.FAILED, S.CANCELLED):
            self._audit(job, "finished")
        log.info("JOB %s → %s%s", job.job_id, to.value, f" ({code}: {message})" if code else "")

    def _audit(self, job: Job, event: str) -> None:
        scan = job.scan
        audit.info("AUDIT %s", json.dumps({
            "event": event, "job_id": job.job_id, "session_id": job.identity.session_id,
            "runtime_id": job.identity.runtime_id, "generation": job.identity.generation,
            "artifact_id": job.identity.artifact_id, "state": job.state.value,
            "outcome": job.outcome.value if job.outcome else None, "size": job.size, "sha256": job.sha256,
            "scan_started": job.scan_started_utc, "scan_finished": job.scan_finished_utc,
            "defender_verdict": scan.verdict.value if scan else None,
            "defender_exit_code": scan.exit_code if scan else None,
            "malware_detected": (scan.verdict == Verdict.DETECTED) if scan else None,
            "threats": scan.threats if scan else None, "engine": scan.engine if scan else None,
            "error_code": (job.error or {}).get("code"), "cleanup_error": job.cleanup_error,
            "disposed": job.state == S.DISPOSED, "export_rel": job.export_rel,
        }, ensure_ascii=False))

    def _get(self, ident: Identity, job_id) -> Job:
        with self._lock:
            job = self._jobs.get(job_id) if isinstance(job_id, str) else None
        if job is None or job.identity != ident:
            raise ScannerError("JOB_NOT_FOUND", "no such job for this session, runtime, generation and artifact")
        return job

    def _dispose(self, job: Job) -> None:
        """Delete the job's quarantine. Only for finished jobs no thread is working on."""
        st = self.quarantine.get_job(job.job_id)
        try:
            if st is not None:
                with job.io_lock:
                    self.quarantine.delete_job(st)
        except OSError as e:
            job.cleanup_error = f"quarantine not deleted yet: {e}"
            log.warning("JOB %s %s (retried by cleanup)", job.job_id, job.cleanup_error)
            return
        job.cleanup_error = None
        if job.state != S.DISPOSED:
            self._set(job, S.DISPOSED)
            self._audit(job, "disposed")

    @staticmethod
    def _cancel_end(job: Job) -> tuple[JobState, str, str]:
        return S.CANCELLED, (job.error or {}).get("code", "CANCELLED"), job.cancel_reason or "cancelled"

    def _fail(self, job: Job, to: JobState, code: str, message: str) -> None:
        """End a job that no other thread owns, and dispose it."""
        with self._lock:
            if job.state in FINISHED:
                return
            self._set(job, to, code=code, message=message)
        self._dispose(job)

    # -- upload --------------------------------------------------------------
    def begin_upload(self, ident: Identity, payload: dict) -> Job:
        if not self.accepting:
            raise ScannerError("SERVICE_STOPPING", "the service is stopping; no new jobs", retryable=True)
        name, size, sha = payload.get("file_name"), payload.get("size"), payload.get("sha256")
        if not isinstance(name, str) or not 1 <= len(name) <= FILE_NAME_MAX or _CONTROL.search(name):
            raise ScannerError("INVALID_ARGUMENT", f"file_name must be 1..{FILE_NAME_MAX} printable characters")
        if type(size) is not int or size < 0:
            raise ScannerError("INVALID_ARGUMENT", "size must be a non-negative integer")
        if size > self.config.max_file_bytes:
            raise ScannerError("FILE_TOO_LARGE", f"more than {self.config.max_file_bytes} bytes")
        if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
            raise ScannerError("INVALID_ARGUMENT", "sha256 must be 64 lower-case hex characters")
        key = (ident.session_id, ident.runtime_id)
        stale: list[Job] = []
        with self._lock:
            current = self._generations.get(key)
            if current is not None and ident.generation < current:
                raise ScannerError("STALE_GENERATION", f"generation {ident.generation} was replaced by {current}")
            if current is None or ident.generation > current:
                self._generations[key] = ident.generation
                stale = [j for j in self._jobs.values() if (j.identity.session_id, j.identity.runtime_id) == key
                         and j.identity.generation < ident.generation and j.state not in FINISHED]
            if any(j.identity == ident and j.state not in FINISHED for j in self._jobs.values()):
                raise ScannerError("DUPLICATE_JOB", "a job for this artifact is already in progress")
        for j in stale:
            self._cancel(j, "RUNTIME_REPLACED", f"runtime generation {ident.generation} replaced it")
        st = self.quarantine.create_job(ident.session_id, size, meta={
            "runtime_id": ident.runtime_id, "generation": ident.generation, "artifact_id": ident.artifact_id,
            "sha256": sha, "state": S.CREATED.value})
        now = self.clock()
        job = Job(st.job_id, ident, name, size, sha, now, _utc(), updated_at=now,
                  created_dt=datetime.now(timezone.utc))
        refuse = None
        with self._lock:                             # the checks again: another request may have won meanwhile
            if not self.accepting:
                refuse = ScannerError("SERVICE_STOPPING", "the service is stopping; no new jobs", retryable=True)
            elif any(j.identity == ident and j.state not in FINISHED for j in self._jobs.values()):
                refuse = ScannerError("DUPLICATE_JOB", "a job for this artifact is already in progress")
            else:
                self._jobs[job.job_id] = job
        if refuse is not None:
            try:
                self.quarantine.delete_job(st)
            except OSError:
                pass                                 # an orphan directory; sweep() removes it
            raise refuse
        log.info("JOB %s created: %s size=%d sha256=%s…", job.job_id, ident.log_fields(), size, sha[:12])
        self._audit(job, "created")
        return job

    def write_chunk(self, ident: Identity, job_id, offset, data: bytes) -> Job:
        job = self._get(ident, job_id)
        if type(offset) is not int or offset < 0:
            raise ScannerError("INVALID_ARGUMENT", "offset must be a non-negative integer")
        if len(data) > self.config.max_chunk_bytes:
            raise ScannerError("CHUNK_TOO_LARGE", f"chunks are at most {self.config.max_chunk_bytes} bytes")
        with job.io_lock:
            with self._lock:
                if job.state == S.CREATED:
                    self._set(job, S.RECEIVING)
                elif job.state != S.RECEIVING:
                    raise ScannerError("INVALID_STATE", f"job is {job.state.value}; no more data accepted")
            st = self.quarantine.get_job(job.job_id)
            try:
                job.received = self.quarantine.write_chunk(st, offset, data)
                job.updated_at = self.clock()
                return job
            except ScannerError as e:
                if e.code == "BAD_OFFSET":
                    raise                            # the client may resend from the right offset
                fatal = e
        self._fail(job, S.FAILED, fatal.code, fatal.message)
        raise fatal

    def complete_upload(self, ident: Identity, job_id) -> Job:
        job = self._get(ident, job_id)
        with job.io_lock:
            with self._lock:
                if job.state == S.CREATED:
                    self._set(job, S.RECEIVING)
                elif job.state != S.RECEIVING:
                    raise ScannerError("INVALID_STATE", f"job is {job.state.value}")
            st = self.quarantine.get_job(job.job_id)
            try:
                size, sha = self.quarantine.finalize_upload(st, job.declared_sha256)
            except ScannerError as e:
                err = e
            else:
                job.size, job.sha256 = size, sha
                self._set(job, S.RECEIVED)
                log.info("JOB %s received %d bytes sha256=%s…", job.job_id, size, sha[:12])
                return job
        # wrong bytes: the upload failed; bytes gone or swapped after writing: blocked
        to = S.BLOCKED if err.code in ("MALWARE_DETECTED", "CONTENT_REMOVED", "CONTENT_CHANGED") else S.FAILED
        if err.code == "CONTENT_REMOVED":
            found = self._detections(job, st)
            if found:                                # real-time protection took it as soon as it was closed
                err = ScannerError("MALWARE_DETECTED", "Defender real-time protection removed the file: "
                                   + ", ".join(found))
        self._fail(job, to, err.code, err.message)
        raise err

    def _detections(self, job: Job, st) -> list[str]:
        query = getattr(self.scanner, "detections_since", None)
        if query is None or st is None:
            return []
        try:
            return query(st.payload_path, job.created_dt) or []
        except Exception:  # noqa: BLE001 - no evidence then
            return []

    # -- scan ----------------------------------------------------------------
    def start_scan(self, ident: Identity, job_id) -> Job:
        job = self._get(ident, job_id)
        with self._lock:
            if not self.accepting:
                raise ScannerError("SERVICE_STOPPING", "the service is stopping", retryable=True)
            if job.state != S.RECEIVED:
                raise ScannerError("INVALID_STATE", f"job is {job.state.value}; only RECEIVED jobs are scanned")
            self._set(job, S.SCANNING)
            job.busy = True
            job.scan_started_utc = _utc()
        try:
            self._pool.submit(self._scan_job, job)
        except RuntimeError:                         # pool shut down meanwhile
            job.busy = False
            self._fail(job, S.CANCELLED, "SERVICE_STOPPING", "the service is stopping")
            raise ScannerError("SERVICE_STOPPING", "the service is stopping", retryable=True) from None
        return job

    def _scan_job(self, job: Job) -> None:
        end: tuple[JobState, str | None, str | None] = (S.BLOCKED, "SCAN_ERROR", "scan did not finish")
        try:
            end = self._scan_steps(job)
        except Exception as e:  # noqa: BLE001 - an unexpected error is a failed scan, never a pass
            log.exception("JOB %s scan crashed", job.job_id)
            end = (S.BLOCKED, "SCAN_ERROR", f"{type(e).__name__}")
        finally:
            job.scan_finished_utc = _utc()
            to, code, message = end
            if job.cancel.is_set():
                to, code, message = self._cancel_end(job)
            with self._lock:
                job.busy = False
                if job.state == S.SCANNING:
                    self._set(job, to, code=code, message=message)
            if job.state != S.SCANNED:
                self._dispose(job)

    def _scan_steps(self, job: Job) -> tuple[JobState, str | None, str | None]:
        st = self.quarantine.get_job(job.job_id)
        data = self.quarantine.read_payload(st)
        if hashlib.sha256(data).hexdigest() != job.sha256:
            return S.BLOCKED, "CONTENT_CHANGED", "quarantined file changed before the scan"
        bad = check_format(job.file_name, data)
        del data
        if bad is not None:
            job.scan = ScanOutcome(Verdict.ERROR, bad.detail, engine="format-policy")
            return S.BLOCKED, bad.code, bad.detail
        if job.cancel.is_set():
            return self._cancel_end(job)
        outcome = self.scanner.scan_file(st.payload_path, job.cancel)
        job.scan = outcome
        log.info("JOB %s Defender: %s (%s) exit=%s %.1fs", job.job_id, outcome.verdict.value, outcome.detail,
                 outcome.exit_code, outcome.duration_s or 0.0)
        if outcome.verdict == Verdict.CANCELLED or job.cancel.is_set():
            return self._cancel_end(job)
        if outcome.verdict != Verdict.CLEAN:
            return S.BLOCKED, BLOCK_CODES[outcome.verdict], outcome.detail
        why = self.quarantine.verify_unchanged(st)
        if why is not None:
            return S.BLOCKED, "CONTENT_CHANGED", f"quarantined file {why} after the scan"
        return S.SCANNED, None, None

    # -- publish -------------------------------------------------------------
    def publish(self, ident: Identity, job_id, approval) -> Job:
        job = self._get(ident, job_id)
        with self._lock:
            if job.published or job.state in (S.PUBLISHING, S.EXPORTED) or job.outcome == S.EXPORTED:
                raise ScannerError("ALREADY_PUBLISHED", "this job was already published")
            if job.state != S.SCANNED:
                raise ScannerError("INVALID_STATE", f"job is {job.state.value}; only SCANNED jobs are published")
            if not self.accepting:
                raise ScannerError("SERVICE_STOPPING", "the service is stopping", retryable=True)
        approval_id = self.publisher.check(job, approval)          # refusal leaves the job SCANNED
        with self._lock:
            if job.state != S.SCANNED or job.published:
                raise ScannerError("INVALID_STATE", f"job is {job.state.value}")
            self._set(job, S.PUBLISHING)
            job.busy = True
            job.published = True                                    # one attempt only, success or not
        end: tuple[JobState, str | None, str | None] = (S.FAILED, "PUBLISH_FAILED", "publish did not finish")
        try:
            st = self.quarantine.get_job(job.job_id)
            why = self.quarantine.verify_unchanged(st)
            if why is not None:
                end = (S.BLOCKED, "CONTENT_CHANGED", f"quarantined file {why} before publishing")
            elif job.cancel.is_set():
                end = self._cancel_end(job)
            else:
                path, rel = self.publisher.publish(job, st, job.cancel)
                job.export_path, job.export_rel = path, rel
                end = (S.EXPORTED, None, None)
        except PublishCancelled:
            end = self._cancel_end(job)
        except ScannerError as e:
            end = (S.BLOCKED if e.code == "CONTENT_CHANGED" else S.FAILED, e.code, e.message)
        except Exception as e:  # noqa: BLE001
            log.exception("JOB %s publish crashed", job.job_id)
            end = (S.FAILED, "PUBLISH_FAILED", type(e).__name__)
        finally:
            to, code, message = end
            with self._lock:
                job.busy = False
                self._set(job, to, code=code, message=message)
            if to == S.EXPORTED:
                log.info("JOB %s EXPORTED as %s (approval %s)", job.job_id, job.export_rel, approval_id)
            self._dispose(job)
        if to != S.EXPORTED:
            raise ScannerError(code, message)
        return job

    # -- status / cancel -----------------------------------------------------
    def status(self, ident: Identity, job_id) -> Job:
        return self._get(ident, job_id)

    def abort(self, ident: Identity, job_id, reason: str = "aborted by the Host") -> Job:
        job = self._get(ident, job_id)
        self._cancel(job, "ABORTED", reason)
        return job

    def abort_session(self, session_id: str, reason: str = "session ended") -> int:
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.identity.session_id == session_id and j.state not in FINISHED]
        for j in jobs:
            self._cancel(j, "SESSION_ENDED", reason)
        return len(jobs)

    def _cancel(self, job: Job, code: str, reason: str) -> None:
        with self._lock:
            if job.state in FINISHED:
                return
            job.cancel_reason = reason
            if job.error is None:
                job.error = {"code": code, "message": reason}
            job.cancel.set()
            if job.busy:
                log.info("JOB %s cancel requested (%s); the running %s step ends it", job.job_id, reason,
                         job.state.value)
                return
        with job.io_lock:                            # wait for a chunk write in progress
            with self._lock:
                if job.state in FINISHED:
                    return
                self._set(job, S.CANCELLED, code=code, message=reason)
        self._dispose(job)

    # -- housekeeping --------------------------------------------------------
    def sweep(self) -> None:
        """Expire idle or old jobs, retry failed deletions, forget old records, remove orphans."""
        now = self.clock()
        with self._lock:
            jobs = list(self._jobs.values())
        for j in jobs:
            if j.state in (S.CREATED, S.RECEIVING) and now - j.updated_at > self.config.upload_idle_timeout_s:
                self._cancel(j, "UPLOAD_TIMEOUT", "no upload data within the idle timeout")
            elif j.state not in FINISHED and now - j.created_at > self.config.job_ttl_s:
                self._cancel(j, "JOB_EXPIRED", "job exceeded its lifetime")
            elif j.state in FINISHED and j.state != S.DISPOSED and not j.busy:
                self._dispose(j)
        with self._lock:
            for j in list(self._jobs.values()):
                if j.state == S.DISPOSED and j.finished_at is not None \
                        and now - j.finished_at > self.config.final_retention_s:
                    del self._jobs[j.job_id]
            active = {j.job_id for j in self._jobs.values() if j.state != S.DISPOSED}
        self.quarantine.cleanup_expired_jobs(active)

    def counts(self) -> dict:
        with self._lock:
            out: dict[str, int] = {}
            for j in self._jobs.values():
                out[j.state.value] = out.get(j.state.value, 0) + 1
            return out

    def shutdown(self, timeout_s: float = 20.0) -> None:
        """Stop accepting, cancel everything unfinished, wait (bounded) for running steps."""
        self.accepting = False
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.state not in FINISHED]
        for j in jobs:
            self._cancel(j, "SERVICE_STOPPING", "the service is stopping")
        self._pool.shutdown(wait=False, cancel_futures=True)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                if not any(j.busy for j in self._jobs.values()):
                    break
            time.sleep(0.1)
        with self._lock:
            left = [j.job_id for j in self._jobs.values() if j.busy]
        if left:
            log.warning("stopping with %d job step(s) still running: %s (their quarantine is removed at next "
                        "start)", len(left), ", ".join(left))
        for j in list(self._jobs.values()):
            if j.state in FINISHED and j.state != S.DISPOSED and not j.busy:
                self._dispose(j)
