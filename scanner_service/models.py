"""Job states, transitions and the values passed between the scanner's parts.

    CREATED → RECEIVING → RECEIVED → SCANNING → SCANNED → PUBLISHING → EXPORTED → DISPOSED
       any non-final state ─▶ BLOCKED (verdict says no) / FAILED (operation broke) / CANCELLED
       BLOCKED / FAILED / CANCELLED ─▶ DISPOSED (quarantine bytes deleted)

SCANNED means "scanned and nothing found"; any negative or unknown verdict is BLOCKED.
DISPOSED is about storage only; `outcome` keeps how the job ended.
"""

from __future__ import annotations

import enum
import re
import threading
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = "scanner-ipc-v1"


class JobState(str, enum.Enum):
    CREATED = "CREATED"
    RECEIVING = "RECEIVING"
    RECEIVED = "RECEIVED"
    SCANNING = "SCANNING"
    SCANNED = "SCANNED"
    PUBLISHING = "PUBLISHING"
    EXPORTED = "EXPORTED"
    DISPOSED = "DISPOSED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


S = JobState
_ERRORS = (S.BLOCKED, S.FAILED, S.CANCELLED)
TRANSITIONS: dict[JobState, tuple[JobState, ...]] = {
    S.CREATED: (S.RECEIVING, *_ERRORS),
    S.RECEIVING: (S.RECEIVED, *_ERRORS),
    S.RECEIVED: (S.SCANNING, *_ERRORS),
    S.SCANNING: (S.SCANNED, *_ERRORS),
    S.SCANNED: (S.PUBLISHING, *_ERRORS),
    S.PUBLISHING: (S.EXPORTED, *_ERRORS),
    S.EXPORTED: (S.DISPOSED,),
    S.BLOCKED: (S.DISPOSED,),
    S.FAILED: (S.DISPOSED,),
    S.CANCELLED: (S.DISPOSED,),
    S.DISPOSED: (),
}
# The job's work is over (nothing more will be accepted for it); storage may still be pending deletion.
FINISHED = (S.EXPORTED, S.BLOCKED, S.FAILED, S.CANCELLED, S.DISPOSED)


class ScannerError(Exception):
    """A request the service refuses. `code` goes back over IPC as is."""

    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.retryable = code, message, retryable


class InvalidTransition(ScannerError):
    def __init__(self, job_id: str, frm: JobState, to: JobState):
        super().__init__("INVALID_STATE", f"{job_id}: {frm.value} cannot become {to.value}")


def check_transition(job_id: str, frm: JobState, to: JobState) -> None:
    if to not in TRANSITIONS[frm]:
        raise InvalidTransition(job_id, frm, to)


# ----------------------------------------------------------------------------- identifiers
SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
RUNTIME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
ARTIFACT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
JOB_RE = re.compile(r"job-[0-9a-f]{32}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAX_GENERATION = 2**31 - 1


@dataclass(frozen=True)
class Identity:
    """Who a job belongs to. Every request on a job must name exactly this."""
    session_id: str
    runtime_id: str
    generation: int
    artifact_id: str

    def log_fields(self) -> str:
        return (f"session={self.session_id} runtime={self.runtime_id} gen={self.generation} "
                f"artifact={self.artifact_id}")


def validate_identity(session_id: Any, runtime_id: Any, generation: Any, artifact_id: Any) -> Identity:
    def ok(value, rx):
        return isinstance(value, str) and rx.fullmatch(value) is not None
    if not ok(session_id, SESSION_RE):
        raise ScannerError("INVALID_ARGUMENT", "session_id must match " + SESSION_RE.pattern)
    if not ok(runtime_id, RUNTIME_RE):
        raise ScannerError("INVALID_ARGUMENT", "runtime_id must match " + RUNTIME_RE.pattern)
    if type(generation) is not int or not 1 <= generation <= MAX_GENERATION:
        raise ScannerError("INVALID_ARGUMENT", "generation must be an integer 1..2^31-1")
    if not ok(artifact_id, ARTIFACT_RE) or artifact_id.strip(".") != artifact_id:
        raise ScannerError("INVALID_ARGUMENT", "artifact_id must match " + ARTIFACT_RE.pattern)
    return Identity(session_id, runtime_id, generation, artifact_id)


# ----------------------------------------------------------------------------- verdicts
class Verdict(str, enum.Enum):
    CLEAN = "CLEAN"                  # Defender ran, nothing found, and the evidence agrees
    DETECTED = "DETECTED"            # a threat was reported, or Defender removed the file
    ERROR = "ERROR"                  # MpCmdRun failed
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"      # Defender off, untrusted MpCmdRun, self-test failed
    UNVERIFIABLE = "UNVERIFIABLE"    # ran, but the result cannot be confirmed (e.g. no detection log)
    CANCELLED = "CANCELLED"


# Verdict → the code the job is BLOCKED with (CLEAN passes; CANCELLED cancels the job).
BLOCK_CODES = {Verdict.DETECTED: "MALWARE_DETECTED", Verdict.ERROR: "SCAN_ERROR", Verdict.TIMEOUT: "SCAN_TIMEOUT",
               Verdict.UNAVAILABLE: "SCANNER_UNAVAILABLE", Verdict.UNVERIFIABLE: "SCAN_UNVERIFIABLE"}


@dataclass
class ScanOutcome:
    verdict: Verdict
    detail: str
    engine: str = "defender"
    exit_code: int | None = None
    duration_s: float | None = None
    threats: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)       # what the verdict was based on (for audit)

    def view(self) -> dict:
        return {"verdict": self.verdict.value, "detail": self.detail, "engine": self.engine,
                "exit_code": self.exit_code, "duration_s": None if self.duration_s is None else round(self.duration_s, 3),
                "threats": list(self.threats), "evidence": dict(self.evidence)}


@dataclass(eq=False)
class Job:
    job_id: str
    identity: Identity
    file_name: str                  # display / format policy only, never a Host path
    declared_size: int
    declared_sha256: str
    created_at: float               # monotonic
    created_utc: str
    state: JobState = JobState.CREATED
    outcome: JobState | None = None
    updated_at: float = 0.0         # monotonic, last activity
    finished_at: float | None = None
    created_dt: datetime | None = None
    scan_started_utc: str | None = None
    scan_finished_utc: str | None = None
    received: int = 0
    size: int | None = None
    sha256: str | None = None
    scan: ScanOutcome | None = None
    error: dict | None = None       # {"code", "message"} for BLOCKED / FAILED / CANCELLED
    cleanup_error: str | None = None
    export_rel: str | None = None   # path below the export root, set only when EXPORTED
    export_path: str | None = None
    published: bool = False
    cancel_reason: str | None = None
    busy: bool = False              # a scan or publish thread owns the storage right now
    cancel: threading.Event = field(default_factory=threading.Event)
    io_lock: threading.Lock = field(default_factory=threading.Lock)

    def view(self) -> dict:
        return {
            "job_id": self.job_id,
            "session_id": self.identity.session_id,
            "runtime_id": self.identity.runtime_id,
            "generation": self.identity.generation,
            "artifact_id": self.identity.artifact_id,
            "file_name": self.file_name,
            "state": self.state.value,
            "outcome": self.outcome.value if self.outcome else None,
            "declared_size": self.declared_size,
            "received_bytes": self.received,
            "size": self.size,
            "sha256": self.sha256,
            "scan": self.scan.view() if self.scan else None,
            "error": self.error,
            "cleanup_error": self.cleanup_error,
            "export_path": self.export_path if self.outcome == JobState.EXPORTED else None,
            "created_at": self.created_utc,
            "scan_started_at": self.scan_started_utc,
            "scan_finished_at": self.scan_finished_utc,
            "cancel_requested": self.cancel.is_set() and self.state not in FINISHED,
        }
