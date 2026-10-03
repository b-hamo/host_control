"""Artifact export, Host side of artifact-export-v1 (Runner contract, sandbox_runner 3270091).

    Runner ──Telemetry WSS── SECURITY_EVENT (candidate) ──▶ ArtifactBroker.store ──▶ artifact_id
    Agent ── artifact_export ──▶ Broker: READY, policy REQUIRE_APPROVAL, user approval
          ──▶ ArtifactBroker.export: new grant (upload_id, token, deadline, max_bytes) FIRST,
                                      then ARTIFACT_REQUEST on the Control connection
    Runner ──HTTPS PUT /scrp/v1/artifacts/<upload_id> (Bearer token)──▶ ArtifactGrants.receive
                                      (private temp file, size + SHA-256 fixed, empty 201)
    Runner ──ARTIFACT_RESULT──▶ matched with the receiver's record (candidate, upload_id, bytes)
          ──▶ inspection (format + antivirus, artifact_scan.py) on the same bytes
          ──▶ publish: move into the export folder, EXPORTED, path given to the Agent

Neither the HTTP 201 nor the Runner's result alone starts inspection, and only
bytes that passed inspection are published. A grant is single use; any failure
after it is claimed discards the partial file. Session end, a new Runtime
generation or a lost Telemetry channel cancel everything not yet exported.

Internal stages (contract §10):
    CANDIDATE → AUTHORIZED → RECEIVING → RECEIVED → SCANNING → EXPORTED
                                             failed / cancelled → FAILED / CANCELLED / BLOCKED
shown to the Agent with the existing artifact_list statuses (contract §11).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from host.artifact_scan import Verdict, inspect
from host.observation_store import UploadError
from scrp.validate import ARTIFACT_EXPORT_V1, ProtocolError

if TYPE_CHECKING:
    from host.connection import Connection
    from host.runtime_session import RuntimeSession

log = logging.getLogger("host-artifacts")

ARTIFACT_CAPABILITY = "artifact.export.v1"
ARTIFACT_UPLOAD_PATH = "/scrp/v1/artifacts/"
TELEMETRY_PATH = "/scrp/v1/telemetry"
TELEMETRY_MAX_EVENT_BYTES = 16384
UPLOAD_LIFETIME_S = 120.0          # contract §7 example default
RESULT_GRACE_S = 10.0              # §10: result after the upload deadline
DEFAULT_MAX_BYTES = 1024 * 1024    # demo policy: one small text file (contract allows up to 50 MiB)
MAX_BYTES_LIMIT = 52_428_800
STORE_LIMIT_BYTES = 200 * 1024 * 1024
MAX_CANDIDATES = 4096
TELEMETRY_WAIT_S = 10.0            # Startup Verification: Telemetry channel must be up by then
CHUNK = 64 * 1024

Identity = tuple[str, str, int]


def _utc_in(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii", "replace")).digest()


def _short(upload_id: str) -> str:
    return upload_id[:6] + "…"


# ----------------------------------------------------------------------------- upload grants
ISSUED, CLAIMED, RECEIVED, G_FAILED, G_CANCELLED, G_EXPIRED = (
    "ISSUED", "CLAIMED", "RECEIVED", "FAILED", "CANCELLED", "EXPIRED")


@dataclass(eq=False)
class Grant:
    upload_id: str
    token_digest: bytes = field(repr=False)
    identity: Identity
    artifact_id: str
    event_id: str
    max_bytes: int
    deadline: float                     # monotonic
    deadline_utc: str
    state: str = ISSUED
    path: Path | None = None
    size: int | None = None
    sha256: str | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)   # receiving finished (either way)


class ArtifactGrants:
    """Upload authority for artifact PUTs. Shared by the HTTPS receiver and the ArtifactBroker.

    upload_id is public; the token proves the right to use it. Every check that could
    tell an attacker something happens only after the token matched.
    """

    def __init__(self, incoming_dir: Path, store_limit: int = STORE_LIMIT_BYTES, clock=time.monotonic):
        self.incoming_dir = Path(incoming_dir)
        self.store_limit = store_limit
        self.clock = clock
        self.bytes_held = 0
        self._by_id: dict[str, Grant] = {}

    def purge_leftovers(self) -> int:
        """Partial or unpublished files of an earlier run: deleted, never published."""
        n = 0
        if self.incoming_dir.is_dir():
            for path in self.incoming_dir.glob("*.part"):
                self._discard_path(path)
                n += 1
        if n:
            log.info("removed %d leftover artifact file(s) from an earlier run", n)
        return n

    def issue(self, identity: Identity, artifact_id: str, event_id: str, max_bytes: int,
              lifetime_s: float = UPLOAD_LIFETIME_S) -> tuple[Grant, str]:
        upload_id = "u_" + secrets.token_urlsafe(24)           # 192-bit, [A-Za-z0-9_-]{34}
        token = secrets.token_urlsafe(32)                      # 32 random bytes, base64url, 43 chars
        grant = Grant(upload_id, _digest(token), identity, artifact_id, event_id, max_bytes,
                      self.clock() + lifetime_s, _utc_in(lifetime_s))
        self._by_id[upload_id] = grant
        return grant, token

    def get(self, upload_id: str) -> Grant | None:
        return self._by_id.get(upload_id)

    def claim(self, upload_id: str, token: str | None, content_length: int) -> Grant:
        """Authorize one PUT before its body is read. Raises UploadError(status)."""
        if not token:
            raise UploadError(401, "missing upload token")
        grant = self._by_id.get(upload_id)
        if grant is None or not hmac.compare_digest(_digest(token), grant.token_digest):
            raise UploadError(403, "upload not permitted")          # unknown id and wrong token look alike
        if grant.state in (G_CANCELLED, G_EXPIRED):
            raise UploadError(410, "upload permission no longer valid")
        if grant.state != ISSUED:
            raise UploadError(409, "upload already used")
        if self.clock() >= grant.deadline:
            self._finish(grant, G_EXPIRED)
            raise UploadError(410, "upload permission expired")
        grant.state = CLAIMED                     # from here on the grant is spent, success or not
        if content_length > grant.max_bytes:
            self._finish(grant, G_FAILED)
            raise UploadError(413, f"more than {grant.max_bytes} bytes")
        if self.bytes_held + content_length > self.store_limit:
            self._finish(grant, G_FAILED)
            raise UploadError(503, "Host artifact storage is full")
        self.bytes_held += content_length
        grant.size = content_length               # reserved; the real count is checked while reading
        return grant

    async def receive(self, grant: Grant, reader: asyncio.StreamReader, length: int) -> None:
        """Stream the body into a new private file; fix size and SHA-256. Raises UploadError."""
        self.incoming_dir.mkdir(parents=True, exist_ok=True)
        path = self.incoming_dir / f"{secrets.token_hex(16)}.part"
        sha, got = hashlib.sha256(), 0
        try:
            with open(path, "xb") as f:                         # never overwrites
                while got < length:
                    if grant.state != CLAIMED:
                        raise UploadError(410, "upload cancelled")
                    left = grant.deadline - self.clock()
                    if left <= 0:
                        raise UploadError(408, "upload deadline passed")
                    try:
                        chunk = await asyncio.wait_for(reader.read(min(CHUNK, length - got)), left)
                    except asyncio.TimeoutError:
                        raise UploadError(408, "upload deadline passed") from None
                    if not chunk:
                        raise UploadError(400, f"body ended after {got} of {length} bytes")
                    f.write(chunk)
                    sha.update(chunk)
                    got += len(chunk)
                f.flush()
                os.fsync(f.fileno())
            if grant.state != CLAIMED:
                raise UploadError(410, "upload cancelled")
            os.chmod(path, stat.S_IREAD)                         # fixed: inspection and publish use these bytes
        except BaseException:
            self._discard_path(path)
            self.bytes_held -= length
            grant.size = None
            if grant.state == CLAIMED:
                self._finish(grant, G_FAILED)
            raise
        grant.path, grant.size, grant.sha256 = path, got, sha.hexdigest()
        self._finish(grant, RECEIVED)
        log.info("ARTIFACT received %s for %s: %d bytes sha256=%s…", _short(grant.upload_id), grant.artifact_id,
                 got, grant.sha256[:12])

    def cancel(self, grant: Grant) -> None:
        """Revoke a grant and drop whatever it received."""
        if grant.state in (ISSUED, CLAIMED):
            self._finish(grant, G_CANCELLED)        # a running receive() notices and cleans up
        self.discard(grant)

    def discard(self, grant: Grant) -> None:
        if grant.path is not None:
            self._discard_path(grant.path)
            self.bytes_held -= grant.size or 0
            grant.path = None

    def release(self, grant: Grant) -> None:
        """The file left quarantine (published): stop counting it."""
        self.bytes_held -= grant.size or 0
        grant.path = None

    def _finish(self, grant: Grant, state: str) -> None:
        grant.state = state
        grant.done.set()

    @staticmethod
    def _discard_path(path: Path) -> None:
        try:
            os.chmod(path, stat.S_IWRITE)
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("could not delete %s: %s", path.name, e)


# ----------------------------------------------------------------------------- artifacts
CANDIDATE, AUTHORIZED, SCANNING, EXPORTED, BLOCKED, FAILED, CANCELLED = (
    "CANDIDATE", "AUTHORIZED", "SCANNING", "EXPORTED", "BLOCKED", "FAILED", "CANCELLED")
FINAL = (EXPORTED, BLOCKED, FAILED, CANCELLED)

# Runner ARTIFACT_RESULT error code → may the Agent ask again (new approval, new grant)?
RUNNER_RETRYABLE = {"ARTIFACT_BUSY": True, "UPLOAD_FAILED": True, "UPLOAD_EXPIRED": True,
                    "CANDIDATE_UNAVAILABLE": False, "ARTIFACT_BLOCKED": False,
                    "SESSION_TERMINATED": False, "INTERNAL": False}


class ArtifactError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False, next_step: str | None = None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.retryable, self.next_step = code, message, retryable, next_step


@dataclass(eq=False)
class Artifact:
    artifact_id: str
    identity: Identity
    event_id: str
    relative_path: str                  # what the Guest reported; display only, never a Host path
    observed_at: str
    payload: dict
    stage: str = CANDIDATE
    result: dict | None = None
    retry_allowed: bool = False
    grant: Grant | None = None
    size: int | None = None
    sha256: str | None = None
    export_path: Path | None = None
    attempts: int = 0
    task: asyncio.Task | None = None


class ArtifactBroker:
    def __init__(self, grants: ArtifactGrants, export_dir: Path, scanner, *,
                 max_bytes: int = DEFAULT_MAX_BYTES, upload_lifetime_s: float = UPLOAD_LIFETIME_S,
                 result_grace_s: float = RESULT_GRACE_S, scan_timeout_s: float = 30.0,
                 telemetry_wait_s: float = TELEMETRY_WAIT_S):
        if not 1 <= max_bytes <= MAX_BYTES_LIMIT:
            raise ValueError(f"max_bytes must be 1..{MAX_BYTES_LIMIT}")
        self.grants = grants
        self.export_dir = Path(export_dir)
        self.scanner = scanner
        self.max_bytes = max_bytes
        self.upload_lifetime_s = upload_lifetime_s
        self.result_grace_s = result_grace_s
        self.scan_timeout_s = scan_timeout_s
        self.telemetry_wait_s = telemetry_wait_s
        self._seq = 0
        self._by_id: dict[str, Artifact] = {}
        self._by_event: dict[tuple[Identity, str], Artifact] = {}
        self._channel: dict[Identity, asyncio.Event] = {}
        self._channel_lost: dict[Identity, str] = {}

    # -- Telemetry side --------------------------------------------------------
    def _event(self, identity: Identity) -> asyncio.Event:
        return self._channel.setdefault(identity, asyncio.Event())

    def channel_up(self, identity: Identity) -> None:
        self._event(identity).set()
        log.info("ARTIFACT channel up for %s gen %d", identity[0], identity[2])

    def channel_down(self, identity: Identity, why: str) -> None:
        """Telemetry lost: no new exports for this Runtime, running ones fail (contract §4)."""
        if not self._event(identity).is_set() or identity in self._channel_lost:
            return
        self._channel_lost[identity] = why
        log.warning("ARTIFACT channel lost for %s gen %d: %s", identity[0], identity[2], why)
        self._cancel(identity, "TELEMETRY_LOST", f"artifact channel lost ({why})")

    async def startup_check(self, session: RuntimeSession) -> tuple[str, bool, str]:
        """Startup Verification step: the Runner only reports files created after this."""
        try:
            await asyncio.wait_for(self._event(session.identity).wait(), self.telemetry_wait_s)
        except asyncio.TimeoutError:
            return "telemetry", False, f"no Telemetry channel within {self.telemetry_wait_s:.0f}s"
        return "telemetry", True, "Telemetry channel up (artifact candidates are reported)"

    def store(self, identity: Identity, payload: dict) -> bool:
        """A candidate SECURITY_EVENT. True: STORED (also for an identical repeat). False: REJECTED."""
        key = (identity, payload["event_id"])
        known = self._by_event.get(key)
        if known is not None:
            return known.payload == payload          # same id, other content: refused
        if identity in self._channel_lost or len(self._by_id) >= MAX_CANDIDATES:
            return False
        self._seq += 1
        art = Artifact(f"ART-{self._seq:06d}", identity, payload["event_id"], payload["relative_path"],
                       payload["observed_at"], dict(payload))
        self._by_id[art.artifact_id] = art
        self._by_event[key] = art
        log.info("ARTIFACT candidate %s %s (event %s…)", art.artifact_id, art.relative_path, art.event_id[:8])
        return True

    # -- Agent side ------------------------------------------------------------
    def get(self, artifact_id: str) -> Artifact | None:
        return self._by_id.get(artifact_id)

    def precheck(self, session: RuntimeSession, artifact_id: str) -> Artifact:
        """Before asking the user: is this an artifact that can be exported, or already in progress?"""
        art = self._by_id.get(artifact_id)
        if art is None or art.identity[:2] != session.identity[:2]:
            raise ArtifactError("INVALID_ARGUMENT", f"{artifact_id} is not an artifact of this session",
                                next_step="artifact_list")
        if not self.needs_new_attempt(art):
            return art                                  # in progress or finished: just report it
        if art.identity != session.identity:
            raise ArtifactError("INVALID_ARGUMENT", f"{artifact_id} was reported by an earlier runtime generation; "
                                "it can no longer be exported", next_step="artifact_list")
        if session.identity in self._channel_lost:
            raise ArtifactError("POLICY_DENIED", "the artifact channel of this runtime was lost; "
                                "exports stay off until the runtime is restarted")
        busy = [a.artifact_id for a in self._by_id.values()
                if a.identity == session.identity and a.stage in (AUTHORIZED, SCANNING)]
        if busy:
            raise ArtifactError("ARTIFACT_BUSY", f"{busy[0]} is still being transferred; one export at a time",
                                retryable=True, next_step="artifact_list")
        return art

    @staticmethod
    def needs_new_attempt(art: Artifact) -> bool:
        """True when export would issue a new grant (and so needs a new approval)."""
        return art.stage == CANDIDATE or (art.stage in (FAILED, CANCELLED) and art.retry_allowed)

    async def export(self, session: RuntimeSession, artifact_id: str) -> dict:
        """After approval. Issues the grant, sends ARTIFACT_REQUEST, returns at once."""
        art = self.precheck(session, artifact_id)
        if not self.needs_new_attempt(art):
            return {**self.view(art), "accepted": True, "note": "already requested; follow it with artifact_list"}
        conn = session._live()                           # READY and connected, or ProtocolError
        grant, token = self.grants.issue(session.identity, art.artifact_id, art.event_id, self.max_bytes,
                                         self.upload_lifetime_s)
        msg = conn.me.envelope("ARTIFACT_REQUEST", {
            "candidate_event_id": art.event_id, "upload_id": grant.upload_id, "upload_token": token,
            "upload_deadline_at": grant.deadline_utc, "max_bytes": grant.max_bytes})
        art.grant, art.stage, art.result, art.retry_allowed = grant, AUTHORIZED, None, False
        art.size = art.sha256 = None
        art.attempts += 1
        art.task = asyncio.get_running_loop().create_task(self._run(art, grant, conn, msg))
        log.info("ARTIFACT %s export requested (upload %s, up to %d bytes, until %s)",
                 art.artifact_id, _short(grant.upload_id), grant.max_bytes, grant.deadline_utc)
        return {**self.view(art), "accepted": True}

    async def _run(self, art: Artifact, grant: Grant, conn: Connection, msg: dict) -> None:
        wait = max(0.0, grant.deadline - self.grants.clock()) + self.result_grace_s
        try:
            reply = await conn.request(msg, ("ARTIFACT_RESULT",), timeout=wait)
        except ProtocolError as e:
            if art.stage == AUTHORIZED:
                code = "RESULT_MISSING" if e.code == "ACTION_TIMEOUT" else e.code
                self._end(art, FAILED, code, f"no usable ARTIFACT_RESULT ({e.detail})", retry=True)
            return
        if art.stage != AUTHORIZED:
            return                                       # cancelled meanwhile
        p = reply["payload"]
        if reply["status"] != "OK":
            code = reply["error"]["code"]
            self._end(art, FAILED, code, f"Runner: {reply['error']['message']}",
                      retry=RUNNER_RETRYABLE.get(code, False))
            return
        if grant.state == CLAIMED:                       # the 201 went out just before; let receive() finish
            try:
                await asyncio.wait_for(grant.done.wait(), 5.0)
            except asyncio.TimeoutError:
                pass
        if art.stage != AUTHORIZED:
            return
        mismatch = [what for what, ok in (
            ("upload not received by the Host", grant.state == RECEIVED),
            ("candidate_event_id", p["candidate_event_id"] == art.event_id),
            ("upload_id", p["upload_id"] == grant.upload_id),
            ("bytes_sent", grant.size is not None and p["bytes_sent"] == grant.size)) if not ok]
        if mismatch:
            self._end(art, FAILED, "RESULT_MISMATCH", "ARTIFACT_RESULT does not match what the Host received: "
                      + ", ".join(mismatch), retry=True)
            return
        art.size, art.sha256 = grant.size, grant.sha256
        art.stage = SCANNING
        verdict = await inspect(grant.path, art.relative_path, grant.sha256, self.scanner, self.scan_timeout_s)
        if art.stage != SCANNING:
            return
        if not verdict.ok:
            self._end(art, BLOCKED, verdict.code, verdict.detail, engine=verdict.engine)
            return
        await self._publish(art, grant, verdict)

    async def _publish(self, art: Artifact, grant: Grant, verdict: Verdict) -> None:
        """Move the inspected file out of quarantine. Only those bytes, never a copy made later."""
        session_id = art.identity[0]
        name = _safe_name(art.relative_path)
        dest_dir = self.export_dir / session_id / art.artifact_id
        dest = dest_dir / name
        try:
            await asyncio.to_thread(dest_dir.mkdir, parents=True, exist_ok=True)
        except OSError as e:
            self._end(art, FAILED, "PUBLISH_FAILED", f"export folder: {e}", retry=False)
            return
        if art.stage != SCANNING or grant.path is None:
            return
        # No await between this check, the move and the state change: cancel cannot slip in.
        try:
            os.rename(grant.path, dest)
        except OSError as e:
            self._end(art, FAILED, "PUBLISH_FAILED", f"move into the export folder failed: {e}", retry=False)
            return
        self.grants.release(grant)
        art.stage, art.export_path = EXPORTED, dest
        art.result = {"code": "EXPORTED", "detail": verdict.detail, "engine": verdict.engine}
        if await asyncio.to_thread(_sha_file, dest) != grant.sha256:     # same bytes as inspected
            os.chmod(dest, stat.S_IWRITE)
            dest.unlink(missing_ok=True)
            art.stage, art.export_path = BLOCKED, None
            art.result = {"code": "CONTENT_CHANGED", "detail": "file changed while it was published"}
            log.error("ARTIFACT %s withdrawn: content changed during publish", art.artifact_id)
            return
        log.info("ARTIFACT %s EXPORTED to %s (%d bytes, %s)", art.artifact_id, dest, art.size, verdict.detail)

    def _end(self, art: Artifact, stage: str, code: str, detail: str, *, retry: bool = False,
             engine: str | None = None) -> None:
        art.stage, art.retry_allowed = stage, retry
        art.result = {"code": code, "detail": detail, **({"engine": engine} if engine else {})}
        if art.grant is not None:
            self.grants.cancel(art.grant)              # unused grants revoked, received bytes deleted
        log.warning("ARTIFACT %s %s: %s %s", art.artifact_id, stage, code, detail)

    # -- end of a session / generation -------------------------------------------
    def cancel_identity(self, identity: Identity, why: str) -> None:
        """Session ended or replaced by a new generation: nothing of it is exported any more."""
        self._channel_lost.setdefault(identity, why)
        self._cancel(identity, "CANCELLED", why)

    def _cancel(self, identity: Identity, code: str, why: str) -> None:
        for art in self._by_id.values():
            if art.identity != identity or art.stage in FINAL:
                continue
            was = art.stage
            if art.task is not None and art.task is not asyncio.current_task():
                art.task.cancel()
            self._end(art, CANCELLED, code, why, retry=False)
            if was == CANDIDATE:
                log.info("ARTIFACT %s candidate dropped: %s", art.artifact_id, why)

    # -- views ---------------------------------------------------------------
    def status(self, art: Artifact) -> str:
        if art.stage in (CANDIDATE,):
            return "PENDING"
        if art.stage == AUTHORIZED:
            return "QUARANTINED" if art.grant is not None and art.grant.state == RECEIVED else "PENDING"
        return {SCANNING: "SCANNING", EXPORTED: "EXPORTED"}.get(art.stage, "BLOCKED")

    def stage(self, art: Artifact) -> str:
        if art.stage == AUTHORIZED and art.grant is not None:
            return {CLAIMED: "RECEIVING", RECEIVED: "RECEIVED"}.get(art.grant.state, AUTHORIZED)
        return art.stage

    def view(self, art: Artifact) -> dict:
        received = art.size is not None
        out = {
            "artifact_id": art.artifact_id,
            "path": art.relative_path,
            "status": self.status(art),
            "stage": self.stage(art),
            "generation": art.identity[2],
            "observed_at": art.observed_at,
            "size_bytes": art.size,
            "sha256": art.sha256,
            "mime": None,
            "result": art.result,
            "export_path": str(art.export_path) if art.stage == EXPORTED else None,
            "can_export": self.needs_new_attempt(art),
        }
        if not received:
            out["unverified"] = "size, type and hash are unknown until the Host has received the file"
        return out

    def list(self, session: RuntimeSession, status: str = "ANY", limit: int = 50, cursor: str | None = None) -> dict:
        arts = [a for a in self._by_id.values() if a.identity[:2] == session.identity[:2]]
        if cursor:
            arts = [a for a in arts if a.artifact_id > cursor]
        views = [self.view(a) for a in arts]
        if status != "ANY":
            views = [v for v in views if v["status"] == status]
        page = views[:limit]
        return {"artifacts": page, "next_cursor": page[-1]["artifact_id"] if len(views) > limit else None,
                "note": "Reported candidates, not a live directory listing; a file changed or deleted "
                        "since it was reported is refused when exported."}


_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def _safe_name(relative_path: str) -> str:
    """The Guest's file name, made safe as a Host file name. Never a Host path from the Guest."""
    name = PureWindowsPath(relative_path).name
    name = "".join(ch if ch.isprintable() and ch not in '\\/:*?"<>|' else "_" for ch in name).strip(" .")
    if not name or name.split(".")[0].upper() in _RESERVED:
        name = "_" + (name or "artifact")
    return name[:200]


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


__all__ = ["ARTIFACT_CAPABILITY", "ARTIFACT_EXPORT_V1", "ARTIFACT_UPLOAD_PATH", "TELEMETRY_PATH", "ArtifactBroker",
           "ArtifactError", "ArtifactGrants"]
