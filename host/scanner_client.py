"""Host side of the SecureArtifactScanner service pipe (scanner_service/, protocol scanner-ipc-v1).

Used with --artifact-scanner defender-service. The pipe calls are blocking (pywin32), so every
one runs in a worker thread (asyncio.to_thread): the Host's event loop never waits on the pipe.

Checks on top of the service's own:
- the process at the other end of the pipe is the SecureArtifactScanner service the SCM reports
  (unless verify_server=False, for tests with an in-process service)
- every response answers its own request_id (scanner_service.ipc_client) and every job view
  names the job, session, runtime, generation and artifact that were asked about
- a broken connection, a timeout or a stopped service is ScannerServiceError("SCANNER_UNAVAILABLE"),
  never a result

One upload uses one connection (chunks in order); other calls open a short connection each.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import threading

from scanner_service.config import PIPE_NAME
from scanner_service.ipc_client import ScannerClient, service_pid
from scanner_service.models import Identity as JobIdentity
from scanner_service.models import ScannerError
from scanner_service.pipe_io import FrameTooLarge, PipeClosed, PipeStopping, PipeTimeout

log = logging.getLogger("host-scanner-client")

HostIdentity = tuple[str, str, int]
UNAVAILABLE = "SCANNER_UNAVAILABLE"
# service error codes that mean "try again later", not "this file is refused"
BUSY_CODES = {"SERVICE_STOPPING", "TOO_MANY_JOBS", "STORAGE_FULL", "DISK_FULL", UNAVAILABLE}


class ScannerServiceError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.retryable = code, message, retryable


def job_identity(identity: HostIdentity, artifact_id: str) -> JobIdentity:
    return JobIdentity(identity[0], identity[1], identity[2], artifact_id)


def _check_view(view: dict, ident: JobIdentity, job_id: str | None) -> dict:
    """A job view must be about the job and identity the request named."""
    expected = {"session_id": ident.session_id, "runtime_id": ident.runtime_id, "generation": ident.generation,
                "artifact_id": ident.artifact_id, **({"job_id": job_id} if job_id else {})}
    wrong = [k for k, v in expected.items() if view.get(k) != v]
    if wrong:
        raise ScannerServiceError("RESPONSE_MISMATCH", f"scanner answer is about another job ({', '.join(wrong)})")
    return view


class ScannerServiceClient:
    def __init__(self, pipe_name: str = PIPE_NAME, *, verify_server: bool = True, timeout_s: float = 30.0,
                 connect_timeout_s: float = 2.0):
        self.pipe_name = pipe_name
        self.verify_server = verify_server
        self.timeout_s = timeout_s
        self.connect_timeout_s = connect_timeout_s    # a missing service must fail fast (a PUT is waiting)

    # -- plumbing (worker threads) ---------------------------------------------
    def _open(self) -> ScannerClient:
        pid = None
        if self.verify_server:
            try:
                pid = service_pid()
            except Exception as e:  # noqa: BLE001 - not installed / SCM refused
                raise ScannerServiceError(UNAVAILABLE, f"SecureArtifactScanner service not found ({e})",
                                          retryable=True) from None
            if pid is None:
                raise ScannerServiceError(UNAVAILABLE, "SecureArtifactScanner service is not running", retryable=True)
        c = ScannerClient(self.pipe_name, timeout_s=self.timeout_s, expected_server_pid=pid,
                          connect_timeout_s=self.connect_timeout_s)
        try:
            c.connect()
        except (ConnectionError, OSError) as e:
            raise ScannerServiceError(UNAVAILABLE, f"scanner pipe: {e}", retryable=True) from None
        return c

    @staticmethod
    def _call_on(c: ScannerClient, command: str, ident: JobIdentity | None, job_id: str | None,
                 payload: dict | None, session_id: str | None = None) -> dict:
        try:
            return c.call(command, ident, job_id, payload, session_id=session_id)
        except ScannerError as e:
            raise ScannerServiceError(e.code, e.message, retryable=e.retryable or e.code in BUSY_CODES) from None
        except (ConnectionError, OSError, PipeClosed, PipeTimeout, PipeStopping, FrameTooLarge, ValueError) as e:
            c.close()
            raise ScannerServiceError(UNAVAILABLE, f"scanner pipe: {type(e).__name__}: {e}", retryable=True) from None

    def _once(self, command: str, ident: JobIdentity | None = None, job_id: str | None = None,
              payload: dict | None = None, session_id: str | None = None) -> dict:
        c = self._open()
        try:
            return self._call_on(c, command, ident, job_id, payload, session_id)
        finally:
            c.close()

    def _job(self, command: str, ident: JobIdentity, job_id: str, payload: dict | None = None) -> dict:
        return _check_view(self._once(command, ident, job_id, payload), ident, job_id)

    # -- async API -----------------------------------------------------------
    async def health(self) -> dict:
        return await asyncio.to_thread(self._once, "HEALTH_CHECK")

    async def scan(self, ident: JobIdentity, job_id: str) -> dict:
        return await asyncio.to_thread(self._job, "SCAN", ident, job_id)

    async def status(self, ident: JobIdentity, job_id: str) -> dict:
        return await asyncio.to_thread(self._job, "GET_STATUS", ident, job_id)

    async def publish(self, ident: JobIdentity, job_id: str, approval: dict) -> dict:
        return await asyncio.to_thread(self._job, "PUBLISH", ident, job_id, {"approval": approval})

    async def abort(self, ident: JobIdentity, job_id: str, reason: str) -> dict:
        return await asyncio.to_thread(self._job, "ABORT", ident, job_id, {"reason": reason[:200]})

    async def abort_session(self, session_id: str, reason: str) -> int:
        r = await asyncio.to_thread(self._once, "ABORT", None, None, {"scope": "session", "reason": reason[:200]},
                                    session_id)
        return int(r.get("cancelled_jobs", 0))

    def abort_soon(self, ident: JobIdentity, job_id: str, reason: str) -> None:
        """Fire and forget (from synchronous cancel paths). A failure is only logged: the service
        expires abandoned jobs by itself (upload idle timeout, job lifetime)."""
        def run():
            try:
                self._job("ABORT", ident, job_id, {"reason": reason[:200]})
                log.info("SCANNER job %s aborted (%s)", job_id, reason)
            except ScannerServiceError as e:
                if e.code not in ("JOB_NOT_FOUND",):
                    log.warning("SCANNER job %s not aborted: %s", job_id, e)
        threading.Thread(target=run, name="scanner-abort", daemon=True).start()

    def upload(self, ident: JobIdentity) -> "UploadStream":
        return UploadStream(self, ident)


class UploadStream:
    """BEGIN_UPLOAD, WRITE_CHUNK..., COMPLETE_UPLOAD on one connection, in order."""

    def __init__(self, client: ScannerServiceClient, ident: JobIdentity):
        self.client = client
        self.ident = ident
        self.job_id: str | None = None
        self.sent = 0
        self._conn: ScannerClient | None = None

    def _call(self, command: str, payload: dict) -> dict:
        if self._conn is None:
            self._conn = self.client._open()
        return self.client._call_on(self._conn, command, self.ident, self.job_id, payload)

    async def begin(self, file_name: str, size: int) -> str:
        view = await asyncio.to_thread(self._call, "BEGIN_UPLOAD", {"file_name": file_name, "size": size})
        _check_view(view, self.ident, None)
        self.job_id = view["job_id"]
        return self.job_id

    async def write(self, data: bytes) -> None:
        payload = {"offset": self.sent, "data": base64.b64encode(data).decode("ascii")}
        r = await asyncio.to_thread(self._call, "WRITE_CHUNK", payload)
        if r.get("job_id") != self.job_id or r.get("received_bytes") != self.sent + len(data):
            raise ScannerServiceError("RESPONSE_MISMATCH", "scanner did not record the chunk as sent")
        self.sent += len(data)

    async def complete(self, sha256: str) -> dict:
        view = await asyncio.to_thread(self._call, "COMPLETE_UPLOAD", {"sha256": sha256})
        return _check_view(view, self.ident, self.job_id)

    async def close(self) -> None:
        if self._conn is not None:
            conn, self._conn = self._conn, None
            await asyncio.to_thread(conn.close)
