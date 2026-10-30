"""Named Pipe interface \\\\.\\pipe\\SecureArtifactScanner (protocol scanner-ipc-v1).

Request (one frame, at most max_request_bytes):
    {"protocol_version": "scanner-ipc-v1", "request_id": "<1..64 chars>", "command": "<COMMAND>",
     "session_id", "runtime_id", "generation", "artifact_id", "job_id", "payload": {...}}
Response (at most max_response_bytes):
    {"protocol_version", "request_id", "status": "OK", "result": {...}}
    {"protocol_version", "request_id", "status": "ERROR", "error": {"code", "message", "retryable"}}

Commands: HEALTH_CHECK, BEGIN_UPLOAD, WRITE_CHUNK, COMPLETE_UPLOAD, SCAN, GET_STATUS, PUBLISH,
ABORT (see scanner_service/README.md for each one's fields). There is no command that takes
a path, a program or a command line: the service only works on jobs it created.

Who may connect is decided by the pipe's DACL: SYSTEM, Administrators, the service itself
and the configured Host user SIDs; network logons are denied and remote clients rejected.
Clients get read + write but NOT FILE_CREATE_PIPE_INSTANCE (part of GENERIC_WRITE for
pipes), so a client cannot open its own server end and pose as the service. The first
instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE: if someone already holds the name,
the service refuses to start instead of sharing it.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

import pywintypes
import win32api
import win32event
import win32file
import win32pipe
import win32security
import winerror

from scanner_service import pipe_io
from scanner_service.models import (JOB_RE, PROTOCOL_VERSION, SESSION_RE, ScannerError, validate_identity)

log = logging.getLogger("scanner.ipc")

COMMANDS = ("HEALTH_CHECK", "BEGIN_UPLOAD", "WRITE_CHUNK", "COMPLETE_UPLOAD", "SCAN", "GET_STATUS", "PUBLISH",
            "ABORT")
TOP_KEYS = {"protocol_version", "request_id", "command", "job_id", "artifact_id", "session_id", "runtime_id",
            "generation", "payload"}
PAYLOAD_KEYS = {
    "HEALTH_CHECK": {"selftest"},
    "BEGIN_UPLOAD": {"file_name", "size", "sha256"},
    "WRITE_CHUNK": {"offset", "data"},
    "COMPLETE_UPLOAD": {"sha256"},
    "SCAN": set(),
    "GET_STATUS": set(),
    "PUBLISH": {"approval"},
    "ABORT": {"scope", "reason"},
}
FILE_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_CLIENT_MASK = 0x0012019B        # FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE


@dataclass(frozen=True)
class ClientInfo:
    pid: int | None
    sid: str | None

    def __str__(self) -> str:
        return f"pid {self.pid} sid {self.sid}"


def pipe_sddl(service_sid: str, client_sids: tuple[str, ...]) -> str:
    aces = ["(D;;GA;;;NU)",                     # no network logons
            "(A;;GA;;;SY)", "(A;;GA;;;BA)", f"(A;;GA;;;{service_sid})"]
    aces += [f"(A;;0x{PIPE_CLIENT_MASK:x};;;{sid})" for sid in client_sids]
    return "D:P" + "".join(aces)


def current_user_sid() -> str:
    tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        return win32security.ConvertSidToStringSid(win32security.GetTokenInformation(tok, win32security.TokenUser)[0])
    finally:
        tok.Close()


# ----------------------------------------------------------------------------- request handling
class RequestHandler:
    """Bytes in, bytes out. Knows nothing about pipes, so it is tested directly."""

    def __init__(self, manager, health: Callable[[dict], dict], *, max_chunk_bytes: int, max_response_bytes: int):
        self.manager = manager
        self.health = health
        self.max_chunk_bytes = max_chunk_bytes
        self.max_b64 = (max_chunk_bytes + 2) // 3 * 4
        self.max_response_bytes = max_response_bytes

    def error_frame(self, code: str, message: str, request_id=None, retryable: bool = False) -> bytes:
        return self._encode({"protocol_version": PROTOCOL_VERSION, "request_id": request_id, "status": "ERROR",
                             "error": {"code": code, "message": message, "retryable": retryable}})

    def _encode(self, obj: dict) -> bytes:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def handle(self, raw: bytes, client: ClientInfo) -> bytes:
        request_id = command = req = None
        try:
            try:
                req = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise ScannerError("BAD_REQUEST", "request is not UTF-8 JSON") from None
            if not isinstance(req, dict):
                raise ScannerError("BAD_REQUEST", "request must be a JSON object")
            rid = req.get("request_id")
            if isinstance(rid, str) and 1 <= len(rid) <= 64 and rid.isprintable():
                request_id = rid
            else:
                raise ScannerError("BAD_REQUEST", "request_id must be 1..64 printable characters")
            if req.get("protocol_version") != PROTOCOL_VERSION:
                raise ScannerError("UNSUPPORTED_PROTOCOL", f"protocol_version must be {PROTOCOL_VERSION}")
            unknown = set(req) - TOP_KEYS
            if unknown:
                raise ScannerError("BAD_REQUEST", f"unknown field(s): {', '.join(sorted(unknown))}")
            command = req.get("command")
            if command not in COMMANDS:
                raise ScannerError("UNKNOWN_COMMAND", f"command must be one of {', '.join(COMMANDS)}")
            payload = req.get("payload", {})
            if not isinstance(payload, dict):
                raise ScannerError("BAD_REQUEST", "payload must be an object")
            extra = set(payload) - PAYLOAD_KEYS[command]
            if extra:
                raise ScannerError("BAD_REQUEST", f"unknown payload field(s) for {command}: {', '.join(sorted(extra))}")
            result = self._dispatch(command, req, payload)
            out = self._encode({"protocol_version": PROTOCOL_VERSION, "request_id": request_id, "status": "OK",
                                "result": result})
            code = "OK"
        except ScannerError as e:
            out, code = self.error_frame(e.code, e.message, request_id, e.retryable), e.code
        except Exception:  # noqa: BLE001 - never leak a traceback to the client
            log.exception("IPC %s from %s failed", command, client)
            out, code = self.error_frame("INTERNAL", "internal error", request_id), "INTERNAL"
        if len(out) > self.max_response_bytes:
            out, code = self.error_frame("RESPONSE_TOO_LARGE", "response exceeds the limit", request_id), \
                "RESPONSE_TOO_LARGE"
        job = req.get("job_id") if isinstance(req, dict) else None
        (log.info if command not in ("WRITE_CHUNK", "GET_STATUS") or code != "OK" else log.debug)(
            "IPC %s job=%s from %s → %s", command, job if isinstance(job, str) and JOB_RE.fullmatch(job) else "-",
            client, code)
        return out

    def _ident(self, req: dict):
        return validate_identity(req.get("session_id"), req.get("runtime_id"), req.get("generation"),
                                 req.get("artifact_id"))

    @staticmethod
    def _job_id(req: dict) -> str:
        jid = req.get("job_id")
        if not isinstance(jid, str) or not JOB_RE.fullmatch(jid):
            raise ScannerError("JOB_NOT_FOUND", "job_id missing or malformed")
        return jid

    def _dispatch(self, command: str, req: dict, payload: dict) -> dict:
        m = self.manager
        if command == "HEALTH_CHECK":
            return self.health(payload)
        if command == "ABORT" and payload.get("scope") == "session":
            sid = req.get("session_id")
            if not isinstance(sid, str) or not SESSION_RE.fullmatch(sid):
                raise ScannerError("INVALID_ARGUMENT", "session_id required for a session abort")
            return {"cancelled_jobs": m.abort_session(sid, self._reason(payload, "session ended"))}
        if payload.get("scope") not in (None, "job"):
            raise ScannerError("INVALID_ARGUMENT", "scope must be job or session")
        ident = self._ident(req)
        if command == "BEGIN_UPLOAD":
            if req.get("job_id") is not None:
                raise ScannerError("BAD_REQUEST", "job_id is assigned by the service")
            return m.begin_upload(ident, payload).view()
        jid = self._job_id(req)
        if command == "WRITE_CHUNK":
            data = payload.get("data")
            if not isinstance(data, str) or len(data) > self.max_b64:
                raise ScannerError("CHUNK_TOO_LARGE", f"data must be base64 of at most {self.max_chunk_bytes} bytes")
            try:
                raw = base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError):
                raise ScannerError("BAD_REQUEST", "data is not valid base64") from None
            job = m.write_chunk(ident, jid, payload.get("offset"), raw)
            return {"job_id": job.job_id, "state": job.state.value, "received_bytes": job.received}
        if command == "COMPLETE_UPLOAD":
            return m.complete_upload(ident, jid, payload.get("sha256")).view()
        if command == "SCAN":
            return m.start_scan(ident, jid).view()
        if command == "GET_STATUS":
            return m.status(ident, jid).view()
        if command == "PUBLISH":
            return m.publish(ident, jid, payload.get("approval")).view()
        if command == "ABORT":
            return m.abort(ident, jid, self._reason(payload, "aborted by the Host")).view()
        raise ScannerError("UNKNOWN_COMMAND", command)

    @staticmethod
    def _reason(payload: dict, default: str) -> str:
        r = payload.get("reason")
        return r[:200] if isinstance(r, str) and r.isprintable() and r else default


# ----------------------------------------------------------------------------- the pipe server
class NamedPipeServer:
    def __init__(self, name: str, handler: RequestHandler, *, sddl: str, max_instances: int,
                 max_request_bytes: int, idle_timeout_s: float):
        self.name = name
        self.handler = handler
        self.sddl = sddl
        self.max_instances = max_instances
        self.max_request_bytes = max_request_bytes
        self.idle_timeout_s = idle_timeout_s
        self._stop = win32event.CreateEvent(None, True, False, None)
        self._threads: list[threading.Thread] = []

    def _security(self):
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            self.sddl, win32security.SDDL_REVISION_1)
        sa.bInheritHandle = False
        return sa

    def _create(self, first: bool):
        mode = win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED | (FILE_FIRST_PIPE_INSTANCE if first else 0)
        return win32pipe.CreateNamedPipe(
            self.name, mode,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT
            | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
            self.max_instances, 64 * 1024, 64 * 1024, 0, self._security())

    def start(self) -> None:
        try:
            first = self._create(first=True)
        except pywintypes.error as e:
            if e.winerror in (winerror.ERROR_ACCESS_DENIED, winerror.ERROR_PIPE_BUSY):
                raise RuntimeError(f"{self.name} is already in use by another process; refusing to share it") from None
            raise
        for i in range(self.max_instances):
            t = threading.Thread(target=self._worker, args=(first if i == 0 else None,), name=f"pipe-{i}",
                                 daemon=True)
            self._threads.append(t)
            t.start()
        log.info("IPC listening on %s (%d instances)", self.name, self.max_instances)

    def stop(self, timeout_s: float = 5.0) -> None:
        win32event.SetEvent(self._stop)
        for t in self._threads:
            t.join(timeout_s)
        log.info("IPC stopped")

    def _stopping(self) -> bool:
        return win32event.WaitForSingleObject(self._stop, 0) == win32event.WAIT_OBJECT_0

    def _worker(self, handle) -> None:
        try:
            if handle is None:
                handle = self._create(first=False)
        except pywintypes.error as e:
            log.error("IPC pipe instance not created: %s", e.strerror)
            return
        try:
            while not self._stopping():
                if not self._connect(handle):
                    continue
                try:
                    self._serve(handle)
                except Exception:  # noqa: BLE001 - one bad connection must not end the listener
                    log.exception("IPC connection failed")
                finally:
                    try:
                        win32pipe.DisconnectNamedPipe(handle)
                    except pywintypes.error:
                        pass
        finally:
            handle.Close()

    def _connect(self, handle) -> bool:
        ov = pywintypes.OVERLAPPED()
        ov.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            rc = win32pipe.ConnectNamedPipe(handle, ov)
            if rc == winerror.ERROR_PIPE_CONNECTED:
                return True
            r = win32event.WaitForMultipleObjects([ov.hEvent, self._stop], False, win32event.INFINITE)
            if r != win32event.WAIT_OBJECT_0:
                pipe_io._cancel(handle, ov)
                return False
            win32file.GetOverlappedResult(handle, ov, False)
            return True
        except pywintypes.error as e:
            if e.winerror == winerror.ERROR_NO_DATA:          # client came and went
                return False
            log.warning("IPC connect failed: %s", e.strerror)
            return False
        finally:
            ov.hEvent.Close()

    def _identify(self, handle) -> ClientInfo:
        pid = sid = None
        try:
            pid = win32pipe.GetNamedPipeClientProcessId(handle)
        except pywintypes.error:
            pass
        try:
            win32security.ImpersonateNamedPipeClient(handle)
            try:
                tok = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True)
                try:
                    sid = win32security.ConvertSidToStringSid(
                        win32security.GetTokenInformation(tok, win32security.TokenUser)[0])
                finally:
                    tok.Close()
            finally:
                win32security.RevertToSelf()
        except pywintypes.error:
            pass
        return ClientInfo(pid, sid)

    def _serve(self, handle) -> None:
        client = None
        while not self._stopping():
            try:
                raw = pipe_io.read_frame(handle, self.max_request_bytes, self._stop, self.idle_timeout_s)
            except pipe_io.FrameTooLarge as e:
                log.warning("IPC request of %d bytes from %s refused (limit %d)", e.size,
                            client or "unidentified client", e.limit)
                self._send(handle, self.handler.error_frame("REQUEST_TOO_LARGE",
                                                            f"requests are at most {e.limit} bytes"))
                self._linger(handle)
                return                                       # the stream cannot be resynchronised
            except (pipe_io.PipeTimeout, pipe_io.PipeStopping, pipe_io.PipeClosed):
                return
            if raw is None:
                return
            if client is None:
                client = self._identify(handle)              # needs data read first
                if client.sid is None:
                    self._send(handle, self.handler.error_frame("ACCESS_DENIED", "client identity unknown"))
                    self._linger(handle)
                    return
            if not self._send(handle, self.handler.handle(raw, client)):
                return

    def _linger(self, handle, seconds: float = 1.0) -> None:
        """Before hanging up on a client: give it a moment to read the last answer
        (DisconnectNamedPipe throws away whatever it has not read yet)."""
        try:
            pipe_io.read_exact(handle, 1, self._stop, time.monotonic() + seconds)
        except Exception:  # noqa: BLE001 - closed, timed out or stopping: all fine here
            pass

    def _send(self, handle, data: bytes) -> bool:
        try:
            pipe_io.write_frame(handle, data, self._stop)
            return True
        except (pipe_io.PipeTimeout, pipe_io.PipeStopping, pipe_io.PipeClosed):
            return False
