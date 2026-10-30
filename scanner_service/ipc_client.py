"""Test client for the scanner pipe (the Host integration will use the same calls later).

The client asks for an Identification-level impersonation only (SECURITY_SQOS_PRESENT |
SECURITY_IDENTIFICATION): the service can see who is calling, but cannot act as the caller.
With expected_server_pid it also checks that the other end of the pipe is the service
process the SCM reports, not some other program holding the name.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import time

import pywintypes
import win32file
import win32pipe
import winerror

from scanner_service import pipe_io
from scanner_service.config import PIPE_NAME, SERVICE_NAME
from scanner_service.models import PROTOCOL_VERSION, Identity, ScannerError

SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000
_ids = itertools.count(1)


def service_pid(name: str = SERVICE_NAME) -> int | None:
    import win32service
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        svc = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_STATUS)
        try:
            st = win32service.QueryServiceStatusEx(svc)
            return st["ProcessId"] if st["CurrentState"] == win32service.SERVICE_RUNNING else None
        finally:
            win32service.CloseServiceHandle(svc)
    finally:
        win32service.CloseServiceHandle(scm)


class ScannerClient:
    def __init__(self, pipe_name: str = PIPE_NAME, *, timeout_s: float = 30.0, expected_server_pid: int | None = None,
                 max_response_bytes: int = 1024 * 1024):
        self.pipe_name = pipe_name
        self.timeout_s = timeout_s
        self.expected_server_pid = expected_server_pid
        self.max_response_bytes = max_response_bytes
        self.handle = None

    def __enter__(self) -> "ScannerClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        deadline = time.monotonic() + self.timeout_s
        while True:
            try:
                self.handle = win32file.CreateFile(
                    self.pipe_name, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING,
                    win32file.FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None)
                break
            except pywintypes.error as e:
                if time.monotonic() >= deadline or e.winerror not in (winerror.ERROR_PIPE_BUSY,
                                                                      winerror.ERROR_FILE_NOT_FOUND):
                    raise ConnectionError(f"{self.pipe_name}: {e.strerror} ({e.winerror})") from None
                if e.winerror == winerror.ERROR_PIPE_BUSY:
                    try:
                        win32pipe.WaitNamedPipe(self.pipe_name, 1000)
                    except pywintypes.error:
                        pass
                else:
                    time.sleep(0.1)
        if self.expected_server_pid is not None:
            pid = win32pipe.GetNamedPipeServerProcessId(self.handle)
            if pid != self.expected_server_pid:
                self.close()
                raise ConnectionError(f"pipe server is pid {pid}, not the service (pid {self.expected_server_pid})")

    def close(self) -> None:
        if self.handle is not None:
            self.handle.Close()
            self.handle = None

    # -- raw ------------------------------------------------------------------
    def send_bytes(self, data: bytes) -> dict | None:
        if self.handle is None:
            self.connect()
        pipe_io.write_frame(self.handle, data, timeout_s=self.timeout_s)
        raw = pipe_io.read_frame(self.handle, self.max_response_bytes, timeout_s=self.timeout_s)
        return None if raw is None else json.loads(raw.decode("utf-8"))

    def send(self, obj: dict) -> dict:
        resp = self.send_bytes(json.dumps(obj).encode("utf-8"))
        if resp is None:
            raise ConnectionError("service closed the connection")
        return resp

    def call(self, command: str, ident: Identity | None = None, job_id: str | None = None,
             payload: dict | None = None, *, session_id: str | None = None) -> dict:
        req = {"protocol_version": PROTOCOL_VERSION, "request_id": f"r-{os.getpid()}-{next(_ids)}",
               "command": command, "payload": payload or {}}
        if ident is not None:
            req.update(session_id=ident.session_id, runtime_id=ident.runtime_id, generation=ident.generation,
                       artifact_id=ident.artifact_id)
        if session_id is not None:
            req["session_id"] = session_id
        if job_id is not None:
            req["job_id"] = job_id
        resp = self.send(req)
        if resp.get("status") != "OK":
            err = resp.get("error") or {}
            raise ScannerError(err.get("code", "UNKNOWN"), err.get("message", ""), retryable=bool(err.get("retryable")))
        return resp["result"]

    # -- helpers -------------------------------------------------------------
    def health(self, selftest: bool = False) -> dict:
        return self.call("HEALTH_CHECK", payload={"selftest": True} if selftest else {})

    def upload(self, ident: Identity, file_name: str, data: bytes, *, chunk: int = 64 * 1024) -> dict:
        job = self.call("BEGIN_UPLOAD", ident, payload={"file_name": file_name, "size": len(data),
                                                          "sha256": hashlib.sha256(data).hexdigest()})
        jid = job["job_id"]
        for off in range(0, len(data), chunk):
            self.call("WRITE_CHUNK", ident, jid, {"offset": off,
                                                  "data": base64.b64encode(data[off:off + chunk]).decode("ascii")})
        return self.call("COMPLETE_UPLOAD", ident, jid)

    def wait(self, ident: Identity, job_id: str, states: tuple[str, ...], timeout_s: float = 180.0) -> dict:
        deadline = time.monotonic() + timeout_s
        while True:
            view = self.call("GET_STATUS", ident, job_id)
            if view["state"] in states or (view.get("outcome") and view["outcome"] in states):
                return view
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{job_id} still {view['state']} after {timeout_s:.0f}s")
            time.sleep(0.2)

    def scan(self, ident: Identity, job_id: str, timeout_s: float = 180.0) -> dict:
        self.call("SCAN", ident, job_id)
        return self.wait(ident, job_id, ("SCANNED", "BLOCKED", "FAILED", "CANCELLED", "DISPOSED"), timeout_s)

    def publish(self, ident: Identity, job: dict, approved_by: str = "test-approval") -> dict:
        approval = {"approved": True, "approval_id": f"test-{job['job_id'][4:16]}", "approved_by": approved_by,
                    "job_id": job["job_id"], "artifact_id": ident.artifact_id, "session_id": ident.session_id,
                    "sha256": job["sha256"]}
        return self.call("PUBLISH", ident, job["job_id"], {"approval": approval})
