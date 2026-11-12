"""Inspection of a received artifact before it may leave the Host's quarantine.

Two steps, both on the same bytes the receiver fixed (their SHA-256 is checked
first, so what is inspected is exactly what was received):

1. Format policy (artifact-export-v1 demo policy, contract §3): a regular
   UTF-8 text file with a .txt name. Allowing a format is not a safety claim.
2. Antivirus, through a Scanner. Which engine the team uses is not decided yet,
   so the default is NoScanner: every file is BLOCKED with SCANNER_UNAVAILABLE.
   A missing, failing or slow scanner is never a pass (contract §10).

AmsiScanner asks the antivirus registered with Windows AMSI (Defender, or a
third-party product that registers as an AMSI provider) to scan the bytes in
memory. "Not detected" alone proves nothing: with no provider, or a provider
that ignores this application, AMSI answers "not detected" without any engine
having looked (seen on a Host whose McAfee AMSI plugin passes the EICAR test
string). So before first use it scans the EICAR test string, in memory only;
unless that is detected the scanner counts as unavailable and every file is
BLOCKED. It never cleans or modifies the file; a detection blocks the export.

DefenderServiceScanner (--artifact-scanner defender-service) hands the work to the separate
SecureArtifactScanner Windows service: the bytes are streamed there instead of into a Host file,
scanned with Microsoft Defender as a non-admin service account, and published by the service.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

log = logging.getLogger("host-artifact-scan")

ALLOWED_SUFFIXES = (".txt",)
SCAN_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class Verdict:
    ok: bool
    code: str            # PASSED / FORMAT_NOT_ALLOWED / NOT_UTF8 / MALWARE_DETECTED / SCANNER_UNAVAILABLE /
                         # SCAN_ERROR / SCAN_TIMEOUT / CONTENT_CHANGED
    detail: str
    engine: str | None = None


def check_format(relative_path: str, data: bytes) -> Verdict | None:
    """None if the demo format policy allows it, else the reason it does not."""
    name = PureWindowsPath(relative_path).name
    if not name.lower().endswith(ALLOWED_SUFFIXES):
        return Verdict(False, "FORMAT_NOT_ALLOWED", f"only {', '.join(ALLOWED_SUFFIXES)} files are exported")
    if b"\x00" in data:
        return Verdict(False, "NOT_UTF8", "contains NUL bytes; not a text file")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        return Verdict(False, "NOT_UTF8", f"not valid UTF-8 at byte {e.start}")
    return None


class NoScanner:
    """No antivirus configured: nothing may pass."""
    name = "none"

    def available(self) -> tuple[bool, str]:
        return False, "no antivirus scanner is configured for artifact export (--artifact-scanner)"

    def scan(self, data: bytes, content_name: str) -> Verdict:
        return Verdict(False, "SCANNER_UNAVAILABLE", self.available()[1])


def _eicar() -> bytes:
    """The standard antivirus test string, assembled in memory (never written to disk)."""
    return ("X5O!P%@AP[4" + "\\" + "PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


class AmsiScanner:
    """The antivirus registered with Windows AMSI, trusted only after it detects EICAR."""
    name = "amsi"

    def __init__(self):
        self._selftest: tuple[bool, str] | None = None
    APP = "SCRP-Host-ArtifactExport"
    DETECTED = 32768                              # AMSI_RESULT_DETECTED and above
    BLOCKED_BY_ADMIN = range(0x4000, 0x5000)

    def providers(self) -> list[str]:
        if sys.platform != "win32":
            return []
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\AMSI\Providers")
        except OSError:
            return []
        out, i = [], 0
        with key:
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    return out
                i += 1

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, "AMSI exists only on Windows"
        found = self.providers()
        if not found:
            return False, "no antivirus is registered with AMSI on this Host"
        if self._selftest is None:
            v = self._scan_raw(_eicar(), "eicar-selftest.txt")
            self._selftest = (True, f"{len(found)} AMSI provider(s), EICAR self-test detected")                 if v.code == "MALWARE_DETECTED" else                 (False, f"AMSI provider(s) did not detect the EICAR test string ({v.detail}); "
                        "no engine is scanning this application's content")
            log.info("AMSI self-test: %s", self._selftest[1])
        return self._selftest

    def scan(self, data: bytes, content_name: str) -> Verdict:
        ok, why = self.available()
        if not ok:
            return Verdict(False, "SCANNER_UNAVAILABLE", why, self.name)
        return self._scan_raw(data, content_name)

    def _scan_raw(self, data: bytes, content_name: str) -> Verdict:
        if not data:
            # Nothing for an engine to look at; AMSI rejects a zero-length buffer.
            return Verdict(True, "PASSED", "empty file (0 bytes): nothing to scan", self.name)
        import ctypes
        from ctypes import wintypes
        amsi = ctypes.WinDLL("amsi.dll")
        ctx, session, result = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_int()
        hr = amsi.AmsiInitialize(ctypes.c_wchar_p(self.APP), ctypes.byref(ctx))
        if hr != 0:
            return Verdict(False, "SCAN_ERROR", f"AmsiInitialize failed (0x{hr & 0xFFFFFFFF:08X})", self.name)
        try:
            hr = amsi.AmsiOpenSession(ctx, ctypes.byref(session))
            if hr != 0:
                return Verdict(False, "SCAN_ERROR", f"AmsiOpenSession failed (0x{hr & 0xFFFFFFFF:08X})", self.name)
            try:
                buf = ctypes.create_string_buffer(data, len(data))
                hr = amsi.AmsiScanBuffer(ctx, buf, wintypes.ULONG(len(data)), ctypes.c_wchar_p(content_name),
                                         session, ctypes.byref(result))
                if hr != 0:
                    return Verdict(False, "SCAN_ERROR", f"AmsiScanBuffer failed (0x{hr & 0xFFFFFFFF:08X})",
                                   self.name)
            finally:
                amsi.AmsiCloseSession(ctx, session)
        finally:
            amsi.AmsiUninitialize(ctx)
        r = result.value
        if r >= self.DETECTED:
            return Verdict(False, "MALWARE_DETECTED", f"antivirus reported a detection (AMSI result {r})", self.name)
        if r in self.BLOCKED_BY_ADMIN:
            return Verdict(False, "MALWARE_DETECTED", f"blocked by administrator policy (AMSI result {r})",
                           self.name)
        if r in (0, 1):                          # AMSI_RESULT_CLEAN / AMSI_RESULT_NOT_DETECTED
            return Verdict(True, "PASSED", f"no detection (AMSI result {r})", self.name)
        return Verdict(False, "SCAN_ERROR", f"unexpected AMSI result {r}", self.name)


class DefenderServiceScanner:
    """Microsoft Defender through the SecureArtifactScanner Windows service (scanner_service/).

    The bytes never sit in the Host process or on its disk: ArtifactGrants streams the upload
    into a service job, the service scans it with MpCmdRun.exe as a non-admin service account
    (format policy included: the same check_format), and publishes it into the export folder.
    This class checks the service and turns its job results into Verdicts.

    A missing, stopped or misconfigured service is never a pass: exports are refused before the
    approval prompt (ArtifactBroker.precheck), and a job whose result is unclear is BLOCKED.
    """
    name = "defender-service"
    service_mode = True
    POLL_S = 0.25
    RECHECK_S = 15.0

    SERVICE_ACCOUNT = "NT SERVICE\\SecureArtifactScanner"

    def __init__(self, client=None, *, scan_timeout_s: float = 300.0, expected_account: str | None = SERVICE_ACCOUNT):
        self.expected_account = expected_account     # None: tests run the service code as the current user
        if client is None:
            from host.scanner_client import ScannerServiceClient
            client = ScannerServiceClient()
        self.client = client
        self.scan_timeout_s = scan_timeout_s     # the service's own MpCmdRun limit is 120 s, plus its self-test
        self._state: tuple[bool, str] = (False, "the scanner service has not been checked yet")

    def available(self) -> tuple[bool, str]:
        return self._state

    def scan(self, data: bytes, content_name: str) -> Verdict:
        return Verdict(False, "SCANNER_UNAVAILABLE", "defender-service scans service jobs, not Host bytes", self.name)

    async def refresh(self, export_dir: Path) -> tuple[bool, str]:
        """HEALTH_CHECK: running as a non-admin account, Defender usable, publishing into export_dir."""
        from host.scanner_client import ScannerServiceError
        try:
            h = await self.client.health()
        except ScannerServiceError as e:
            self._state = (False, e.message)
            return self._state
        tok, d, pub = h.get("token") or {}, h.get("defender") or {}, h.get("publish") or {}
        root = pub.get("export_root")
        account = str(tok.get("account") or "")
        if tok.get("is_admin") or tok.get("is_local_system") or (self.expected_account and tok.get("administrators_group")):
            st = (False, f"the scanner service runs with administrator rights ({account}); refused")
        elif self.expected_account and account.lower() != self.expected_account.lower():
            st = (False, f"the scanner service runs as {account}, not {self.expected_account}; refused")
        elif not h.get("accepting"):
            st = (False, "the scanner service is stopping")
        elif not d.get("available"):
            st = (False, f"Microsoft Defender is not usable by the scanner service: {d.get('problem')}")
        elif not pub.get("enabled"):
            st = (False, f"the scanner service cannot publish: {pub.get('problem') or 'disabled'}")
        elif not root or os.path.normcase(os.path.abspath(root)) != os.path.normcase(os.path.abspath(export_dir)):
            st = (False, f"the scanner service publishes into {root}, not this Host's export folder {export_dir} "
                         "(reinstall it with installer\\install.ps1 -ExportRoot <export folder>)")
        else:
            st = (True, f"SecureArtifactScanner {h.get('version')} as {tok.get('account')}, Defender "
                        f"{d.get('platform_version')} sig {d.get('signature_version')}")
        if st != self._state:
            (log.info if st[0] else log.error)("scanner service %s: %s", "ready" if st[0] else "NOT usable", st[1])
        self._state = st
        return st

    async def keep_checking(self, export_dir: Path) -> None:
        while True:
            await asyncio.sleep(self.RECHECK_S)
            await self.refresh(export_dir)

    async def inspect_job(self, grant, relative_path: str, still_wanted=lambda: True) -> Verdict:
        """SCAN the grant's service job and wait for its verdict. Never raises; failures are verdicts."""
        from host.scanner_client import ScannerServiceError, job_identity
        if getattr(grant, "scanner_verdict", None) is not None:     # refused already when the upload completed
            return grant.scanner_verdict
        if grant.scanner_job_id is None:
            return Verdict(False, "SCAN_ERROR", "no scanner job for the received file", self.name)
        ident = job_identity(grant.identity, grant.artifact_id)
        job = grant.scanner_job_id
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.scan_timeout_s
        try:
            view = await self.client.scan(ident, job)
            while view["state"] == "SCANNING" or (view["state"] == "RECEIVED" and view.get("outcome") is None):
                if not still_wanted():
                    return Verdict(False, "CANCELLED", "export cancelled during the scan", self.name)
                if loop.time() >= deadline:
                    self.client.abort_soon(ident, job, "Host scan timeout")
                    return Verdict(False, "SCAN_TIMEOUT", f"no scan result within {self.scan_timeout_s:.0f}s",
                                   self.name)
                await asyncio.sleep(self.POLL_S)
                view = await self.client.status(ident, job)
        except ScannerServiceError as e:
            code = "SCANNER_UNAVAILABLE" if e.code == "SCANNER_UNAVAILABLE" else "SCAN_ERROR"
            return Verdict(False, code, f"scanner service: {e.message}", self.name)
        scan = view.get("scan") or {}
        if view["state"] == "SCANNED":
            if (view.get("size"), view.get("sha256")) != (grant.size, grant.sha256):
                return Verdict(False, "CONTENT_CHANGED", "the scanner service holds other bytes than were received",
                               self.name)
            if scan.get("verdict") != "CLEAN":
                return Verdict(False, "SCAN_ERROR", f"unexpected scan verdict {scan.get('verdict')}", self.name)
            return Verdict(True, "PASSED", f"Microsoft Defender: {scan.get('detail')}", self.name)
        err = view.get("error") or {}
        if view.get("outcome") == "BLOCKED" and err.get("code"):
            return Verdict(False, err["code"], f"scanner service: {err.get('message')}", self.name)
        return Verdict(False, "SCAN_ERROR", f"scanner job ended {view.get('outcome') or view['state']} "
                                            f"({err.get('code')}: {err.get('message')})", self.name)


def make_scanner(name: str, **kw):
    if name == "none":
        return NoScanner()
    if name == "amsi":
        return AmsiScanner()
    if name == "defender-service":
        return DefenderServiceScanner(**kw)
    raise ValueError(f"unknown scanner {name!r}")


async def inspect(path: Path, relative_path: str, expected_sha256: str, scanner,
                  timeout_s: float = SCAN_TIMEOUT_S) -> Verdict:
    """Format policy and antivirus on the received file. Never raises; failures are verdicts."""
    try:
        data = await asyncio.to_thread(path.read_bytes)
    except OSError as e:
        # e.g. a real-time antivirus on the Host quarantined it after it was written
        return Verdict(False, "CONTENT_CHANGED", f"received file can no longer be read ({type(e).__name__})")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        return Verdict(False, "CONTENT_CHANGED", "received file changed after it was fixed")
    bad = check_format(relative_path, data)
    if bad is not None:
        return bad
    try:
        return await asyncio.wait_for(asyncio.to_thread(scanner.scan, data, PureWindowsPath(relative_path).name),
                                      timeout_s)
    except asyncio.TimeoutError:
        return Verdict(False, "SCAN_TIMEOUT", f"no scan result within {timeout_s:.0f}s",
                       getattr(scanner, "name", None))
    except Exception as e:  # noqa: BLE001 - a broken scanner is a failed scan, not a pass
        return Verdict(False, "SCAN_ERROR", f"{type(e).__name__}: {e}", getattr(scanner, "name", None))
