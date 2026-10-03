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
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
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


def make_scanner(name: str):
    if name == "none":
        return NoScanner()
    if name == "amsi":
        return AmsiScanner()
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
