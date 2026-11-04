"""Signature check for inbox_download --signed-downloads: does this download carry a valid, publicly trusted signature?

Design (2026-11-03 멘토링, 서명 검사와 격리 폴더): a downloaded program with a valid Authenticode signature may
also go to the user's Downloads folder; everything else stays only in the inbox (deny-execute on the Host, run
in the Sandbox). By default any signer passes whose chain ends in a root of the machine stores, the rule
Windows 11 Smart App Control uses for consumers when its cloud service cannot judge an app; since 2023 the
CA/Browser Forum requires those code-signing keys in hardware (FIPS 140-2 Level 2). --trusted-publishers
narrows it to a list (B2B). Ported from the 10/31 speed experiment
(experiments/speed-2026-10-31/fastpath.py, L2 by publisher), with what the review found missing:
  - only .exe and .msi are judged; a script is code whatever its signature says
  - programs that run other code are refused even when signed: Microsoft's recommended block rules plus
    interpreters (Survivalism, IEEE S&P 2021: living-off-the-land in 9.41% of 31.8M samples), by file name AND
    by the OriginalFileName in the version resource, so a renamed powershell.exe does not pass (ATT&CK T1036.003)
  - remote control tools are refused by name or signer (CISA AA23-025A)
  - nothing may follow the signature (CVE-2013-3900: Windows accepts bytes appended inside the certificate
    table unless EnableCertPaddingCheck is set, and the 3CX attack used that)
  - the chain must end in a root of the machine stores (LocalMachine Root or AuthRoot); a root only in the
    current user's store is something any program of this user, the Agent included, can add
  - revocation is checked over the network; when it cannot be checked within the time limit, not trusted

"Trusted" here means "a valid, publicly trusted signature (of a listed publisher, if listed)", never "safe": a publisher whose build was
compromised (SolarWinds 2020, 3CX 2023) signs genuine malware. That is EDR territory (보호 경계).
"""

from __future__ import annotations

import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

CHECKED_SUFFIXES = {".exe", ".msi"}
# Microsoft recommended block rules, user mode, executables (Microsoft Learn "Applications that can bypass
# App Control", fetched 2026-11-05): Microsoft-signed programs that run code they are given.
MICROSOFT_BLOCK_RULES = {
    "addinprocess.exe", "addinprocess32.exe", "addinutil.exe", "aspnet_compiler.exe", "bash.exe", "bginfo.exe",
    "cdb.exe", "cscript.exe", "csi.exe", "dbghost.exe", "dbgsvc.exe", "dbgsrv.exe", "dnx.exe", "dotnet.exe",
    "fsi.exe", "fsianycpu.exe", "infdefaultinstall.exe", "kd.exe", "kill.exe", "lxrun.exe",
    "microsoft.workflow.compiler.exe", "msbuild.exe", "mshta.exe", "ntkd.exe", "ntsd.exe", "powershellcustomhost.exe",
    "rcsi.exe", "runscripthelper.exe", "texttransform.exe", "visualuiaverifynative.exe", "wfc.exe", "windbg.exe",
    "wmic.exe", "wscript.exe", "wsl.exe", "wslconfig.exe", "wslhost.exe",
}
# Interpreters and system proxies not on that list (ATT&CK T1059, T1218 / LOLBAS; Survivalism, IEEE S&P 2021).
RUNS_OTHER_CODE = MICROSOFT_BLOCK_RULES | {
    "python.exe", "pythonw.exe", "py.exe", "pyw.exe", "pwsh.exe", "powershell.exe", "powershell_ise.exe", "cmd.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe",
    "certutil.exe", "bitsadmin.exe", "forfiles.exe", "node.exe", "java.exe", "javaw.exe", "conhost.exe",
    "explorer.exe",
}
# Remote control tools: signed, not detected by antivirus, and they hand this computer to whoever is on the
# other end (CISA AA23-025A: AnyDesk and ScreenConnect in the October 2022 refund scam). Matched as parts of
# the file name, the OriginalFileName or the signer. Not a complete list.
REMOTE_CONTROL = ("anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "rustdesk", "supremo",
                  "nanosystems", "ultraviewer", "ammyy", "ateraagent", "atera networks", "rutserv", "rutview", "remote utilities")
# None: any valid signature that chains to a root of the machine stores, like Windows 11 Smart App Control
# for an app its cloud service cannot judge (B2C). A list (--trusted-publishers, B2B) narrows it to those signers.
TRUSTED_PUBLISHERS = None
REVOCATION_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class Verdict:
    trusted: bool
    signer: str | None
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Signature:
    """What WinVerifyTrust said about one file."""
    status: int                     # WinVerifyTrust result, unsigned 32-bit; 0 = valid
    signer: str | None              # leaf certificate's simple display name
    machine_root: bool              # the chain's root is in LocalMachine Root or AuthRoot


def check(path: Path, publishers=TRUSTED_PUBLISHERS, *, revocation: bool = True,
          timeout_s: float = REVOCATION_TIMEOUT_S, verify: Callable | None = None) -> Verdict:
    """The verdict for one file. The caller keeps the file from changing (a deny-write handle) until it is
    done with the bytes it copies, so the checked bytes are the copied bytes."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in CHECKED_SUFFIXES:
        return Verdict(False, None, f"only .exe and .msi are checked, not {suffix or 'a file without extension'}")
    if verify is None and sys.platform != "win32":
        return Verdict(False, None, "signature checks need Windows")
    if path.name.lower() in RUNS_OTHER_CODE:
        return Verdict(False, None, f"{path.name} runs other code; signed or not, it stays in the inbox")
    if _remote_control(path.name):
        return Verdict(False, None, f"{path.name} is a remote control tool; signed or not, it stays in the inbox")
    if suffix == ".exe":
        original = original_file_name(path)
        if original and original.lower() in RUNS_OTHER_CODE:
            return Verdict(False, None, f"this is {original} renamed; it runs other code and stays in the inbox")
        if original and _remote_control(original):
            return Verdict(False, None, f"this is {original} renamed; a remote control tool stays in the inbox")
        why = certificate_table_problem(path)
        if why:
            return Verdict(False, None, why)
    sig = _verify_in_time(verify or (lambda p: winverifytrust(p, revocation)), path, timeout_s)
    if sig is None:
        return Verdict(False, None, f"the signature could not be checked within {timeout_s:.0f}s (revocation)")
    if sig.status != 0:
        return Verdict(False, sig.signer, _status_text(sig.status))
    if not sig.machine_root:
        return Verdict(False, sig.signer, "the signing chain ends in a root this computer's user added, "
                                          "not one of the machine's trusted roots")
    if _remote_control(sig.signer or ""):
        return Verdict(False, sig.signer, f"signed by {sig.signer}, a remote control vendor; it stays in the inbox")
    if publishers is not None and sig.signer not in publishers:
        return Verdict(False, sig.signer, f"signed by {sig.signer}, which is not on the trusted publisher list")
    return Verdict(True, sig.signer, f"valid signature of {sig.signer}")


def _remote_control(name: str) -> bool:
    low = name.lower()
    return any(word in low for word in REMOTE_CONTROL)


def load_publishers(path: Path) -> list[str]:
    """--trusted-publishers: a UTF-8 JSON list of signer names (the certificate's simple display name)."""
    import json
    names = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(names, list) or not names or not all(isinstance(n, str) and n.strip() for n in names):
        raise ValueError(f"{path}: expected a non-empty JSON list of signer names")
    return [n.strip() for n in names]


def _verify_in_time(verify: Callable, path: Path, timeout_s: float) -> Signature | None:
    """WinVerifyTrust has no time limit of its own (revocation fetches can hang on a bad network)."""
    box: list = []

    def run():
        try:
            box.append(verify(path))
        except OSError as e:
            box.append(e)

    t = threading.Thread(target=run, name="signature-check", daemon=True)
    t.start()
    t.join(timeout_s)
    if not box:
        return None
    if isinstance(box[0], OSError):
        return Signature(0xFFFFFFFF, None, False)
    return box[0]


TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0100, 0x800B0003
REVOCATION_UNKNOWN = {0x800B010E, 0x80092013}           # CERT_E_REVOCATION_FAILURE, CRYPT_E_REVOCATION_OFFLINE


def _status_text(status: int) -> str:
    if status in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN):
        return "not signed"
    if status in REVOCATION_UNKNOWN:
        return "whether the certificate was revoked could not be checked"
    if status == 0x800B010C:                              # CERT_E_REVOKED
        return "the signing certificate was revoked"
    return f"the signature is not valid (0x{status:08X})"


def certificate_table_problem(path: Path) -> str | None:
    """None, or why the PE certificate table is suspicious: anything after it, or bytes appended inside it
    beyond the signature blob (what EnableCertPaddingCheck refuses). An unsigned PE has no table: None."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return f"could not read the file ({type(e).__name__})"
    if data[:2] != b"MZ" or len(data) < 0x40:
        return "not a Windows program (no MZ header)"
    pe = int.from_bytes(data[0x3C:0x40], "little")
    if data[pe:pe + 4] != b"PE\0\0":
        return "not a Windows program (no PE header)"
    opt = pe + 24
    magic = int.from_bytes(data[opt:opt + 2], "little")
    dirs = opt + (96 if magic == 0x10B else 112 if magic == 0x20B else -1)
    if dirs < opt:
        return "not a Windows program (unknown optional header)"
    sec = dirs + 4 * 8                                     # IMAGE_DIRECTORY_ENTRY_SECURITY
    offset = int.from_bytes(data[sec:sec + 4], "little")
    size = int.from_bytes(data[sec + 4:sec + 8], "little")
    if size == 0:
        return None
    if offset + size != len(data):
        return "data follows the signature"
    at = offset
    while at < offset + size:
        length = int.from_bytes(data[at:at + 4], "little")
        blob = data[at + 8:at + length]
        der = _der_length(blob)
        if length < 8 or der is None or der > len(blob):
            return "the signature table is malformed"
        slack = blob[der:]
        if len(slack) >= 8 or slack.strip(b"\0"):
            return "bytes were added inside the signature table (CVE-2013-3900)"
        at += (length + 7) & ~7
    return None


def _der_length(blob: bytes) -> int | None:
    if len(blob) < 2 or blob[0] != 0x30:
        return None
    if blob[1] < 0x80:
        return 2 + blob[1]
    n = blob[1] & 0x7F
    if n == 0 or n > 4 or len(blob) < 2 + n:
        return None
    return 2 + n + int.from_bytes(blob[2:2 + n], "big")


# ---- Windows APIs ---------------------------------------------------------------------------------------

def original_file_name(path: Path) -> str | None:
    """OriginalFileName from the version resource (what the maker named it), or None."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes as wt
    ver = ctypes.WinDLL("version")
    size = ver.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(str(path), 0, size, buf):
        return None
    ptr, n = ctypes.c_void_p(), wt.UINT()
    if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(n)) or not n.value:
        langs = [(0x0409, 0x04B0)]
    else:
        words = (wt.WORD * (n.value // 2)).from_address(ptr.value)
        langs = [(words[i], words[i + 1]) for i in range(0, len(words) - 1, 2)]
    for lang, cp in langs:
        key = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\OriginalFileName"
        if ver.VerQueryValueW(buf, key, ctypes.byref(ptr), ctypes.byref(n)) and n.value:
            name = ctypes.wstring_at(ptr.value, n.value).rstrip("\0").strip()
            return (name[:-4] if name.lower().endswith(".mui") else name) or None
    return None


def winverifytrust(path: Path, revocation: bool = True) -> Signature:
    import ctypes
    import uuid
    from ctypes import wintypes as wt
    wintrust, crypt32 = ctypes.WinDLL("wintrust"), ctypes.WinDLL("crypt32")

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wt.DWORD), ("pcwszFilePath", wt.LPCWSTR), ("hFile", wt.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wt.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wt.DWORD), ("fdwRevocationChecks", wt.DWORD),
                    ("dwUnionChoice", wt.DWORD), ("pFile", ctypes.POINTER(FILE_INFO)), ("dwStateAction", wt.DWORD),
                    ("hWVTStateData", wt.HANDLE), ("pwszURLReference", wt.LPCWSTR), ("dwProvFlags", wt.DWORD),
                    ("dwUIContext", wt.DWORD), ("pSignatureSettings", ctypes.c_void_p)]

    class HASH_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.c_void_p)]

    u = uuid.UUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")          # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WinVerifyTrust.argtypes = [wt.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wintrust.WTHelperProvDataFromStateData.argtypes = [wt.HANDLE]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD]
    wintrust.WTHelperGetProvCertFromChain.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p, wt.DWORD]
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    crypt32.CertGetCertificateContextProperty.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p,
                                                          ctypes.POINTER(wt.DWORD)]
    crypt32.CertOpenStore.restype = ctypes.c_void_p
    crypt32.CertOpenStore.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.LPCWSTR]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                                   ctypes.c_void_p]
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wt.DWORD]

    fi = FILE_INFO(ctypes.sizeof(FILE_INFO), str(path), None, None)
    wd = DATA()
    wd.cbStruct = ctypes.sizeof(DATA)
    wd.dwUIChoice = 2                                     # WTD_UI_NONE
    wd.fdwRevocationChecks = 1 if revocation else 0       # WTD_REVOKE_WHOLECHAIN / WTD_REVOKE_NONE
    wd.dwUnionChoice = 1                                  # WTD_CHOICE_FILE
    wd.pFile = ctypes.pointer(fi)
    wd.dwStateAction = 1                                  # WTD_STATEACTION_VERIFY
    # WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, or WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
    wd.dwProvFlags = 0x80 if revocation else 0x1000 | 0x10
    no_ui = wt.HWND(ctypes.c_void_p(-1).value)
    status = wintrust.WinVerifyTrust(no_ui, ctypes.byref(action), ctypes.byref(wd)) & 0xFFFFFFFF
    signer, machine_root = None, False
    try:
        prov = wintrust.WTHelperProvDataFromStateData(wd.hWVTStateData) if wd.hWVTStateData else None
        sgnr = wintrust.WTHelperGetProvSignerFromChain(prov, 0, False, 0) if prov else None
        if sgnr:
            ptr = ctypes.sizeof(ctypes.c_void_p)                     # CRYPT_PROVIDER_CERT.pCert offset
            leaf = wintrust.WTHelperGetProvCertFromChain(sgnr, 0)
            if leaf and (cert := ctypes.c_void_p.from_address(leaf + ptr).value):
                buf = ctypes.create_unicode_buffer(256)
                crypt32.CertGetNameStringW(cert, 4, 0, None, buf, 256)    # CERT_NAME_SIMPLE_DISPLAY_TYPE
                signer = buf.value or None
            chain_len = wt.DWORD.from_address(sgnr + 12).value            # CRYPT_PROVIDER_SGNR.csCertChain
            top = wintrust.WTHelperGetProvCertFromChain(sgnr, chain_len - 1) if chain_len else None
            root = ctypes.c_void_p.from_address(top + ptr).value if top else None
            if root:
                sha1, n = (ctypes.c_ubyte * 20)(), wt.DWORD(20)
                if crypt32.CertGetCertificateContextProperty(root, 3, sha1, ctypes.byref(n)):   # CERT_SHA1_HASH_PROP_ID
                    blob = HASH_BLOB(n.value, ctypes.cast(sha1, ctypes.c_void_p))
                    for name in ("Root", "AuthRoot"):
                        # CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE | READONLY | OPEN_EXISTING
                        store = crypt32.CertOpenStore(ctypes.c_void_p(10), 0, None, 0x20000 | 0x8000 | 0x4000, name)
                        if not store:
                            continue
                        found = crypt32.CertFindCertificateInStore(store, 0x10001, 0, 0x10000,  # CERT_FIND_SHA1_HASH
                                                                   ctypes.byref(blob), None)
                        if found:
                            crypt32.CertFreeCertificateContext(found)
                        crypt32.CertCloseStore(store, 0)
                        if found:
                            machine_root = True
                            break
    finally:
        wd.dwStateAction = 2                              # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(no_ui, ctypes.byref(action), ctypes.byref(wd))
    return Signature(status, signer, machine_root)
