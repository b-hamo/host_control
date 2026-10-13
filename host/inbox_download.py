"""inbox_download: the Host fetches one file into the shared inbox; the Agent runs it in the Sandbox only.

Router design (download on the Host, run in the Sandbox): the Agent never gets network or write
access on the Host. It asks this tool (through the Broker: policy, rate limit, audit) for one https
URL; the file lands in the inbox folder, which
  - is mapped read-only and live into the Sandbox at C:\\Inbox (Sandbox Manager prepare(inbox=...)),
  - carries a deny-execute ACE, so nothing in it runs on the Host (sandbox_manager tools/setup_inbox.ps1),
and the Guest copies each finished file to Desktop\\Input after checking its SHA-256.

Based on the Lifecycle team's demo tool (sandbox_manager acf5f9f tools/inbox_download.py), with:
  - connect to the address that was checked (no second DNS lookup: DNS rebinding cannot swap in a
    private address between the check and the connection); every redirect is checked the same way
  - no archive extraction on the Host: a .zip is unpacked inside the Sandbox
  - the downloaded file is marked as coming from the Internet (Zone.Identifier, ZoneId=3), so Windows
    and Office treat it as untrusted if someone opens it on the Host anyway
  - the inbox limits (files, total bytes) are checked before anything is written

Nothing downloaded is ever opened or run on the Host; it is only read to hash it.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import logging
import os
import re
import secrets
import shutil
import socket
import ssl
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Callable

log = logging.getLogger("host-inbox")

MAX_REDIRECTS = 5
FILE_MAX = 50 * 1024 * 1024          # = sandbox_manager config.INPUT_FILE_MAX
TOTAL_MAX = 200 * 1024 * 1024        # = config.INPUT_TOTAL_MAX
FILES_MAX = 200                      # = config.INBOX_FILES_MAX
DEADLINE_S = 45.0                    # whole download; inside the 60 s MCP call limit
GUEST_INBOX = r"C:\Inbox"
GUEST_INPUT = r"Desktop\Input"
INCOMPLETE_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".!ut")

Resolver = Callable[[str, int], list[str]]


class DownloadError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise DownloadError("INVALID_ARGUMENT", f"cannot resolve {host}: {e}") from None
    return list(dict.fromkeys(info[4][0].split("%")[0] for info in infos))


def safe_name(name: str, fallback: str = "download.bin") -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or fallback
    if name.lower().endswith(INCOMPLETE_SUFFIXES):
        name += ".bin"                                 # never hidden from the watcher by its name
    return name[:100]


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to one already-checked IP; certificate and SNI still checked against the host name."""

    def __init__(self, host: str, ip: str, port: int, context: ssl.SSLContext, timeout: float):
        super().__init__(host, port, context=context, timeout=timeout)
        self._ip = ip
        self._ctx = context

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


@dataclass
class Downloader:
    inbox: Path
    context: ssl.SSLContext | None = None
    downloads: Path | None = None        # inbox_import's source folder; None = the user's Downloads
    resolver: Resolver = resolve
    allow_private: bool = False          # tests only
    file_max: int = FILE_MAX
    deadline_s: float = DEADLINE_S

    def _check(self, url: str) -> tuple[urllib.parse.SplitResult, str]:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise DownloadError("INVALID_ARGUMENT", "only https URLs are allowed")
        if u.username or u.password:
            raise DownloadError("INVALID_ARGUMENT", "URLs with credentials are not allowed")
        addrs = self.resolver(u.hostname, u.port or 443)
        if not addrs:
            raise DownloadError("INVALID_ARGUMENT", f"cannot resolve {u.hostname}")
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if not ip.is_global and not self.allow_private:
                raise DownloadError("POLICY_DENIED", f"{u.hostname} resolves to a non-public address ({ip})")
        return u, addrs[0]                                # connect to exactly this one

    def _inbox_usage(self) -> tuple[int, int]:
        files = total = 0
        for root, _dirs, names in os.walk(self.inbox):
            for n in names:
                try:
                    total += os.lstat(os.path.join(root, n)).st_size
                    files += 1
                except OSError:
                    pass
        return files, total

    def fetch(self, url: str, staging: Path) -> tuple[Path, str]:
        ctx = self.context or ssl.create_default_context()
        deadline = time.monotonic() + self.deadline_s
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            u, ip = self._check(current)
            left = deadline - time.monotonic()
            if left <= 0:
                raise DownloadError("ACTION_TIMEOUT", f"download not finished within {self.deadline_s:.0f}s")
            conn = _PinnedHTTPS(u.hostname, ip, u.port or 443, ctx, timeout=min(left, 30.0))
            try:
                # Re-quote characters a sloppy server left raw (e.g. spaces in a redirect); keep %XX as is.
                safe = "/%:@!$&'()*+,;=-._~"
                path = urllib.parse.quote(u.path or "/", safe=safe) +                     (f"?{urllib.parse.quote(u.query, safe=safe + '?')}" if u.query else "")
                conn.request("GET", path, headers={"User-Agent": "SecureCUA-inbox/1.0", "Accept-Encoding": "identity"})
                resp = conn.getresponse()
                if resp.status in (301, 302, 303, 307, 308) and resp.getheader("Location"):
                    current = urllib.parse.urljoin(current, resp.getheader("Location"))
                    continue
                if resp.status != 200:
                    raise DownloadError("INVALID_ARGUMENT", f"HTTP {resp.status} from {u.hostname}")
                length = resp.getheader("Content-Length")
                if length is not None and int(length) > self.file_max:
                    raise DownloadError("INVALID_ARGUMENT", f"file is {length} bytes (limit {self.file_max})")
                name = safe_name(PureWindowsPath(urllib.parse.unquote(u.path)).name)
                out = staging / name
                total = 0
                with out.open("wb") as f:
                    while chunk := resp.read(1 << 16):
                        total += len(chunk)
                        if total > self.file_max:
                            raise DownloadError("INVALID_ARGUMENT", f"file is over {self.file_max} bytes")
                        if time.monotonic() > deadline:
                            raise DownloadError("ACTION_TIMEOUT",
                                                f"download not finished within {self.deadline_s:.0f}s")
                        f.write(chunk)
                if length is not None and total != int(length):
                    raise DownloadError("RUNTIME_UNAVAILABLE", f"download incomplete ({total} of {length} bytes)")
                return out, current
            except (OSError, http.client.HTTPException) as e:
                raise DownloadError("RUNTIME_UNAVAILABLE", f"download failed: {type(e).__name__}") from None
            finally:
                conn.close()
        raise DownloadError("INVALID_ARGUMENT", f"more than {MAX_REDIRECTS} redirects")

    def download(self, url: str) -> dict:
        """Fetch into a private staging folder, then place it in the inbox under a new name."""
        files, total = self._inbox_usage()
        if files >= FILES_MAX:
            raise DownloadError("POLICY_DENIED", f"inbox already holds {files} files (limit {FILES_MAX})")
        with tempfile.TemporaryDirectory(prefix="scrp-inbox-dl-") as tmp:
            got, final_url = self.fetch(url, Path(tmp))
            size = got.stat().st_size
            if total + size > TOTAL_MAX:
                raise DownloadError("POLICY_DENIED", f"inbox would exceed {TOTAL_MAX} bytes")
            digest = _sha256(got)
            try:
                dst = place(self.inbox, got.name, got)
            except OSError as e:
                raise DownloadError("RUNTIME_UNAVAILABLE", f"could not write into the inbox ({type(e).__name__})") from None
            mark_internet(dst, final_url)
        log.info("INBOX download %s -> %s (%d bytes, sha256=%s…)", _host_of(final_url), dst.name, size, digest[:12])
        return {"source": url, "final_url": final_url,
                "file": {"name": dst.name, "size": size, "sha256": digest},
                "sandbox_path": f"{GUEST_INPUT}\\{dst.name}", "inbox_path": f"{GUEST_INBOX}\\{dst.name}"}

    def import_local(self, name: str) -> dict:
        """inbox_import: copy a file the user already downloaded (directly in Downloads, by name only).

        Every check on the name and the file (no path, no link or hard link, finished, size, unchanged
        while copied) is sandbox_manager.import_to_inbox's; the original stays where it is."""
        from sandbox_manager import SandboxManagerError, import_to_inbox
        files, total = self._inbox_usage()
        if files >= FILES_MAX:
            raise DownloadError("POLICY_DENIED", f"inbox already holds {files} files (limit {FILES_MAX})")
        try:
            got = import_to_inbox(name, self.inbox, self.downloads)
        except SandboxManagerError as e:
            raise DownloadError(e.code, e.message) from None
        f = got["files"][0]
        if total + f["size"] > TOTAL_MAX:
            try:
                (self.inbox / f["name"]).unlink()
            except OSError:
                pass
            raise DownloadError("POLICY_DENIED", f"inbox would exceed {TOTAL_MAX} bytes")
        log.info("INBOX import %s -> %s (%d bytes, sha256=%s…)", name, f["name"], f["size"], f["sha256"][:12])
        return {"source": "Downloads\\" + Path(got["source"]).name, "file": f,
                "sandbox_path": f"{GUEST_INPUT}\\{f['name']}", "inbox_path": f"{GUEST_INBOX}\\{f['name']}"}

    def similar(self, url: str) -> list[str]:
        """Files directly in Downloads that look like the one at `url`: the same name, or one name starts
        the other ("tailscale-setup-1.102.4.exe" / "tailscale-setup-1.102.4-amd64.msi"). Names only."""
        from sandbox_manager.importer import downloads_folder
        want = PureWindowsPath(urllib.parse.unquote(urllib.parse.urlsplit(url).path)).stem.lower()
        if len(want) < 6:
            return []
        try:
            entries = list((self.downloads or downloads_folder()).iterdir())
        except OSError:
            return []
        found = [p.name for p in entries if p.is_file() and len(p.stem) >= 6
                 and (p.stem.lower() == want or want.startswith(p.stem.lower()) or p.stem.lower().startswith(want))]
        return sorted(found)[:5]

    def finish(self, keep: list[str]) -> dict:
        """inbox_finish: copy the kept items to Downloads (marked as from the Internet), then empty the inbox.
        Copied, not moved: a moved file would carry the inbox's deny-execute ACE along. If any name is
        refused, nothing is kept or deleted (sandbox_manager.finish_inbox)."""
        from sandbox_manager import SandboxManagerError, finish_inbox
        try:
            done = finish_inbox(self.inbox, keep, self.downloads)
        except SandboxManagerError as e:
            raise DownloadError(e.code, e.message) from None
        log.info("INBOX finish: kept %s, deleted %d files", [k["to"] for k in done["kept"]], done["deleted_files"])
        return done


def place(inbox: Path, name: str, content: Path | bytes) -> Path:
    """Create a new file in the inbox and fill it under a handle that shares nothing.

    A running Sandbox maps the inbox live, and while it does, nothing can be renamed or moved
    into it (sharing violation), so a file is never written elsewhere and renamed in. It is
    written in place instead, and until it is complete and closed nobody else (the Guest's
    watcher included) can open it: a half-written file is never read. Never overwrites."""
    for _ in range(20):
        dst = _unique(inbox, name)
        try:
            stream = _create_exclusive(dst)
        except FileExistsError:
            continue                                   # taken meanwhile: next free name
        try:
            with stream:
                if isinstance(content, bytes):
                    stream.write(content)
                else:
                    with open(content, "rb") as src:
                        shutil.copyfileobj(src, stream, 1024 * 1024)
        except BaseException:
            dst.unlink(missing_ok=True)
            raise
        return dst
    raise OSError(f"no free name for {name} in the inbox")


def _create_exclusive(path: Path):
    if sys.platform != "win32":
        return open(path, "xb")
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    GENERIC_WRITE, NO_SHARING, CREATE_NEW, FILE_ATTRIBUTE_NORMAL = 0x40000000, 0, 1, 0x80
    h = k32.CreateFileW(str(path), GENERIC_WRITE, NO_SHARING, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
    if h in (None, wintypes.HANDLE(-1).value):
        err = ctypes.get_last_error()
        if err in (80, 183):                           # ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS
            raise FileExistsError(str(path))
        raise ctypes.WinError(err)
    return os.fdopen(msvcrt.open_osfhandle(h, os.O_WRONLY | os.O_BINARY), "wb")


def mark_internet(path: Path, url: str) -> None:
    """Mark-of-the-Web: Windows SmartScreen and Office Protected View treat the file as from the Internet."""
    if sys.platform != "win32":
        return
    try:
        with open(f"{path}:Zone.Identifier", "w", encoding="ascii", errors="replace") as f:
            f.write(f"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={_strip_query(url)}\r\n")
    except OSError as e:
        log.warning("could not mark %s as downloaded: %s", path.name, e)


def check_no_execute(inbox: Path) -> tuple[bool, str]:
    """Is the deny-execute ACE really in force? Copy a harmless system program in and try to run it."""
    if sys.platform != "win32":
        return False, "the inbox needs Windows (deny-execute ACL)"
    import subprocess
    probe = Path(inbox) / f"scrp-probe-{secrets.token_hex(4)}.exe.part"
    exe = probe.with_suffix("")                          # *.exe; created via the .part name first
    try:
        shutil.copyfile(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "whoami.exe", probe)
        os.replace(probe, exe)
        try:
            subprocess.run([str(exe)], capture_output=True, timeout=10)
        except PermissionError:
            return True, "programs in the inbox cannot run on this computer"
        except OSError as e:
            if getattr(e, "winerror", None) == 5:          # ERROR_ACCESS_DENIED
                return True, "programs in the inbox cannot run on this computer"
            return False, f"could not test the inbox: {e}"
        return False, ("a program in the inbox still runs on this computer: run "
                       "sandbox_manager tools/setup_inbox.ps1 for this folder first")
    finally:
        for p in (probe, exe):
            try:
                p.unlink()
            except OSError:
                pass


def _unique(folder: Path, name: str) -> Path:
    p = folder / name
    stem, suffix, n = p.stem, p.suffix, 1
    while p.exists():
        n += 1
        p = folder / f"{stem}-{n}{suffix}"
    return p


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _strip_query(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((u.scheme, u.hostname or "", u.path, "", ""))


def _host_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or "?"
