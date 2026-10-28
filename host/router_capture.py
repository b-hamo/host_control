"""router_capture: command text seen on a web page, kept as untrusted data (#94).

GUI mode (mcp_server.py --router-capture), next to sandbox_run:

- Browsing stays on this computer (Router rule: browse = Local), in any browser.
  This module never opens the URL and never runs anything.
- The text can come from two places, recorded separately:
  the Agent's copy of what it saw (``text``), and this computer's clipboard
  read by the Host itself (``clipboard``). ClickFix pages show one thing and
  copy another, so only the Host's own clipboard read shows the command the
  page actually handed over. When both are given, whether they match is recorded.
- Each capture is a router ``Source`` (SHA-256 of the stored bytes, origin
  external). router_execute (sandbox_run.py) derives a script from it and runs
  that inside the Sandbox only.
- The source URL is the Agent's attribution, not verified here.

Clipboard provenance is a moment in time, not proof that no other program
wrote to the clipboard meanwhile.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from router.models import Source, identifier

MAX_TEXT_BYTES = 65536
MAX_CAPTURES = 128


class CaptureError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def clipboard_snapshot() -> dict:
    """This computer's clipboard text and its sequence number. Reads only; no fallback."""
    import ctypes
    from ctypes import wintypes
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    user.GetClipboardData.argtypes = [wintypes.UINT]
    user.GetClipboardData.restype = wintypes.HANDLE
    kernel.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel.GlobalLock.restype = ctypes.c_void_p
    kernel.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel.GlobalSize.argtypes = [wintypes.HGLOBAL]
    kernel.GlobalSize.restype = ctypes.c_size_t
    if not user.OpenClipboard(None):
        raise CaptureError("RUNTIME_UNAVAILABLE", "the clipboard is busy; try again")
    try:
        sequence = user.GetClipboardSequenceNumber()
        handle = user.GetClipboardData(13)                 # CF_UNICODETEXT
        text = ""
        if handle:
            size = kernel.GlobalSize(handle)
            if not 0 < size <= 2 * MAX_TEXT_BYTES + 2:
                raise CaptureError("INVALID_ARGUMENT", "the clipboard text is larger than a capture may be")
            ptr = kernel.GlobalLock(handle)
            if not ptr:
                raise CaptureError("RUNTIME_UNAVAILABLE", "the clipboard could not be read")
            try:
                text = ctypes.string_at(ptr, size).decode("utf-16-le").split("\0", 1)[0]
            finally:
                kernel.GlobalUnlock(handle)
        return {"sequence": sequence, "text": text}
    finally:
        user.CloseClipboard()


def page_url(url: str) -> str:
    """The attribution as recorded: http(s), no credentials, no query (a signed URL's query is a secret)."""
    try:
        u = urlsplit(url)
    except ValueError:
        u = None
    if u is None or u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise CaptureError("INVALID_ARGUMENT", "source_url must be the http(s) page address, without credentials")
    return f"{u.scheme}://{u.netloc}{u.path}"


class CaptureStore:
    def __init__(self, directory: Path, *, clipboard=clipboard_snapshot):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.clipboard = clipboard
        self.sources: dict[str, tuple[Source, Path]] = {}
        self.from_clipboard: set[str] = set()              # source_ids the Host read itself
        self._requests: dict[str, tuple[str, dict]] = {}   # request_id -> (signature, result)
        self._seq = 0

    # -- the tool ------------------------------------------------------------
    def capture(self, args: dict) -> dict:
        request_id = args["request_id"]
        try:
            identifier(request_id)
        except ValueError:
            raise CaptureError("INVALID_ARGUMENT", "request_id: letters, digits, . _ - (up to 96)") from None
        signature = json.dumps(args, sort_keys=True, ensure_ascii=False)
        if request_id in self._requests:
            known, result = self._requests[request_id]
            if known != signature:
                raise CaptureError("IDEMPOTENCY_CONFLICT", f"{request_id} was already used with other arguments")
            return {**result, "repeated": True}            # the same capture, never taken again
        text, use_clipboard = args.get("text"), bool(args.get("clipboard"))
        if text is None and not use_clipboard:
            raise CaptureError("INVALID_ARGUMENT", "give the text you saw, clipboard=true, or both")
        if len(self._requests) >= MAX_CAPTURES:
            raise CaptureError("POLICY_DENIED", f"at most {MAX_CAPTURES} captures per session")
        url = page_url(args["source_url"])
        clip = None
        if use_clipboard:
            clip = self.clipboard()
            if not clip["text"]:
                raise CaptureError("INVALID_ARGUMENT", "the clipboard holds no text: click the page's copy button "
                                                       "first, then capture")
        self._seq += 1
        base = f"CAP-{self._seq:04d}"
        shown = []
        agent = host = None
        if text is not None:
            agent = self._store(f"{base}-AGENT", text, "agent-observed:" + url)
            shown.append(self._view(agent, "agent_text"))
        if clip is not None:
            host = self._store(f"{base}-CLIP", clip["text"], f"clipboard:host:{clip['sequence']}:{url}")
            self.from_clipboard.add(host.source_id)
            shown.append({**self._view(host, "host_clipboard"), "clipboard_sequence": clip["sequence"]})
        primary = host or agent
        result = {"request_id": request_id, "source_id": primary.source_id, "sources": shown, "source_url": url,
                  "trust": "external", "source_url_verified": False, "execution_location": "SANDBOX",
                  "clipboard_read_by_host": host is not None,
                  "agent_text_matches_clipboard": (None if agent is None or host is None
                                                   else agent.sha256 == host.sha256)}
        if result["agent_text_matches_clipboard"] is False:
            result["notice"] = ("The page copied something other than the text you saw. source_id is what the page "
                                "actually copied (read by the Host); analyze that one, never on this computer.")
        self._requests[request_id] = (signature, result)
        return dict(result)

    def query(self, request_id: str) -> dict | None:
        known = self._requests.get(request_id)
        return None if known is None else {**known[1], "repeated": True}

    # -- what router_execute may use -----------------------------------------
    def verify(self, src: Source) -> bool:
        known = self.sources.get(src.source_id)
        if known is None or known[0] != src:
            return False
        path = known[1]
        try:
            if path.is_symlink() or not path.is_file():
                return False
            return hashlib.sha256(path.read_bytes()).hexdigest() == src.sha256
        except OSError:
            return False

    def text(self, source_id: str) -> str:
        return self.sources[source_id][1].read_bytes().decode("utf-8")

    # -- storage ---------------------------------------------------------------
    def _store(self, source_id: str, text: str, reference: str) -> Source:
        raw = text.encode("utf-8")
        if not raw or len(raw) > MAX_TEXT_BYTES or "\0" in text:
            raise CaptureError("INVALID_ARGUMENT", f"capture text must be 1..{MAX_TEXT_BYTES} bytes without NUL")
        path = self.directory / f"{source_id}.txt"
        with path.open("xb") as stream:                    # never overwrites
            stream.write(raw)
        src = Source(source_id, reference, hashlib.sha256(raw).hexdigest(), "external")
        self.sources[source_id] = (src, path)
        return src

    @staticmethod
    def _view(src: Source, kind: str) -> dict:
        return {"source_id": src.source_id, "kind": kind, "sha256": src.sha256}
