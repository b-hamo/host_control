"""Screenshot uploads: one-time upload_ids, receiving, validation (protocol doc §8).

    Host ── OBSERVE {upload_id} ──wss──▶ Runner
    Runner ── PUT /scrp/v1/observations/<upload_id> (PNG) ──https──▶ Host   (upload_server.py)
    Runner ── OBSERVE_RESULT {sha256, width, height, upload_id} ──wss──▶ Host
    Host: the PNG must be there, and match the result, before the Agent sees it

- upload_id is the upload's key: 256-bit random, single use, 30 s, bound on the
  Host to session / runtime / generation / action. It only ever travels inside
  the TLS control channel, so the OBSERVE schema did not need a separate token.
- The Host checks the bytes itself: size ≤ 8 MiB, PNG signature, IHDR first,
  IEND present, width×height ≤ 16 MP, SHA-256. What the Runner claims is compared
  against that, never trusted instead of it.
- Validated screenshots stay in memory only (the last few per session) and are
  dropped when the session ends: a screen can show anything, passwords included.
- `inspectors` is where the W8-9 screenshot prompt-injection detector plugs in.
  A screenshot is observation data; nothing in it is treated as an instruction.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

UPLOAD_TTL_S = 30.0                 # protocol doc §8
MAX_PNG_BYTES = 8 * 1024 * 1024     # §7
MAX_PIXELS = 16 * 1024 * 1024       # §7: 16 megapixels after decoding
KEEP_PER_SESSION = 8                # the Runner also remembers its last 8 observations

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

Identity = tuple[str, str, int]
# An inspector gets the PNG bytes and returns None, or a reason to block it.
Inspector = Callable[[bytes], "str | None"]


class UploadError(Exception):
    """Refusing an upload. `status` is the HTTP status the uploader gets."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def png_size(data: bytes) -> tuple[int, int]:
    """Width and height from a PNG, checking structure without decoding pixels."""
    if not data.startswith(PNG_SIGNATURE):
        raise UploadError(415, "not a PNG")
    pos, first, seen_end = len(PNG_SIGNATURE), True, False
    width = height = 0
    while pos + 12 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if len(body) != length or pos + 12 + length > len(data):
            raise UploadError(400, "truncated PNG chunk")
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        if zlib.crc32(ctype + body) & 0xFFFFFFFF != crc:
            raise UploadError(400, f"bad CRC in {ctype!r} chunk")
        if first:
            if ctype != b"IHDR" or length != 13:
                raise UploadError(400, "PNG does not start with IHDR")
            width, height = struct.unpack(">II", body[:8])
            first = False
        if ctype == b"IEND":
            seen_end = True
            break
        pos += 12 + length
    if first or not seen_end:
        raise UploadError(400, "incomplete PNG")
    if width == 0 or height == 0 or width * height > MAX_PIXELS:
        raise UploadError(413, f"{width}x{height} is over {MAX_PIXELS // (1024 * 1024)} megapixels")
    return width, height


@dataclass
class _Slot:
    upload_id: str = field(repr=False)
    identity: Identity
    action_id: str
    expires_at: float
    used: bool = False
    data: bytes | None = field(default=None, repr=False)
    sha256: str | None = None
    size: tuple[int, int] | None = None
    state: str = "ISSUED"            # ISSUED → RECEIVED → VALIDATED | BLOCKED


@dataclass
class Screenshot:
    observation_id: str
    action_id: str
    png: bytes = field(repr=False)
    sha256: str
    width: int
    height: int


class ObservationUploads:
    def __init__(self, *, ttl_s: float = UPLOAD_TTL_S, clock=time.monotonic,
                 inspectors: list[Inspector] | None = None):
        self._ttl_s, self._clock = ttl_s, clock
        self._slots: dict[str, _Slot] = {}
        self._kept: dict[Identity, deque[Screenshot]] = {}
        self.inspectors: list[Inspector] = list(inspectors or [])

    # -- issued with each OBSERVE ---------------------------------------------
    def issue(self, identity: Identity, action_id: str) -> str:
        self._expire()
        upload_id = secrets.token_urlsafe(32)          # 43 chars, fits the OBSERVE schema
        self._slots[upload_id] = _Slot(upload_id, identity, action_id, self._clock() + self._ttl_s)
        return upload_id

    # -- the PUT --------------------------------------------------------------
    def receive(self, upload_id: str, data: bytes) -> str:
        """Called by the upload server with the full body. Returns the SHA-256."""
        slot = self._slots.get(upload_id)
        if slot is None:
            raise UploadError(401, "unknown upload_id")
        if slot.used:
            raise UploadError(401, "upload_id already used")
        if self._clock() >= slot.expires_at:
            raise UploadError(401, "upload_id expired")
        slot.used = True                               # one try; a failed upload needs a new OBSERVE
        if len(data) > MAX_PNG_BYTES:
            raise UploadError(413, f"{len(data)} bytes is over {MAX_PNG_BYTES}")
        slot.size = png_size(data)
        slot.data, slot.sha256, slot.state = data, hashlib.sha256(data).hexdigest(), "RECEIVED"
        return slot.sha256

    # -- the OBSERVE_RESULT ---------------------------------------------------
    def finalize(self, upload_id: str, result: dict) -> tuple[str, Screenshot | None, str | None]:
        """Match OBSERVE_RESULT against what arrived. Returns (state, screenshot, reason).

        MISSING means the Runner sent no PNG at all (it may not upload yet); the
        observation is still usable for coordinates, just without an image.
        BLOCKED means what arrived disagrees with what the Runner reported.
        """
        slot = self._slots.pop(upload_id, None)
        if slot is None or slot.state != "RECEIVED":
            return "MISSING", None, "no screenshot was uploaded for this observation"
        if slot.sha256 != result["sha256"]:
            return "BLOCKED", None, "uploaded PNG does not match the reported sha256"
        if slot.size != (result["width"], result["height"]):
            return "BLOCKED", None, (f"uploaded PNG is {slot.size[0]}x{slot.size[1]}, "
                                     f"reported {result['width']}x{result['height']}")
        for inspect in self.inspectors:
            reason = inspect(slot.data)
            if reason:
                return "BLOCKED", None, f"screenshot inspection: {reason}"
        shot = Screenshot(result["observation_id"], slot.action_id, slot.data, slot.sha256, *slot.size)
        kept = self._kept.setdefault(slot.identity, deque(maxlen=KEEP_PER_SESSION))
        kept.append(shot)
        return "VALIDATED", shot, None

    def purge(self, identity: Identity) -> None:
        """Session over: forget its screenshots and any unused upload_ids."""
        self._kept.pop(identity, None)
        for uid in [u for u, s in self._slots.items() if s.identity == identity]:
            del self._slots[uid]

    def kept(self, identity: Identity) -> list[Screenshot]:
        return list(self._kept.get(identity, ()))

    def _expire(self) -> None:
        now = self._clock()
        for uid in [u for u, s in self._slots.items() if now >= s.expires_at + self._ttl_s]:
            del self._slots[uid]
