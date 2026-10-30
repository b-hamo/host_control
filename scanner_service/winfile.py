"""Windows file primitives for the quarantine and the export (pywin32).

Path checks alone (Path.resolve and friends) are not enough: a path can be swapped
between the check and the use. So every file the service works on is reached through
a handle it opened itself:

- new files: CREATE_NEW (never an existing file or link), no sharing while written
- scanned files: read handle that shares only READ (+ DELETE, so Defender can still
  remediate); nobody can write until it is closed
- identity: volume serial + file index (+ link count) from the handle, and the
  handle's final path, compared with what the service expects
- links: FILE_FLAG_OPEN_REPARSE_POINT on files, attribute check on directories

pywintypes.error is turned into OSError (with winerror), so callers handle one type.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import pywintypes
import win32api
import win32con
import win32file
import winerror

GENERIC_READ = win32con.GENERIC_READ
GENERIC_WRITE = win32con.GENERIC_WRITE
DELETE = 0x00010000
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 0x1, 0x2, 0x4
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000   # keep the search indexer (and its previewers) out
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
READ_BLOCK = 1 << 20


def _oserror(e: pywintypes.error, path=None) -> OSError:
    return OSError(0, e.strerror, str(path) if path is not None else None, e.winerror)


@contextlib.contextmanager
def _win(path=None):
    try:
        yield
    except pywintypes.error as e:
        raise _oserror(e, path) from None


@dataclass(frozen=True)
class FileId:
    volume: int
    index: int
    links: int
    attributes: int
    size: int

    def same_file(self, other: "FileId") -> bool:
        return (self.volume, self.index) == (other.volume, other.index)


def identity(handle) -> FileId:
    with _win():
        info = win32file.GetFileInformationByHandle(handle)
    attrs, _c, _a, _w, vol, size_hi, size_lo, links, idx_hi, idx_lo = info
    return FileId(vol, (idx_hi << 32) | idx_lo, links, attrs, (size_hi << 32) | size_lo)


def _strip_prefix(p: str) -> str:
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


def final_path(handle) -> str:
    """Where the handle really points (links resolved), as a normal DOS path."""
    with _win():
        return _strip_prefix(win32file.GetFinalPathNameByHandle(handle, 0))


def same_path(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.normpath(str(a))) == os.path.normcase(os.path.normpath(str(b)))


def is_within(child: str | Path, parent: str | Path) -> bool:
    c = os.path.normcase(os.path.normpath(str(child)))
    p = os.path.normcase(os.path.normpath(str(parent))).rstrip("\\") + "\\"
    return c.startswith(p)


def attributes(path: str | Path) -> int | None:
    """File attributes of the entry itself (a link is not followed), None if missing."""
    try:
        a = win32file.GetFileAttributes(str(path))
    except pywintypes.error as e:
        if e.winerror in (winerror.ERROR_FILE_NOT_FOUND, winerror.ERROR_PATH_NOT_FOUND):
            return None
        raise _oserror(e, path) from None
    if a in (-1, INVALID_FILE_ATTRIBUTES):          # pywin32 returns the failure value instead of raising
        err = win32api.GetLastError()
        if err in (0, winerror.ERROR_FILE_NOT_FOUND, winerror.ERROR_PATH_NOT_FOUND):
            return None
        raise OSError(0, "file attributes unreadable", str(path), err)
    return a & INVALID_FILE_ATTRIBUTES


def is_reparse(path: str | Path) -> bool:
    a = attributes(path)
    return a is not None and bool(a & FILE_ATTRIBUTE_REPARSE_POINT)


def check_plain_dir(path: str | Path) -> None:
    """A real directory (no junction, symlink or other reparse point). Raises OSError."""
    a = attributes(path)
    if a is None:
        raise FileNotFoundError(f"{path} does not exist")
    if a & FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError(f"{path} is a reparse point (junction or link); refused")
    if not a & FILE_ATTRIBUTE_DIRECTORY:
        raise NotADirectoryError(f"{path} is not a directory")


def dir_final_path(path: str | Path) -> str:
    """The real location of a directory, following links (to compare with the expected one)."""
    with _win(path):
        h = win32file.CreateFile(str(path), FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
                                 win32con.OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
    try:
        return final_path(h)
    finally:
        h.Close()


def make_new_dir(path: str | Path) -> None:
    """Create a directory that must not exist yet (never reuse one). FileExistsError otherwise."""
    with _win(path):
        win32file.CreateDirectory(str(path), None)
        win32file.SetFileAttributes(str(path), FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


def create_new(path: str | Path):
    """A new file, exclusively ours: fails if anything (file or link) already has the name."""
    with _win(path):
        return win32file.CreateFile(str(path), GENERIC_READ | GENERIC_WRITE | DELETE, 0, None,
                                    win32con.CREATE_NEW,
                                    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_OPEN_REPARSE_POINT, None)


def open_entry(path: str | Path):
    """Attribute-only handle on the entry itself, to compare its identity. Blocks nobody."""
    with _win(path):
        return win32file.CreateFile(str(path), FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
                                    win32con.OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, None)


def open_locked(path: str | Path, *, share_delete: bool = True):
    """Read handle that refuses every writer until closed. The entry itself, not a link target."""
    share = FILE_SHARE_READ | (FILE_SHARE_DELETE if share_delete else 0)
    with _win(path):
        return win32file.CreateFile(str(path), GENERIC_READ, share, None, win32con.OPEN_EXISTING,
                                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, None)


def write_all(handle, data: bytes) -> None:
    with _win():
        _rc, n = win32file.WriteFile(handle, data)
    if n != len(data):
        raise OSError(f"short write: {n} of {len(data)} bytes")


def flush(handle) -> None:
    with _win():
        win32file.FlushFileBuffers(handle)


def rewind(handle) -> None:
    with _win():
        win32file.SetFilePointer(handle, 0, win32file.FILE_BEGIN)


def read_blocks(handle, limit: int):
    """Yield the file from the start, refusing more than `limit` bytes."""
    rewind(handle)
    total = 0
    while True:
        with _win():
            _rc, data = win32file.ReadFile(handle, READ_BLOCK)
        if not data:
            return
        total += len(data)
        if total > limit:
            raise OSError(f"file grew beyond {limit} bytes")
        yield bytes(data)


def hash_handle(handle, limit: int) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    for block in read_blocks(handle, limit):
        h.update(block)
        n += len(block)
    return n, h.hexdigest()


def read_all(handle, limit: int) -> bytes:
    return b"".join(read_blocks(handle, limit))


def close(handle) -> None:
    if handle is None:
        return
    try:
        handle.Close()
    except pywintypes.error:
        pass


def delete_file(path: str | Path) -> None:
    """Delete one entry (a link is deleted itself, never its target). Missing is fine."""
    try:
        win32file.SetFileAttributes(str(path), FILE_ATTRIBUTE_NORMAL)
        win32file.DeleteFile(str(path))
    except pywintypes.error as e:
        if e.winerror in (winerror.ERROR_FILE_NOT_FOUND, winerror.ERROR_PATH_NOT_FOUND):
            return
        raise _oserror(e, path) from None


def remove_dir(path: str | Path) -> None:
    """Remove an empty directory or a directory link itself. Missing is fine."""
    try:
        win32file.RemoveDirectory(str(path))
    except pywintypes.error as e:
        if e.winerror in (winerror.ERROR_FILE_NOT_FOUND, winerror.ERROR_PATH_NOT_FOUND):
            return
        raise _oserror(e, path) from None


def move_no_replace(src: str | Path, dst: str | Path) -> None:
    """Rename within a volume; fails if dst exists."""
    with _win(dst):
        win32file.MoveFileEx(str(src), str(dst), win32file.MOVEFILE_WRITE_THROUGH)


def replace_file(src: str | Path, dst: str | Path) -> None:
    with _win(dst):
        win32file.MoveFileEx(str(src), str(dst),
                             win32file.MOVEFILE_WRITE_THROUGH | win32file.MOVEFILE_REPLACE_EXISTING)


def free_bytes(path: str | Path) -> int:
    with _win(path):
        return int(win32file.GetDiskFreeSpaceEx(str(path))[0])
