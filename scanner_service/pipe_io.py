"""Framed messages over a Windows Named Pipe, with overlapped I/O so nothing blocks forever.

Frame: 4-byte little-endian length, then that many bytes of UTF-8 JSON. The length is
checked against the limit before any of the body is read. Every read and write waits on
the I/O event, an optional stop event (service stopping) and a deadline.
"""

from __future__ import annotations

import struct
import time

import pywintypes
import win32event
import win32file
import winerror

HEADER = struct.Struct("<I")
ERROR_BROKEN = (winerror.ERROR_BROKEN_PIPE, winerror.ERROR_NO_DATA, winerror.ERROR_PIPE_NOT_CONNECTED,
                winerror.ERROR_OPERATION_ABORTED)


class PipeClosed(Exception):
    pass


class PipeTimeout(Exception):
    pass


class PipeStopping(Exception):
    pass


class FrameTooLarge(Exception):
    def __init__(self, size: int, limit: int):
        super().__init__(f"frame of {size} bytes exceeds {limit}")
        self.size, self.limit = size, limit


def _wait(handle, ov, stop_event, deadline: float | None) -> int:
    """Wait for an overlapped operation. Returns bytes transferred; cancels on stop/timeout."""
    handles = [ov.hEvent] + ([stop_event] if stop_event is not None else [])
    while True:
        ms = win32event.INFINITE if deadline is None else max(0, int((deadline - time.monotonic()) * 1000))
        r = win32event.WaitForMultipleObjects(handles, False, ms)
        if r == win32event.WAIT_OBJECT_0:
            try:
                return win32file.GetOverlappedResult(handle, ov, False)
            except pywintypes.error as e:
                if e.winerror in ERROR_BROKEN:
                    raise PipeClosed(e.strerror) from None
                raise
        _cancel(handle, ov)
        if r == win32event.WAIT_OBJECT_0 + 1:
            raise PipeStopping()
        raise PipeTimeout()


def _cancel(handle, ov) -> None:
    try:
        win32file.CancelIo(handle)
        win32file.GetOverlappedResult(handle, ov, True)
    except pywintypes.error:
        pass


def _new_ov():
    ov = pywintypes.OVERLAPPED()
    ov.hEvent = win32event.CreateEvent(None, True, False, None)
    return ov


def read_exact(handle, n: int, stop_event=None, deadline: float | None = None) -> bytes:
    out = bytearray()
    ov = _new_ov()
    try:
        while len(out) < n:
            buf = win32file.AllocateReadBuffer(min(n - len(out), 64 * 1024))
            win32event.ResetEvent(ov.hEvent)
            try:
                win32file.ReadFile(handle, buf, ov)
            except pywintypes.error as e:
                if e.winerror in ERROR_BROKEN:
                    raise PipeClosed(e.strerror) from None
                raise
            got = _wait(handle, ov, stop_event, deadline)
            if got == 0:
                raise PipeClosed("no data")
            out += bytes(buf[:got])
    finally:
        ov.hEvent.Close()
    return bytes(out)


def write_all(handle, data: bytes, stop_event=None, deadline: float | None = None) -> None:
    ov = _new_ov()
    try:
        sent = 0
        while sent < len(data):
            win32event.ResetEvent(ov.hEvent)
            try:
                win32file.WriteFile(handle, data[sent:], ov)
            except pywintypes.error as e:
                if e.winerror in ERROR_BROKEN:
                    raise PipeClosed(e.strerror) from None
                raise
            n = _wait(handle, ov, stop_event, deadline)
            if n == 0:
                raise PipeClosed("nothing written")
            sent += n
    finally:
        ov.hEvent.Close()


def read_frame(handle, limit: int, stop_event=None, timeout_s: float | None = None,
               body_timeout_s: float = 10.0) -> bytes | None:
    """One frame. None if the peer closed cleanly before a new frame began.

    timeout_s bounds the wait for the next frame (idle); the body then has body_timeout_s.
    """
    deadline = None if timeout_s is None else time.monotonic() + timeout_s
    try:
        head = read_exact(handle, HEADER.size, stop_event, deadline)
    except PipeClosed:
        return None
    (size,) = HEADER.unpack(head)
    if size > limit:
        raise FrameTooLarge(size, limit)
    return read_exact(handle, size, stop_event, time.monotonic() + body_timeout_s) if size else b""


def write_frame(handle, payload: bytes, stop_event=None, timeout_s: float = 10.0) -> None:
    write_all(handle, HEADER.pack(len(payload)) + payload, stop_event, time.monotonic() + timeout_s)
