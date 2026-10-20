"""Connection lifetime for stdio clients, independent of the persistent owner."""
import json
import os
import queue
import sys
import threading


def prepare_stdio():
    """Recover inherited MCP pipe handles when launched by Windows pythonw.

    Never allocate/attach a console. Missing protocol handles fail closed.
    A private duplicate belongs to each stream, so closing it cannot close
    the handle supplied by the parent process.
    """
    if sys.platform != 'win32':
        return
    import ctypes
    from ctypes import wintypes
    import io
    import msvcrt

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetStdHandle.argtypes = [wintypes.DWORD]
    kernel.GetStdHandle.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                      wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE),
                                      wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.DuplicateHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    process = kernel.GetCurrentProcess()
    for name, handle_id, mode, flags in (
        ('stdin', -10, 'rb', os.O_RDONLY),
        ('stdout', -11, 'wb', os.O_WRONLY),
        ('stderr', -12, 'wb', os.O_WRONLY),
    ):
        if getattr(sys, name) is not None:
            continue
        handle = kernel.GetStdHandle(handle_id & 0xffffffff)
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            raise OSError(f'Missing inherited MCP {name} handle')
        duplicate = wintypes.HANDLE()
        if not kernel.DuplicateHandle(process, handle, process,
                                      ctypes.byref(duplicate), 0, False, 2):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(duplicate.value, flags | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(duplicate)
            raise
        stream = io.TextIOWrapper(os.fdopen(fd, mode), encoding='utf-8',
                                  errors='replace', write_through=True)
        setattr(sys, name, stream)
        setattr(sys, '__' + name + '__', stream)


def serve_stdio(handle, *, close, alive=lambda: True):
    """Close transport on stdin EOF even while a tool response is pending.

    Open stdio still means connected. A completed assistant turn is not EOF.
    No idle timeout or Sandbox termination is implied by this transport.
    """
    messages = queue.Queue()
    eof = threading.Event()
    stopped = threading.Event()

    def chunks():
        fd = sys.stdin.fileno()
        if sys.platform == 'win32':
            import ctypes
            from ctypes import wintypes
            import msvcrt
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetFileType.argtypes = [wintypes.HANDLE]
            kernel.GetFileType.restype = wintypes.DWORD
            kernel.PeekNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
            kernel.PeekNamedPipe.restype = wintypes.BOOL
            pipe = msvcrt.get_osfhandle(fd)
            if kernel.GetFileType(pipe) == 3:  # FILE_TYPE_PIPE
                # A blocking CRT read can also stall interpreter finalization.
                # Poll availability so client shutdown can stop the reader while the
                # parent deliberately keeps stdin open. Only this thread reads.
                while not stopped.is_set():
                    available = wintypes.DWORD()
                    if not kernel.PeekNamedPipe(pipe, None, 0, None,
                                                ctypes.byref(available), None):
                        return  # closed/broken input pipe
                    if available.value:
                        chunk = os.read(fd, min(available.value, 65536))
                        if not chunk:
                            return
                        yield chunk
                    else:
                        stopped.wait(0.02)
                return
        while not stopped.is_set():
            chunk = os.read(fd, 65536)
            if not chunk:
                return
            yield chunk

    def reader():
        try:
            # A daemon blocked on BufferedReader can hold its lock during
            # interpreter shutdown. Read the descriptor instead.
            pending = b''
            for chunk in chunks():
                pending += chunk
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    if not line.strip():
                        continue
                    try:
                        message = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if isinstance(message, dict):
                        messages.put(message)
        except OSError:
            pass
        finally:
            eof.set()

    def monitor():
        while not stopped.wait(0.2):
            if eof.is_set() or not alive():
                stopped.set()
                close()  # socket shutdown unblocks an outstanding receive
                return

    input_reader = threading.Thread(target=reader, name='scrp-stdio-reader', daemon=True)
    input_reader.start()
    watcher = threading.Thread(target=monitor, name='scrp-stdio-lifetime', daemon=True)
    watcher.start()
    try:
        while not eof.is_set() and not stopped.is_set():
            try:
                message = messages.get(timeout=0.2)
            except queue.Empty:
                continue
            if eof.is_set() or stopped.is_set():
                break
            response = handle(message)
            if response is not None:
                sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False).encode('utf-8') + b'\n')
                sys.stdout.buffer.flush()
    except (EOFError, BrokenPipeError, ConnectionError, OSError):
        pass  # an interrupted request is never automatically retried
    finally:
        stopped.set()
        close()
        watcher.join(timeout=2)
        input_reader.join(timeout=2)
