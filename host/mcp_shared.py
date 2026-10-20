"""Authenticated local JSON transport for one SCRP owner and many stdio clients.

Only the owner constructs the runtime. Closing a chat detaches its client;
it does not stop the runtime. A lost reply is never automatically replayed.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import hmac
import json
import logging
import os
import queue
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys
import threading
import time

log = logging.getLogger("host-mcp-shared")
OWNER_ENV = "SCRP_SHARED_OWNER"
MAX_FRAME = 32 * 1024 * 1024


@contextmanager
def exclusive(directory):
    """Hold the owner lock for the process lifetime, without deleting its file."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "owner.lock").open("a+b") as lock:
        if lock.seek(0, os.SEEK_END) == 0:
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            lock.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def read(stream):
    line = stream.readline(MAX_FRAME + 1)
    if not line:
        raise EOFError("shared runtime disconnected")
    if len(line) > MAX_FRAME or not line.endswith(b"\n"):
        raise ValueError("invalid shared frame")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def write(stream, value):
    data = json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(data) > MAX_FRAME:
        raise ValueError("shared frame too large")
    stream.write(data)
    stream.flush()


def fingerprint(args):
    # These output paths are allocated anew by launchers for every client.
    transient = {"log_file", "artifact_dir", "cert_dir", "audit_dir", "export_dir"}
    config = {k: str(v) for k, v in vars(args).items() if k not in transient}
    config["host_source"] = str(Path(__file__).resolve().parent)
    config["python"] = sys.executable
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def serve(server, directory, config_id, *, ready=None, stop=None):
    """The caller owns owner.lock and any runtime-specific journal lock."""
    directory = Path(directory)
    endpoint = directory / "endpoint.json"
    token = secrets.token_hex(32)
    dispatch = threading.Lock()
    sockets, sockets_lock = set(), threading.Lock()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(32)
        listener.settimeout(0.5)
        metadata = {"port": listener.getsockname()[1], "token": token,
                    "pid": os.getpid(), "config": config_id}
        temporary = directory / ("endpoint-" + secrets.token_hex(8) + ".tmp")
        temporary.write_text(json.dumps(metadata), encoding="utf-8")
        os.replace(temporary, endpoint)
        log.info("Shared SCRP owner ready (pid %s)", os.getpid())

        def client(sock):
            try:
                with sock:
                    sock.settimeout(5)
                    with sock.makefile("rwb") as stream:
                        hello = read(stream)
                        supplied = hello.get("token")
                        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, token):
                            write(stream, {"error": "SHARED_AUTHENTICATION_FAILED"})
                            return
                        if hello.get("config") != config_id:
                            write(stream, {"error": "SHARED_CONFIGURATION_MISMATCH"})
                            return
                        write(stream, {"ok": True, "owner_pid": os.getpid()})
                        sock.settimeout(None)
                        while True:
                            msg = read(stream)
                            if msg.get("method") == "tools/call":
                                with dispatch:
                                    result = server.handle(msg)
                            else:
                                result = server.handle(msg)
                            write(stream, {"response": result})
            except (OSError, EOFError, ValueError):
                pass  # Disconnect never stops the shared Guest or retries a call.
            except Exception:
                log.exception("Shared client handler failed; request not replayed")
            finally:
                with sockets_lock:
                    sockets.discard(sock)

        if ready is not None:
            ready.set()
        try:
            while stop is None or not stop.is_set():
                try:
                    sock, _ = listener.accept()
                except socket.timeout:
                    continue
                with sockets_lock:
                    sockets.add(sock)
                threading.Thread(target=client, args=(sock,), daemon=True).start()
        finally:
            with sockets_lock:
                for sock in sockets:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            # Never remove metadata published by a replacement owner.
            try:
                if json.loads(endpoint.read_text(encoding="utf-8")).get("token") == token:
                    endpoint.unlink()
            except (OSError, ValueError):
                pass


def connect(directory, config_id):
    endpoint = json.loads((Path(directory) / "endpoint.json").read_text(encoding="utf-8"))
    # No remotely supplied host/path is honored.
    sock = socket.create_connection(("127.0.0.1", int(endpoint["port"])), timeout=5)
    stream = sock.makefile("rwb")
    try:
        write(stream, {"token": endpoint["token"], "config": config_id})
        result = read(stream)
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "SHARED_AUTHENTICATION_FAILED"))
        sock.settimeout(None)
        return sock, stream, result["owner_pid"]
    except BaseException:
        stream.close()
        sock.close()
        raise


def attach(directory, config_id, timeout=20, *, cancel=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    child = None
    deadline = time.monotonic() + timeout
    while True:
        if cancel is not None and cancel.is_set():
            raise EOFError("stdio closed while attaching")
        try:
            return connect(directory, config_id)
        except (OSError, EOFError, ValueError, KeyError):
            if time.monotonic() >= deadline:
                raise RuntimeError("SHARED_STARTUP_FAILED: see shared/owner.log; existing journal may be owned by a legacy server")
            if child is None:
                env = {**os.environ, OWNER_ENV: config_id}
                # The shared owner outlives a discovery client's Windows Job.
                # Codex closes that Job when a short-lived discovery client ends.
                # If breakaway is not allowed, fail startup rather than creating
                # an owner that will silently die with its first client.
                options = ({"creationflags": subprocess.CREATE_NO_WINDOW
                            | subprocess.CREATE_NEW_PROCESS_GROUP
                            | subprocess.CREATE_BREAKAWAY_FROM_JOB}
                           if sys.platform == "win32" else {"start_new_session": True})
                with (directory / "owner.log").open("ab") as output:
                    child = subprocess.Popen([sys.executable, "-I", *sys.argv], env=env,
                                             stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                             close_fds=True, **options)
            if cancel is None:
                time.sleep(0.1)
            else:
                cancel.wait(0.1)


class _Connection:
    """One physical socket generation. Its queue is never reused on reconnect."""
    def __init__(self, transport):
        self.sock, self.stream, self.owner_pid = transport
        self.responses = queue.Queue()
        self.closed = threading.Event()
        self.close_lock = threading.Lock()
        self.disposed = False
        self.receiver = threading.Thread(target=self._receive, name='scrp-shared-reader', daemon=True)
        self.receiver.start()
        log.info("SCRP stdio attached to shared owner %s", self.owner_pid)

    def _receive(self):
        pending = b""
        try:
            while not self.closed.is_set():
                # Do not block inside BufferedReader: closing that stream from
                # another thread can wait on its read lock on Windows.
                readable, _, _ = select.select([self.sock], [], [], 0.2)
                if not readable:
                    continue
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise EOFError("shared runtime disconnected")
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if len(line) + 1 > MAX_FRAME:
                        raise ValueError("shared frame too large")
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("expected JSON object")
                    self.responses.put(value["response"])
                if len(pending) >= MAX_FRAME:
                    raise ValueError("shared frame too large")
        except (OSError, EOFError, ValueError, KeyError) as exc:
            self.responses.put(exc)
        finally:
            self.closed.set()

    def alive(self):
        return not self.closed.is_set()

    def __call__(self, msg):
        if self.closed.is_set():
            raise EOFError('SCRP owner disconnected; request not replayed')
        write(self.stream, msg)
        response = self.responses.get()
        if isinstance(response, BaseException):
            raise EOFError('SCRP owner disconnected; request not replayed') from response
        if ((msg.get("id") is not None and
             (not isinstance(response, dict) or response.get("id") != msg["id"]))
                or (msg.get("id") is None and response is not None)):
            self.close()
            raise ValueError('Mismatched SCRP response; request not replayed')
        return response

    def close(self):
        with self.close_lock:
            if self.disposed:
                return
            self.disposed = True
            self.closed.set()
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.stream.close()
            self.sock.close()
            self.responses.put(EOFError('SCRP stdio connection closed'))
            self.receiver.join(timeout=2)


class SharedClient:
    """Persistent stdio peer; reconnect only before a new request, never replay it."""
    def __init__(self, directory, config_id, *, connector=attach):
        self.directory, self.config_id, self.connector = directory, config_id, connector
        self.disposed = threading.Event()
        self.request_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.connection = None
        self.initialization = None
        self.initialized = False

    def alive(self):
        # Losing the owner must not make serve_stdio close Codex's pipe.
        return not self.disposed.is_set()

    def _connect(self):
        with self.state_lock:
            connection = self.connection
        if connection is not None and connection.alive():
            return connection
        if connection is not None:
            connection.close()
        if self.disposed.is_set():
            raise EOFError("stdio closed")
        candidate = _Connection(self.connector(self.directory, self.config_id, cancel=self.disposed))
        try:
            with self.state_lock:
                if self.disposed.is_set():
                    raise EOFError("stdio closed")
                # Publish before negotiation so stdin EOF can interrupt its receive.
                self.connection = candidate
            # Only protocol negotiation is repeated. No application/tool request is replayed.
            if self.initialization is not None:
                response = candidate(self.initialization)
                if "error" in response:
                    raise RuntimeError("Host rejected MCP initialization")
                if self.initialized:
                    candidate({"jsonrpc": "2.0", "method": "notifications/initialized"})
            if self.disposed.is_set():
                raise EOFError("stdio closed")
            return candidate
        except BaseException:
            candidate.close()
            raise

    def _error(self, msg, code, *, uncertain):
        if msg.get("id") is None:
            return None
        value = {
            "ok": False, "error": code,
            "outcome": "UNKNOWN" if uncertain else "NOT_SENT",
            "replayed": False,
            "recommended_next_step": (
                "Reconnect with a new status query; inspect the original request_id before any execution."
                if uncertain else "Check Host availability/configuration and send a new request."
            ),
        }
        params = msg.get("params")
        arguments = params.get("arguments") if isinstance(params, dict) else None
        if isinstance(arguments, dict) and isinstance(arguments.get("request_id"), str):
            value["request_id"] = arguments["request_id"]
        if msg.get("method") == "tools/call":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {
                "isError": True, "content": [{"type": "text", "text": json.dumps(value)}]}}
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {
            "code": -32001, "message": code, "data": value}}

    def __call__(self, msg):
        with self.request_lock:
            if self.disposed.is_set():
                raise EOFError("stdio closed")
            try:
                connection = self._connect()
            except (OSError, EOFError, ValueError, KeyError, RuntimeError):
                return self._error(msg, "MCP_HOST_UNAVAILABLE", uncertain=False)
            try:
                response = connection(msg)
            except (OSError, EOFError, ValueError, KeyError):
                connection.close()
                return self._error(msg, "MCP_REQUEST_OUTCOME_UNKNOWN", uncertain=True)
            if msg.get("method") == "initialize" and response and "result" in response:
                self.initialization = json.loads(json.dumps(msg))
            elif msg.get("method") == "notifications/initialized":
                self.initialized = True
            return response

    def close(self):
        self.disposed.set()
        with self.state_lock:
            connection = self.connection
        if connection is not None:
            connection.close()


def proxy(directory, config_id, handler=None):
    client = SharedClient(directory, config_id)
    try:
        if handler is not None:
            handler(client)
        else:
            from host.mcp_stdio import serve_stdio
            serve_stdio(client, close=client.close, alive=client.alive)
    finally:
        client.close()  # detach only; shared owner/Guest stays alive


def run(args, build_server, *, stdio_handler=None):
    """Called before constructing McpRuntime/RouterScrpRuntime in every client."""
    state = getattr(args, "shared_state", None) or getattr(args, "router_state", None)
    if state is None:
        raise ValueError("Shared runtime requires a private state directory")
    directory = state.resolve() / "shared"
    directory.mkdir(parents=True, exist_ok=True)
    config_id = fingerprint(args)
    if os.environ.get(OWNER_ENV) != config_id:
        proxy(directory, config_id, stdio_handler)
        return
    # Startup races produce at most one owner. Losers never touch the journal.
    with exclusive(directory):
        server = build_server()
        try:
            serve(server, directory, config_id)
        finally:
            server.backend.shutdown()
