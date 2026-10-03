"""HTTPS receiver for screenshot uploads (protocol doc §8).

    PUT https://<host>:17444/scrp/v1/observations/<upload_id>
    Content-Type: image/png
    Content-Length: <bytes, at most 8 MiB>

A deliberately small HTTP/1.1 server: PUT on one path, one request per
connection, Content-Length required (no chunked bodies), a hard size cap and
read deadlines checked before anything is parsed (§7: limits apply before
parsing, and an idle timeout stops slow senders from holding the socket).
Same TLS certificate as the control channel; the Runner pins it the same way.

It runs on its own port because the WebSocket library behind the control
channel does not expose request bodies. The address goes into the bootstrap
file, so the Runner only ever uses the endpoint the Host gave it.

upload_id is a capability, like the bootstrap token: only its first characters
are ever logged.
"""

from __future__ import annotations

import asyncio
import logging
import ssl

from host.observation_store import MAX_PNG_BYTES, ObservationUploads, UploadError

log = logging.getLogger("host-upload")

UPLOAD_PATH = "/scrp/v1/observations/"
UPLOAD_PORT = 17444
MAX_HEADER_BYTES = 8 * 1024
HEADER_TIMEOUT_S = 5.0
BODY_TIMEOUT_S = 15.0
TLS_HANDSHAKE_TIMEOUT_S = 5.0
TLS_SHUTDOWN_TIMEOUT_S = 2.0

REASONS = {201: "Created", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
           405: "Method Not Allowed", 408: "Request Timeout", 411: "Length Required",
           413: "Payload Too Large", 415: "Unsupported Media Type"}


def _short(upload_id: str) -> str:
    return upload_id[:6] + "…" if upload_id else "-"


async def _respond(writer: asyncio.StreamWriter, status: int, body: str = "") -> None:
    payload = (body or REASONS.get(status, "")).encode() + b"\n"
    writer.write(f"HTTP/1.1 {status} {REASONS.get(status, '')}\r\nContent-Type: text/plain\r\n"
                 f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload)
    try:
        await writer.drain()
    finally:
        writer.close()


def make_handler(uploads: ObservationUploads):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        upload_id = ""
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT_S)
            except asyncio.LimitOverrunError:
                return await _respond(writer, 400, "headers too large")
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return await _respond(writer, 408)
            if len(head) > MAX_HEADER_BYTES:
                return await _respond(writer, 400, "headers too large")
            lines = head.decode("latin-1").split("\r\n")
            try:
                method, target, _version = lines[0].split(" ", 2)
            except ValueError:
                return await _respond(writer, 400, "bad request line")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if not target.startswith(UPLOAD_PATH):
                return await _respond(writer, 404)
            upload_id = target[len(UPLOAD_PATH):]
            if method != "PUT":
                return await _respond(writer, 405)
            if "transfer-encoding" in headers:
                return await _respond(writer, 411, "send Content-Length, not chunked")
            try:
                length = int(headers["content-length"])
            except (KeyError, ValueError):
                return await _respond(writer, 411)
            if length > MAX_PNG_BYTES:
                return await _respond(writer, 413)
            if headers.get("content-type", "").split(";")[0].strip().lower() != "image/png":
                return await _respond(writer, 415, "Content-Type must be image/png")
            try:
                body = await asyncio.wait_for(reader.readexactly(length), BODY_TIMEOUT_S)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return await _respond(writer, 408, "body not received in time")
            try:
                sha = uploads.receive(upload_id, body)
            except UploadError as e:
                log.warning("UPLOAD refused %s from %s: %s (%d)", _short(upload_id), peer, e.reason, e.status)
                return await _respond(writer, e.status, e.reason)
            log.info("UPLOAD received %s: %d bytes sha256=%s…", _short(upload_id), length, sha[:12])
            await _respond(writer, 201, sha)
        except (ConnectionError, ssl.SSLError) as e:
            log.info("UPLOAD connection from %s dropped: %s", peer, type(e).__name__)
            writer.close()
    return handle


class UploadServer:
    """asyncio.Server with a bounded shutdown.

    On Windows, a connection reset while closing (e.g. a refused upload whose body
    was never read) can make asyncio skip its bookkeeping for that connection, and
    Server.wait_closed() then waits for it forever. Exiting the Host must not hang
    on that, so shutdown waits CLOSE_WAIT_S and moves on.
    """

    CLOSE_WAIT_S = 3.0

    def __init__(self, server: asyncio.base_events.Server):
        self._server = server

    @property
    def sockets(self):
        return self._server.sockets

    async def aclose(self) -> None:
        self._server.close()
        try:
            await asyncio.wait_for(self._server.wait_closed(), self.CLOSE_WAIT_S)
        except asyncio.TimeoutError:
            log.info("upload server closed with connections still being torn down")

    async def __aenter__(self) -> "UploadServer":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()


async def start_upload_server(uploads: ObservationUploads, ssl_ctx: ssl.SSLContext,
                              host: str = "0.0.0.0", port: int = UPLOAD_PORT) -> UploadServer:
    # Bounded TLS handshake and shutdown: a client that never finishes either must not
    # hold a slot, or keep the Host from exiting (the default shutdown wait is 30 s).
    server = await asyncio.start_server(make_handler(uploads), host, port, ssl=ssl_ctx,
                                        limit=MAX_HEADER_BYTES,
                                        ssl_handshake_timeout=TLS_HANDSHAKE_TIMEOUT_S,
                                        ssl_shutdown_timeout=TLS_SHUTDOWN_TIMEOUT_S)
    return UploadServer(server)
