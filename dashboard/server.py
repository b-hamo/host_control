"""Local, read-only HTTP server for the dashboard (docs: dashboard/README.md).

  GET /                                   the dashboard page (--static folder; index.html)
  GET /api/dashboard/overview             collect.Collector.overview() as JSON
  GET /api/runtimes/{id}/screenshot       image/png of the last screen the Agent saw ({id}: session id or label)
  GET /api/runtimes/{id}/screenshot?format=json   {image_url, captured_at, width, height}

Only 127.0.0.1. Every /api request carries the token (header `Authorization: Bearer <token>` or
`?token=` for <img src>), and the Host header must be this server, so another site in the browser
cannot read it (DNS rebinding). GET only: nothing here starts, stops or approves anything.
"""
from __future__ import annotations

import json
import mimetypes
import secrets
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from dashboard.collect import Collector

DEFAULT_PORT = 17480
CACHE_S = 1.0                         # polling clients share one overview per second


def png_size(path: Path) -> tuple[int, int] | None:
    try:
        with path.open("rb") as f:
            head = f.read(24)
        if head[:8] == b"\x89PNG\r\n\x1a\n" and head[12:16] == b"IHDR":
            return struct.unpack(">II", head[16:24])
    except OSError:
        pass
    return None


class Dashboard:
    def __init__(self, collector: Collector, token: str | None = None, static: Path | None = None):
        self.collector, self.static = collector, Path(static).resolve() if static else None
        self.token = token or secrets.token_urlsafe(24)
        self._lock, self._cached, self._at = threading.Lock(), None, 0.0

    def overview(self) -> dict:
        with self._lock:
            if self._cached is None or time.monotonic() - self._at >= CACHE_S:
                self._cached, self._at = self.collector.overview(), time.monotonic()
            return self._cached

    def session_id(self, key: str) -> str | None:
        for s in self.overview()["sessions"]:
            if key in (s["id"], s["label"]):
                return s["id"]
        return key if key.startswith("SES-") else None


def make_handler(app: Dashboard, port_ref: list[int]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SCRPDashboard/1"

        def log_message(self, *args):          # no request log on the console; tokens live in URLs
            pass

        def _send(self, code: int, body: bytes, kind: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data: dict):
            self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self):
            host = (self.headers.get("Host") or "").lower()
            if host not in (f"127.0.0.1:{port_ref[0]}", f"localhost:{port_ref[0]}"):
                return self._json(403, {"error": "FORBIDDEN_HOST"})
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if not url.path.startswith("/api/"):
                return self._static(url.path)
            given = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip() or \
                (query.get("token") or [""])[0]
            if not secrets.compare_digest(given, app.token):
                return self._json(401, {"error": "UNAUTHORIZED", "message": "token missing or wrong"})
            parts = url.path.strip("/").split("/")
            if parts == ["api", "dashboard", "overview"]:
                return self._json(200, app.overview())
            if len(parts) == 4 and parts[:2] == ["api", "runtimes"] and parts[3] == "screenshot":
                sid = app.session_id(parts[2])
                path = app.collector.screenshot(sid) if sid else None
                if path is None:
                    return self._json(404, {"error": "NO_SCREENSHOT", "message": "no screen saved for this session"})
                captured = app.collector.host_status().get(sid, {}).get("screen_captured_at")
                if (query.get("format") or [""])[0] == "json":
                    size = png_size(path) or (None, None)
                    return self._json(200, {"image_url": f"/api/runtimes/{quote(sid)}/screenshot",
                                            "captured_at": captured, "width": size[0], "height": size[1]})
                try:
                    data = path.read_bytes()
                except OSError:
                    return self._json(404, {"error": "NO_SCREENSHOT"})
                return self._send(200, data, "image/png", {"X-Captured-At": captured or ""})
            return self._json(404, {"error": "NOT_FOUND"})

        def _static(self, path: str):
            if app.static is None:
                body = ("<!doctype html><meta charset=utf-8><title>SCRP dashboard API</title>"
                        "<p>API: /api/dashboard/overview, /api/runtimes/{id}/screenshot "
                        "(Authorization: Bearer &lt;token&gt;)</p>").encode("utf-8")
                return self._send(200, body, "text/html; charset=utf-8")
            name = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (app.static / name).resolve()
            if app.static not in target.parents or not target.is_file():
                return self._json(404, {"error": "NOT_FOUND"})
            kind = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if kind.startswith("text/") or kind in ("application/javascript", "application/json"):
                kind += "; charset=utf-8"
            return self._send(200, target.read_bytes(), kind)

        def do_POST(self):
            self._json(405, {"error": "READ_ONLY"})

        do_PUT = do_DELETE = do_PATCH = do_POST

    return Handler


def serve(app: Dashboard, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    port_ref = [port]
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port_ref))
    port_ref[0] = server.server_address[1]
    return server
