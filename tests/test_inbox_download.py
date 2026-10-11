"""inbox_download and the shared inbox (sandbox_manager acf5f9f, Router: download on the Host, run in the Sandbox).

- Downloader: https only, public addresses only, connection pinned to the checked address
  (no second DNS lookup), redirects checked, size and inbox limits, safe names, never
  overwrites, written under a name the watcher ignores, marked as from the Internet
- the deny-execute probe of the inbox folder
- MCP: the tool exists only with --inbox, goes through the Broker (policy, audit without
  query strings), the inbox is passed to prepare() and watched until the session ends
"""

import argparse
import asyncio
import hashlib
import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import host.inbox_download as dl
from host import tls
from host.inbox_download import Downloader, DownloadError, check_no_execute
from host.mcp_server import HostBackend, load_tool_list
from test_sandbox_launch import FakeManager, args as launch_args, guest, paths, run

ROOT = Path(__file__).resolve().parent.parent
BODY = "ZoomIt 시험 파일\n".encode("utf-8")


# --------------------------------------------------------------------- a small HTTPS file server
class Handler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = __import__("urllib.parse").parse.unquote(self.path.split("?")[0])
        kind, value = self.routes.get(path, ("status", 404))
        if kind == "redirect":
            self.send_response(302)
            self.send_header("Location", value)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif kind == "status":
            self.send_response(value)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif kind == "stream":                         # no Content-Length: read until close
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(value)
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(value)))
            self.end_headers()
            self.wfile.write(value)


@pytest.fixture
def server(tmp_path):
    cert, key = tls.ensure_dev_cert(tmp_path / "certs")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.socket = tls.server_context(cert, key).wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    port = httpd.server_address[1]
    Handler.routes = {}
    yield SimpleNamespace(port=port, base=f"https://files.test:{port}", pem=cert.read_text(), routes=Handler.routes)
    httpd.shutdown()


def downloader(tmp_path, server, **kw):
    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    calls = []

    def resolver(host, port):
        calls.append(host)
        return {"files.test": ["127.0.0.1"], "internal.test": ["10.0.0.5"]}.get(host, ["127.0.0.1"])
    d = Downloader(inbox, context=tls.client_context(server.pem), resolver=resolver, allow_private=True, **kw)
    return d, calls


# --------------------------------------------------------------------- address and URL policy
@pytest.mark.parametrize("url,code", [
    ("http://example.com/a.exe", "INVALID_ARGUMENT"),
    ("https://user:pw@example.com/a.exe", "INVALID_ARGUMENT"),
    ("https://intranet.test/a.exe", "POLICY_DENIED"),       # 10.x
    ("https://loop.test/a.exe", "POLICY_DENIED"),           # 127.x
    ("https://meta.test/a.exe", "POLICY_DENIED"),           # 169.254.169.254 (cloud metadata)
    ("https://v6.test/a.exe", "POLICY_DENIED"),             # ::1
])
def test_only_public_https_is_allowed(tmp_path, url, code):
    table = {"intranet.test": ["10.0.0.5"], "loop.test": ["127.0.0.1"], "meta.test": ["169.254.169.254"],
             "v6.test": ["::1"], "example.com": ["93.184.216.34"]}
    d = Downloader(tmp_path, resolver=lambda h, p: table[h])
    with pytest.raises(DownloadError) as e:
        d._check(url)
    assert e.value.code == code
    assert d._check("https://example.com/a.exe")[1] == "93.184.216.34"


def test_a_name_with_one_public_and_one_private_address_is_refused(tmp_path):
    d = Downloader(tmp_path, resolver=lambda h, p: ["93.184.216.34", "192.168.0.10"])
    with pytest.raises(DownloadError) as e:
        d._check("https://mixed.test/a.exe")
    assert e.value.code == "POLICY_DENIED"


def test_the_connection_goes_to_the_checked_address_without_a_second_lookup(tmp_path, server, monkeypatch):
    """DNS rebinding: the name is resolved once per hop and the socket connects to that exact IP."""
    server.routes["/f.txt"] = ("body", BODY)
    d, calls = downloader(tmp_path, server)
    connected = []
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection", lambda addr, *a, **k: (connected.append(addr), real(addr, *a, **k))[1])
    real_gai = socket.getaddrinfo

    def no_name_lookup(host, *a, **k):
        if host == "files.test":                     # a literal IP is not a lookup; the name would be
            pytest.fail("second DNS lookup")
        return real_gai(host, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", no_name_lookup)
    d.download(f"{server.base}/f.txt")
    assert calls == ["files.test"] and connected == [("127.0.0.1", server.port)]


def test_every_redirect_is_checked(tmp_path, server):
    server.routes["/to-internal"] = ("redirect", f"https://internal.test:{server.port}/f.txt")
    server.routes["/to-http"] = ("redirect", "http://files.test/f.txt")
    server.routes["/loop"] = ("redirect", "/loop")
    d, _ = downloader(tmp_path, server)
    d.allow_private = False
    d.resolver = lambda h, p: {"files.test": ["93.184.216.34"], "internal.test": ["10.0.0.5"]}[h]
    with pytest.raises(DownloadError):                     # cannot even reach the test server as "public"
        d.download(f"{server.base}/to-internal")
    d2, _ = downloader(tmp_path, server)
    with pytest.raises(DownloadError) as e:
        d2.download(f"{server.base}/to-http")
    assert e.value.code == "INVALID_ARGUMENT" and "https" in e.value.message
    with pytest.raises(DownloadError) as e:
        d2.download(f"{server.base}/loop")
    assert "redirects" in e.value.message


# --------------------------------------------------------------------- the file itself
def test_download_lands_in_the_inbox_complete_marked_and_never_overwriting(tmp_path, server):
    server.routes["/dl/Zoom It!.exe"] = ("body", BODY)
    server.routes["/redir"] = ("redirect", "/dl/Zoom It!.exe")
    d, _ = downloader(tmp_path, server)
    first = d.download(f"{server.base}/redir?token=secret")
    second = d.download(f"{server.base}/dl/Zoom%20It!.exe")
    inbox = tmp_path / "inbox"
    names = sorted(p.name for p in inbox.iterdir())
    assert names == ["Zoom_It_-2.exe", "Zoom_It_.exe"]                       # safe names, no overwrite
    assert first["file"] == {"name": "Zoom_It_.exe", "size": len(BODY), "sha256": hashlib.sha256(BODY).hexdigest()}
    assert "/dl/Zoom" in first["final_url"] and "token" not in first["final_url"] and second["file"]["name"] == "Zoom_It_-2.exe"
    assert first["sandbox_path"] == r"Desktop\Input\Zoom_It_.exe"
    assert (inbox / "Zoom_It_.exe").read_bytes() == BODY
    if sys.platform == "win32":
        motw = Path(f"{inbox / 'Zoom_It_.exe'}:Zone.Identifier").read_text(encoding="ascii")
        assert "ZoneId=3" in motw and "secret" not in motw


def test_size_limits_and_failures_leave_nothing_in_the_inbox(tmp_path, server, monkeypatch):
    server.routes["/big"] = ("body", b"x" * 2048)
    server.routes["/big-stream"] = ("stream", b"x" * 2048)
    server.routes["/missing"] = ("status", 404)
    d, _ = downloader(tmp_path, server, file_max=1024)
    for path in ("/big", "/big-stream", "/missing"):
        with pytest.raises(DownloadError):
            d.download(f"{server.base}{path}")
    monkeypatch.setattr(dl, "FILES_MAX", 0)
    server.routes["/ok"] = ("body", b"ok")
    with pytest.raises(DownloadError) as e:
        d.download(f"{server.base}/ok")
    assert e.value.code == "POLICY_DENIED"
    assert list((tmp_path / "inbox").iterdir()) == []


def test_a_zip_is_not_unpacked_on_the_host(tmp_path, server):
    server.routes["/tool.zip"] = ("body", b"PK\x05\x06" + b"\x00" * 18)
    d, _ = downloader(tmp_path, server)
    d.download(f"{server.base}/tool.zip")
    assert [p.name for p in (tmp_path / "inbox").iterdir()] == ["tool.zip"]


@pytest.mark.skipif(sys.platform != "win32", reason="deny-execute ACL is Windows")
def test_the_execute_probe_tells_a_prepared_inbox_from_an_unprepared_one(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    ok, why = check_no_execute(plain)
    assert not ok and "setup_inbox" in why
    guarded = tmp_path / "guarded"
    guarded.mkdir()
    subprocess.run(["icacls", str(guarded), "/deny", "*S-1-1-0:(OI)(IO)(X)"], check=True, capture_output=True)
    ok, why = check_no_execute(guarded)
    assert ok, why
    assert list(guarded.iterdir()) == [] and list(plain.iterdir()) == []      # probes removed


# --------------------------------------------------------------------- through the MCP Host
class InboxManager(FakeManager):
    def prepare(self, session_id, runtime_id, generation, runner_exe, inbox=None):
        self.calls.append(("prepare_inbox", str(inbox)))
        return super().prepare(session_id, runtime_id, generation, runner_exe)


class Watcher:
    made = []

    def __init__(self, manager, sandbox):
        self.started = self.stopped = False
        Watcher.made.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def test_inbox_download_through_the_mcp_host(tmp_path, server):
    server.routes["/zoomit.exe"] = ("body", BODY)
    d, _ = downloader(tmp_path, server)
    fake = InboxManager(tmp_path / "sbx")
    Watcher.made = []

    async def body():
        a = launch_args(tmp_path)
        a.inbox, a.inbox_watcher, a.inbox_downloader, a.inbox_skip_exec_check = d.inbox, Watcher, d, True
        backend = HostBackend(a, sandbox_manager=fake)
        backend.start()
        assert backend.ready.wait(20) and not backend.error, backend.error

        async def call(tool, arguments):
            r = await asyncio.to_thread(backend.call, tool, arguments)
            return json.loads(r["content"][-1]["text"])
        got = await call("inbox_download", {"url": f"{server.base}/zoomit.exe?sig=SECRET"})   # before task_submit
        bad = await call("inbox_download", {"url": "http://example.com/x.exe"})
        await call("task_submit", {"goal": "zoomit 받아서 실행"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        await asyncio.sleep(0.5)
        watched = [w.started for w in Watcher.made]
        await call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving
        await asyncio.to_thread(backend.shutdown)
        audit = [json.loads(l) for l in (tmp_path / "audit" / "SES-TEST-001.jsonl").read_text(encoding="utf-8").splitlines()]
        return got, bad, watched, audit

    got, bad, watched, audit = run(body())
    assert got["ok"] and got["file"]["sha256"] == hashlib.sha256(BODY).hexdigest()
    assert bad["error"] == "INVALID_ARGUMENT"                                  # schema: https only
    assert ("prepare_inbox", str(d.inbox)) in fake.calls
    assert watched == [True] and Watcher.made[0].stopped                        # watched until the end
    rec = next(x for x in audit if x.get("tool") == "inbox_download" and x["result"]["ok"])
    assert rec["policy"]["rule_id"] == "P-INBOX-DOWNLOAD"
    assert "SECRET" not in json.dumps(rec) and rec["result"]["download"]["sha256"] == got["file"]["sha256"]


def test_the_tool_is_listed_only_with_an_inbox():
    assert "inbox_download" in {t["name"] for t in load_tool_list({"host.inbox"})}
    assert "inbox_download" not in {t["name"] for t in load_tool_list()}


def test_bad_inbox_options_stop_before_codex_starts(tmp_path):
    def start(*extra):
        return subprocess.run([sys.executable, str(ROOT / "host" / "mcp_server.py"), *extra,
                               "--log-file", str(tmp_path / "m.log")],
                              capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    exe = tmp_path / "runner.exe"
    exe.write_bytes(b"MZ")
    no_runner = start("--inbox", str(tmp_path))
    in_docs = start("--runner-exe", str(exe), "--inbox", str(Path.home() / "Documents"))
    assert no_runner.returncode == 2 and "--runner-exe" in no_runner.stderr
    assert in_docs.returncode == 2 and "--inbox" in in_docs.stderr
