"""Dashboard backend: Host status files (host/dashboard_status.py), the overview (dashboard/collect.py),
the local read-only server (dashboard/server.py), and a real MCP Host writing its status."""

import asyncio
import http.client
import json
import struct
import sys
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dashboard.collect import Collector, HostMeter, VmMeter, risk_type
from dashboard.server import Dashboard, serve
from host.dashboard_status import DashboardStatus
from mini_runner import MiniRunner

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 10, 5, 0, 0, tzinfo=timezone.utc)


def png(w=4, h=3):
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))  # noqa: E731
    raw = b"".join(b"\x00" + b"\x80" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def at(seconds_ago):
    return (NOW - timedelta(seconds=seconds_ago)).isoformat().replace("+00:00", "Z")


def session(root, sid, kind, state, *, started=120, ended=None, reason=None, files=(), container=None, sandbox=None):
    events = [{"at": at(started), "kind": "PREPARED"}]
    events += [{"at": at(started - 1), "kind": "INBOX_FILE_REGISTERED", "name": n} for n in files]
    if ended is not None:
        events.append({"at": at(ended), "kind": "STATE", "from": "RUNNING", "to": state, "reason": reason})
    data = {"session_id": sid, "state": state, "runtime_type": kind, "termination_reason": reason,
            "sandbox_id": sandbox, "owner": {"pid": 4242, "started": 1}, "events": events,
            "micro_vm": {"container_id": container} if container else None}
    (root / "sessions" / sid).mkdir(parents=True)
    (root / "sessions" / sid / "state.json").write_text(json.dumps(data), encoding="utf-8")


class FakeHostMeter:
    def read(self):
        return {"cpu_percent": 64.0, "mem_percent": 72}


def stats_from(table):
    def read(system_id):
        if table.get(system_id) == "denied":
            raise PermissionError("0x8037011b")
        return table[system_id]
    return read


@pytest.fixture
def board(tmp_path):
    main, other, dash = tmp_path / "manager", tmp_path / "solution-sandbox", tmp_path / "dashboard"
    session(main, "SES-wsb", "WINDOWS_SANDBOX", "RUNNING", files=["setup.exe", "run-abc.ps1", "run-abc.json"],
            sandbox="wsb-1")
    session(main, "SES-vm1", "MICRO_VM_APP_WINDOW", "RUNNING", started=100, container="c-1")
    session(main, "SES-vm2", "MICRO_VM_APP_WINDOW", "STARTING", started=10)
    session(main, "SES-bad", "MICRO_VM_APP_WINDOW", "TERMINATED", started=90, ended=30, reason="SECURITY_VIOLATION",
            files=["install.ps1"])
    session(main, "SES-old", "WINDOWS_SANDBOX", "TERMINATED", started=9000, ended=8000, reason="TASK_COMPLETE")
    session(other, "SES-vm3", "MICRO_VM_APP_WINDOW", "RUNNING", started=60, container="c-3")
    hosts = dash / "hosts"
    hosts.mkdir(parents=True)
    (hosts / "SES-wsb.json").write_text(json.dumps({
        "session_id": "SES-wsb", "task": "매크로 문서 열어 보기", "last_tool": "computer_observe", "last_ok": True,
        "last_activity_at": at(2), "window_state": "OPEN", "screen_captured_at": at(2)}), encoding="utf-8")
    (hosts / "SES-wsb.png").write_bytes(png(1280, 720))
    (hosts / "SES-vm3.json").write_text(json.dumps({"session_id": "SES-vm3", "sandbox_root": str(other),
                                                    "vm_max": 6, "ended_at": None}), encoding="utf-8")
    clock = [NOW.timestamp()]
    vm = VmMeter(stats_from({"wsb-1": {"Processor": {"TotalRuntime100ns": 0}, "Memory": {"MemoryUsageCommitBytes": 2_576_980_378}},
                             "c-1": {"Processor": {"TotalRuntime100ns": 0}, "Memory": {"MemoryUsageCommitBytes": 858_993_459}},
                             "c-3": "denied"}), cpus=4, clock=lambda: clock[0])
    c = Collector([main], dash, wsb=lambda: 1, host_meter=FakeHostMeter(), vm_meter=vm,
                  clock=lambda: clock[0], pid_alive=lambda pid: pid == 4242)
    return c, clock


# --------------------------------------------------------------------- the overview
def test_the_overview_follows_the_frontend_contract(board):
    c, _ = board
    o = c.overview()
    assert set(o) == {"updated_at", "runtimes", "host_resources", "metrics", "sessions"}
    assert o["runtimes"]["windows_sandbox"] == {"running": 1, "state": "RUNNING", "window_state": "OPEN"}
    assert o["runtimes"]["micro_vm"] == {"running": 2, "max": 6, "starting": 1, "failed": 0, "free_slots": 3}
    assert o["host_resources"] == {"cpu_percent": 64.0, "mem_percent": 72}
    by = {s["id"]: s for s in o["sessions"]}
    assert "SES-old" not in by                                   # ended long ago: off the board
    assert [s["label"] for s in o["sessions"]] == ["GUI-01", "VM-01", "VM-02", "VM-03", "VM-04"]
    wsb = by["SES-wsb"]
    assert wsb["runtime"] == "windows_sandbox" and wsb["network"] == "enabled" and wsb["window_state"] == "OPEN"
    assert wsb["risk_type"] == "미확인 실행파일 (setup.exe)"       # the Host's run helpers are not the user's file
    assert wsb["task"] == "매크로 문서 열어 보기" and wsb["last_activity"]["tool"] == "computer_observe"
    assert wsb["mem_bytes"] == 2_576_980_378 and wsb["host_alive"] is True
    assert wsb["screenshot"] == {"available": True, "captured_at": at(2)}
    assert wsb["started_at"] == at(120).replace(".000", "")
    bad = by["SES-bad"]
    assert bad["display_state"] == "VIOLATION" and bad["state"] == "TERMINATED"
    assert bad["termination_reason"] == "SECURITY_VIOLATION" and bad["risk_type"] == "스크립트 실행 (install.ps1)"
    assert bad["network"] == "blocked" and bad["window_state"] is None and bad["cpu_percent"] is None
    assert "SES-vm3" in by                                       # found through the root its Host reported


def test_vm_cpu_is_a_share_of_the_whole_pc_and_needs_two_reads(board):
    c, clock = board
    stats = c.vm_meter._stats
    first = c.overview()
    assert {s["id"]: s["cpu_percent"] for s in first["sessions"]}["SES-vm1"] is None
    clock[0] += 2
    c.vm_meter._stats = lambda i: ({"Processor": {"TotalRuntime100ns": 2 * 10**7}, "Memory": {}} if i == "c-1" else stats(i))
    assert {s["id"]: s["cpu_percent"] for s in c.overview()["sessions"]}["SES-vm1"] == 25.0   # 2 s of CPU in 2 s on 4 CPUs


def test_without_administrator_the_numbers_are_null_and_the_reason_is_given():
    vm = VmMeter(stats_from({"x": "denied"}))
    assert vm.read("x") == (None, None)
    assert "administrator" in vm.reason
    assert VmMeter(stats_from({})).read(None) == (None, None)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows counters")
def test_host_meter_reads_this_pc():
    m = HostMeter()
    time.sleep(0.2)
    r = m.read()
    assert 0 <= r["cpu_percent"] <= 100 and 0 < r["mem_percent"] <= 100


@pytest.mark.parametrize("files, tool, label", [
    (["a.docm"], None, "매크로 문서 (a.docm)"), (["p.zip"], None, "외부 프로젝트 (p.zip)"),
    (["r.pdf"], None, "받은 파일 열기 (r.pdf)"), ([], "router_execute", "웹페이지 명령"),
    ([], "computer_click", "화면 작업"), ([], None, "일반 작업"),
])
def test_risk_type_labels(files, tool, label):
    assert risk_type(files, tool) == label


# --------------------------------------------------------------------- the server
@pytest.fixture
def server(board, tmp_path):
    c, _ = board
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<p>dashboard</p>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("no", encoding="utf-8")
    app = Dashboard(c, "t0ken", static)
    srv = serve(app, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def get(port, path, token="t0ken", host=None, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request(method, path, headers=headers)
    r = conn.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def test_the_api_needs_the_token_and_this_host(server):
    assert get(server, "/api/dashboard/overview", token=None)[0] == 401
    assert get(server, "/api/dashboard/overview", token="wrong")[0] == 401
    assert get(server, "/api/dashboard/overview", host="evil.example:80")[0] == 403    # DNS rebinding
    assert get(server, "/api/dashboard/overview?token=t0ken", token=None)[0] == 200     # <img src> form
    assert get(server, "/api/dashboard/overview", method="POST")[0] == 405


def test_overview_and_screenshot(server):
    code, headers, body = get(server, "/api/dashboard/overview")
    assert code == 200 and headers["Content-Type"].startswith("application/json")
    assert headers["Cache-Control"] == "no-store"
    o = json.loads(body)
    assert o["runtimes"]["micro_vm"]["running"] == 2
    code, headers, body = get(server, "/api/runtimes/GUI-01/screenshot")                 # by label
    assert code == 200 and headers["Content-Type"] == "image/png" and body.startswith(b"\x89PNG")
    assert headers["X-Captured-At"] == at(2)
    code, _, body = get(server, "/api/runtimes/SES-wsb/screenshot?format=json")          # by session id
    assert json.loads(body) == {"image_url": "/api/runtimes/SES-wsb/screenshot", "captured_at": at(2),
                                "width": 1280, "height": 720}
    assert get(server, "/api/runtimes/VM-01/screenshot")[0] == 404                       # nothing observed yet
    assert get(server, "/api/runtimes/..%2F..%2Fsecret/screenshot")[0] == 404


def test_static_page_and_no_escape(server):
    code, headers, body = get(server, "/", token=None)
    assert code == 200 and body == "<p>dashboard</p>".encode() and "text/html" in headers["Content-Type"]
    assert get(server, "/../secret.txt", token=None)[0] == 404


# --------------------------------------------------------------------- the Host side
def test_host_status_keeps_names_not_contents(tmp_path):
    states = iter(["UNSEEN", "OPEN", "OPEN"])
    s = DashboardStatus(tmp_path, "SES-1", sandbox_root=tmp_path / "sb", vm_max=8,
                        window_state=lambda: next(states, "OPEN"), refresh_s=0.05)
    s.record("task_submit", {"goal": "  7-Zip\n받아서   설치해 줘 " + "x" * 300}, True)
    s.record("computer_type", {"text": "비밀번호123"}, True)
    s.record("inbox_download", {"url": "https://example.com/dl/7z.exe?sig=SECRET"}, True)
    s.record("computer_observe", {}, True, png())
    time.sleep(0.3)
    raw = (tmp_path / "hosts" / "SES-1.json").read_text(encoding="utf-8")
    d = json.loads(raw)
    assert d["task"].startswith("7-Zip 받아서 설치해 줘 ") and len(d["task"]) == 200
    assert "비밀번호123" not in raw and "SECRET" not in raw
    assert d["last_tool"] == "computer_observe" and d["last_file"] == "7z.exe" and d["window_state"] == "OPEN"
    assert (tmp_path / "hosts" / "SES-1.png").read_bytes() == png() and d["screen_captured_at"]
    s.close()
    d = json.loads((tmp_path / "hosts" / "SES-1.json").read_text(encoding="utf-8"))
    assert d["ended_at"] and not (tmp_path / "hosts" / "SES-1.png").exists()


def test_a_real_host_writes_its_status_for_the_dashboard(tmp_path):
    """--dashboard-dir on the real MCP server: task, last tool and the observed screen; gone at the end."""
    dash = tmp_path / "dash"

    async def body():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(ROOT / "host" / "mcp_server.py"), "--port", "0", "--upload-port", "0",
            "--startup-timeout", "20", "--bootstrap-out", str(tmp_path / "bootstrap.json"),
            "--cert-dir", str(tmp_path / "certs"), "--audit-dir", str(tmp_path / "audit"),
            "--log-file", str(tmp_path / "mcp.log"), "--dashboard-dir", str(dash),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        n = 0

        async def call(method, params=None):
            nonlocal n
            n += 1
            proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": n, "method": method, "params": params or {}}) + "\n").encode())
            await proc.stdin.drain()
            return json.loads(await asyncio.wait_for(proc.stdout.readline(), 30))

        await call("initialize")
        await call("tools/call", {"name": "task_submit", "arguments": {"goal": "화면 보기"}})
        while not (tmp_path / "bootstrap.json").exists():
            await asyncio.sleep(0.05)
        boot = json.loads((tmp_path / "bootstrap.json").read_text(encoding="utf-8"))
        r = MiniRunner(boot["port"], boot["host_certificate_pem"], (boot["session_id"], boot["runtime_id"], boot["generation"]),
                       upload_port=boot["observation_upload"]["port"])
        await r.connect(boot["token"])
        serving = asyncio.create_task(r.serve())
        while True:
            st = await call("tools/call", {"name": "runtime_get_state", "arguments": {}})
            if json.loads(st["result"]["content"][0]["text"]).get("runtime_state") == "READY":
                break
            await asyncio.sleep(0.1)
        await call("tools/call", {"name": "computer_observe", "arguments": {}})
        status_path = dash / "hosts" / f"{boot['session_id']}.json"
        during = json.loads(status_path.read_text(encoding="utf-8"))
        image_during = (dash / "hosts" / f"{boot['session_id']}.png").is_file()
        r.drop()
        await serving
        proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), 30)
        except asyncio.TimeoutError:
            proc.kill()
        return boot["session_id"], during, image_during

    sid, during, image_during = asyncio.run(asyncio.wait_for(body(), 90))
    assert during["task"] == "화면 보기" and during["last_tool"] == "computer_observe" and during["last_ok"] is True
    assert image_during and during["screen_captured_at"]
    after = json.loads((dash / "hosts" / f"{sid}.json").read_text(encoding="utf-8"))
    assert after["ended_at"] and not (dash / "hosts" / f"{sid}.png").exists()


def test_the_solution_turns_the_dashboard_status_on(tmp_path):
    from host import solution
    from host.dashboard_status import default_dir
    args = solution.host_arguments(tmp_path / "r.exe", tmp_path / "w", tmp_path / "s")
    assert args[args.index("--dashboard-dir") + 1] == str(default_dir())
