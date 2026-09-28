"""WBS 5.7: the MCP Server as Codex sees it, over real stdio.

Each test starts host/mcp_server.py as a child process, exactly as Codex
does, and speaks JSON-RPC to it line by line. The end-to-end test then
connects MiniRunner to the wss port it opened.
"""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mini_runner import MiniRunner

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "host" / "mcp_server.py"


class Client:
    def __init__(self, proc):
        self.proc, self.n = proc, 0

    async def rpc(self, method, params=None):
        self.n += 1
        self.proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method,
                                           "params": params or {}}) + "\n").encode())
        await self.proc.stdin.drain()
        reply = json.loads(await asyncio.wait_for(self.proc.stdout.readline(), 30))
        assert reply["id"] == self.n
        return reply

    async def call(self, tool, args=None):
        r = (await self.rpc("tools/call", {"name": tool, "arguments": args or {}}))["result"]
        body = json.loads(r["content"][0]["text"])
        assert r["isError"] is (not body["ok"])
        return body


async def start(tmp_path):
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(SERVER), "--port", "0", "--upload-port", "0", "--startup-timeout", "20",
        "--bootstrap-out", str(tmp_path / "bootstrap.json"), "--cert-dir", str(tmp_path / "certs"),
        "--audit-dir", str(tmp_path / "audit"), "--log-file", str(tmp_path / "mcp.log"),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    return proc, Client(proc)


async def stop(proc):
    proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), 10)
    except asyncio.TimeoutError:
        proc.kill()


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


def test_answers_codex_fast_and_lists_only_usable_tools(tmp_path):
    """ADR-002: Codex stops waiting after ~0.5-1 s; tools/list must be there by then."""
    async def body():
        t0 = time.perf_counter()
        proc, c = await start(tmp_path)
        init = (await c.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}))["result"]
        tools = (await c.rpc("tools/list"))["result"]["tools"]
        elapsed = time.perf_counter() - t0
        await stop(proc)
        return init, tools, elapsed

    init, tools, elapsed = run(body())
    # Loose bound: process start and first-run bytecode compilation vary a lot by
    # machine load. The deterministic check is the import test below.
    assert elapsed < 3.0, f"initialize + tools/list took {elapsed:.2f}s including process start"
    assert init["protocolVersion"] == "2025-06-18"            # the client's proposal is echoed
    assert "task_submit" in init["instructions"]
    names = {t["name"] for t in tools}
    assert {"task_submit", "computer_observe", "computer_click", "session_stop"} <= names
    assert not names & {"artifact_list", "artifact_export", "computer_click_element"}
    assert all(set(t) == {"name", "description", "inputSchema", "annotations"} for t in tools)


def test_tool_list_needs_no_heavy_imports():
    """What makes the front half fast: answering tools/list must not load the
    Host stack (jsonschema, websockets, cryptography take over a second)."""
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from host import mcp_server as m;"
        "tools = m.load_tool_list();"
        "srv = m.McpServer(m.HostBackend.__new__(m.HostBackend), tools);"
        "reply = srv.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'});"
        "heavy = [x for x in ('jsonschema', 'websockets', 'cryptography', 'host.broker', 'host.sender') if x in sys.modules];"
        "print(len(reply['result']['tools']), heavy)"
    )
    out = subprocess.run([sys.executable, "-c", code, str(ROOT)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    count, heavy = out.stdout.strip().split(" ", 1)
    assert int(count) >= 10 and heavy == "[]", out.stdout


def test_errors_are_mcp_tool_errors_not_protocol_errors(tmp_path):
    async def body():
        proc, c = await start(tmp_path)
        await c.rpc("initialize")
        before_task = await c.call("computer_observe")
        bad = await c.call("computer_click", {"x": "left"})
        unknown = await c.rpc("resources/list")
        await stop(proc)
        return before_task, bad, unknown

    before_task, bad, unknown = run(body())
    assert before_task["error"] == "POLICY_DENIED" and before_task["recommended_next_step"] == "task_submit"
    assert bad["error"] == "INVALID_ARGUMENT"
    assert unknown["error"]["code"] == -32601


def test_codex_to_runner_end_to_end(tmp_path):
    async def body():
        proc, c = await start(tmp_path)
        await c.rpc("initialize")
        assert (await c.call("task_submit", {"goal": "메모장에 인사말 입력"}))["ok"]
        while not (tmp_path / "bootstrap.json").exists():
            await asyncio.sleep(0.05)
        boot = json.loads((tmp_path / "bootstrap.json").read_text(encoding="utf-8"))
        r = MiniRunner(boot["port"], boot["host_certificate_pem"],
                       (boot["session_id"], boot["runtime_id"], boot["generation"]))
        await r.connect(boot["token"])
        serving = asyncio.create_task(r.serve())
        while (await c.call("runtime_get_state"))["runtime_state"] != "READY":
            await asyncio.sleep(0.1)
        obs = await c.call("computer_observe")
        click = await c.call("computer_click", {"x": 640, "y": 420})
        denied = await c.call("computer_hotkey", {"keys": ["win", "r"]})
        typed = await c.call("computer_type", {"text": "안녕하세요"})
        stop_ = await c.call("session_stop", {"reason": "TASK_COMPLETE"})
        assert await asyncio.wait_for(serving, 10) == "terminated"
        await stop(proc)
        audit = (tmp_path / "audit" / f"{boot['session_id']}.jsonl").read_text(encoding="utf-8")
        return r, obs, click, denied, typed, stop_, audit

    r, obs, click, denied, typed, stop_, audit = run(body())
    assert obs["ok"] and obs["width"] == 1280
    assert click["ok"] and click["status"] == "SUCCESS"
    assert denied["error"] == "POLICY_DENIED" and denied["rule_id"] == "P-DENY-HOTKEY"
    assert typed["ok"] and stop_["ok"]
    assert r.executed == [click["action_id"], typed["action_id"]]      # the denied hotkey never arrived
    assert "안녕하세요" not in audit and len(audit.splitlines()) >= 6


def test_observe_returns_the_screenshot_as_mcp_image_content(tmp_path):
    """Protocol doc §8: the Runner PUTs the PNG, the Host validates it, Codex gets an image block."""
    async def body():
        import base64
        proc, c = await start(tmp_path)
        await c.rpc("initialize")
        await c.call("task_submit", {"goal": "화면 보기"})
        while not (tmp_path / "bootstrap.json").exists():
            await asyncio.sleep(0.05)
        boot = json.loads((tmp_path / "bootstrap.json").read_text(encoding="utf-8"))
        assert boot["observation_upload"]["path"] == "/scrp/v1/observations/"
        r = MiniRunner(boot["port"], boot["host_certificate_pem"],
                       (boot["session_id"], boot["runtime_id"], boot["generation"]),
                       upload_port=boot["observation_upload"]["port"])
        await r.connect(boot["token"])
        serving = asyncio.create_task(r.serve())
        while (await c.call("runtime_get_state"))["runtime_state"] != "READY":
            await asyncio.sleep(0.1)
        raw = (await c.rpc("tools/call", {"name": "computer_observe", "arguments": {}}))["result"]
        r.drop()
        await serving
        await stop(proc)
        return raw, base64

    raw, base64 = run(body())
    kinds = [x["type"] for x in raw["content"]]
    assert kinds == ["image", "text"] and raw["isError"] is False
    png = base64.b64decode(raw["content"][0]["data"])
    assert raw["content"][0]["mimeType"] == "image/png" and png.startswith(b"\x89PNG")
    meta = json.loads(raw["content"][1]["text"])
    assert meta["image"] == "attached" and meta["image_state"] == "VALIDATED" and meta["width"] == 1280
