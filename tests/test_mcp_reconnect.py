"""Real local sockets and subprocesses; no Sandbox or execution payload is started."""
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from host.mcp_shared import SharedClient, attach, connect, exclusive, fingerprint, read, serve, write
from host.mcp_stdio import serve_stdio
from types import SimpleNamespace


def connect_only(directory, config_id, *, cancel):
    # The tests own their fake Host lifecycle. Do not launch a real Host on failure.
    return connect(directory, config_id)


class FakeServer:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.initialized = False

    def handle(self, message):
        method = message["method"]
        if method == "initialize":
            if (self.directory / "block-initialize").exists():
                (self.directory / "initializing").write_text("waiting")
                time.sleep(60)
            self.initialized = True
        elif method == "notifications/initialized":
            return None
        elif not self.initialized:
            return {"jsonrpc": "2.0", "id": message["id"],
                    "error": {"code": -32000, "message": "Initialize first"}}
        if method == "tools/call":
            with (self.directory / "calls.jsonl").open("a", encoding="utf-8") as file:
                file.write(json.dumps(message) + "\n")
            if message["params"]["name"] == "crash_after_accept":
                os._exit(17)  # Side effect recorded, but no response: never replay this request.
            if message["params"]["name"] == "block":
                time.sleep(60)
            if message["params"]["name"] == "cleanup_guard":
                return {"jsonrpc": "2.0", "id": message["id"], "result": {
                    "isError": True, "content": [{"type": "text", "text": "CLEANUP_UNCONFIRMED"}]}}
        return {"jsonrpc": "2.0",
                "id": "wrong" if method == "wrong_id" else message.get("id"),
                "result": {"pid": os.getpid(), "method": method}}


def child():
    mode, directory, config_id = sys.argv[1:4]
    if mode == "owner":
        with exclusive(directory):
            serve(FakeServer(directory), directory, config_id)
    elif mode == "client":
        client = SharedClient(directory, config_id, connector=connect_only)
        serve_stdio(client, close=client.close, alive=client.alive)


class ReconnectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.processes = []
        self.streams = []
        self.owner = self.start_owner()

    def tearDown(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        for sock, stream in self.streams:
            stream.close()
            sock.close()
        self.temp.cleanup()

    def spawn(self, mode, config="test-config"):
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), mode, str(self.directory), config],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.processes.append(process)
        return process

    def start_owner(self, config="test-config"):
        process = self.spawn("owner", config)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                endpoint = json.loads((self.directory / "endpoint.json").read_text())
                if endpoint["pid"] == process.pid:
                    return process
            except (OSError, ValueError):
                pass
            if process.poll() is not None:
                self.fail(process.stderr.read().decode())
            time.sleep(0.02)
        self.fail("Owner failed to publish endpoint")

    def start_client(self):
        process = self.spawn("client")
        replies = queue.Queue()
        def receive():
            for line in process.stdout:
                replies.put(json.loads(line))
            replies.put(None)
        threading.Thread(target=receive, daemon=True).start()
        return process, replies

    def send(self, process, message):
        process.stdin.write(json.dumps(message).encode() + b"\n")
        process.stdin.flush()

    def request(self, process, replies, method, rid=1, params=None):
        self.send(process, {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        response = replies.get(timeout=6)
        self.assertIsNotNone(response, "stdio unexpectedly closed")
        self.assertEqual(response["id"], rid)
        return response

    def initialize(self, process, replies):
        result = self.request(process, replies, "initialize")
        self.assertIn("result", result)
        self.send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def terminate_owner(self):
        self.owner.terminate()
        self.owner.wait(timeout=5)
        time.sleep(0.2)  # Let the client's receiver observe socket EOF.

    def test_idle_restart_keeps_same_stdio_and_negotiates_new_owner(self):
        process, replies = self.start_client()
        first = self.initialize(process, replies)["result"]["pid"]
        for rid in (2, 3):
            self.terminate_owner()
            self.assertIsNone(process.poll())
            self.owner = self.start_owner()
            response = self.request(process, replies, "ping", rid)
            self.assertEqual(response["result"]["pid"], self.owner.pid)
            self.assertNotEqual(response["result"]["pid"], first)

    def test_lost_tool_reply_is_unknown_and_never_replayed(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        response = self.request(process, replies, "tools/call", 10, {
            "name": "crash_after_accept", "arguments": {"request_id": "original-request"}})
        error = json.loads(response["result"]["content"][0]["text"])
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(error["error"], "MCP_REQUEST_OUTCOME_UNKNOWN")
        self.assertEqual(error["outcome"], "UNKNOWN")
        self.assertEqual(error["request_id"], "original-request")
        self.assertFalse(error["replayed"])
        self.owner.wait(timeout=5)
        self.owner = self.start_owner()
        self.assertIn("result", self.request(process, replies, "ping", 11))
        calls = (self.directory / "calls.jsonl").read_text().splitlines()
        self.assertEqual([json.loads(row)["id"] for row in calls], [10])

    def test_unavailable_owner_reports_not_sent_then_recovers(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        self.terminate_owner()
        response = self.request(process, replies, "tools/call", 20, {"name": "never_sent"})
        error = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(error["error"], "MCP_HOST_UNAVAILABLE")
        self.assertEqual(error["outcome"], "NOT_SENT")
        self.assertIsNone(process.poll())
        self.owner = self.start_owner()
        self.assertIn("result", self.request(process, replies, "ping", 21))
        self.assertFalse((self.directory / "calls.jsonl").exists())

    def test_wrong_config_blocks_request_without_closing_stdio(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        self.terminate_owner()
        self.owner = self.start_owner("different-config")
        result = self.request(process, replies, "ping", 30)
        self.assertEqual(result["error"]["data"]["outcome"], "NOT_SENT")
        self.terminate_owner()
        self.owner = self.start_owner()
        self.assertIn("result", self.request(process, replies, "ping", 31))

    def test_bad_token_is_rejected_before_any_tool(self):
        endpoint = json.loads((self.directory / "endpoint.json").read_text())
        sock = socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=2)
        stream = sock.makefile("rwb")
        self.streams.append((sock, stream))
        write(stream, {"token": "incorrect", "config": "test-config"})
        self.assertEqual(read(stream), {"error": "SHARED_AUTHENTICATION_FAILED"})
        self.assertFalse((self.directory / "calls.jsonl").exists())

    def test_mismatched_response_invalidates_socket_not_stdio(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        response = self.request(process, replies, "wrong_id", 40)
        self.assertEqual(response["error"]["data"]["outcome"], "UNKNOWN")
        self.assertIn("result", self.request(process, replies, "ping", 41))

    def test_stdin_eof_while_pending_exits_client_leaves_owner(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        self.send(process, {"jsonrpc": "2.0", "id": 50, "method": "tools/call",
                            "params": {"name": "block"}})
        deadline = time.monotonic() + 3
        while not (self.directory / "calls.jsonl").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue((self.directory / "calls.jsonl").exists())
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertIsNone(self.owner.poll())

    def test_stdin_eof_after_owner_loss_exits_client(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        self.terminate_owner()
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 0)

    def test_stdin_eof_during_reconnect_initialization(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        self.terminate_owner()
        (self.directory / "block-initialize").write_text("yes")
        self.owner = self.start_owner()
        self.send(process, {"jsonrpc": "2.0", "id": 55, "method": "ping"})
        deadline = time.monotonic() + 3
        while not (self.directory / "initializing").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue((self.directory / "initializing").exists())
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 0)

    def test_cleanup_guard_is_returned_unchanged(self):
        process, replies = self.start_client()
        self.initialize(process, replies)
        self.terminate_owner()
        self.owner = self.start_owner()
        response = self.request(process, replies, "tools/call", 60, {"name": "cleanup_guard"})
        self.assertEqual(response["result"]["content"][0]["text"], "CLEANUP_UNCONFIRMED")
        self.assertTrue(response["result"]["isError"])

    def test_concurrent_calls_cannot_mix_response_ids(self):
        client = SharedClient(self.directory, "test-config", connector=connect_only)
        try:
            client({"id": 1, "method": "initialize"})
            results = {}
            threads = [threading.Thread(target=lambda rid: results.update(
                {rid: client({"id": rid, "method": "ping"})}), args=(rid,)) for rid in range(2, 12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual({key: value["id"] for key, value in results.items()},
                             {rid: rid for rid in range(2, 12)})
        finally:
            client.close()

    def test_owner_lock_prevents_second_owner(self):
        with self.assertRaises(OSError):
            with exclusive(self.directory):
                self.fail("Second owner acquired the lock")

    def test_attach_starts_replacement_owner_without_replaying_tools(self):
        self.terminate_owner()
        original_popen = subprocess.Popen
        def tracked_popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            self.processes.append(process)
            return process
        command = [str(Path(__file__).resolve()), "owner", str(self.directory), "test-config"]
        client = SharedClient(self.directory, "test-config")
        try:
            with patch.object(sys, "argv", command), patch(
                    "host.mcp_shared.subprocess.Popen", side_effect=tracked_popen):
                first = client({"id": 70, "method": "initialize"})
                self.assertIn("result", first)
                self.owner = self.processes[-1]
                self.terminate_owner()
                response = client({"id": 71, "method": "ping"})
                self.assertEqual(response["result"]["pid"], self.processes[-1].pid)
                self.assertNotEqual(response["result"]["pid"], first["result"]["pid"])
                self.assertFalse((self.directory / "calls.jsonl").exists())
        finally:
            client.close()

    def test_attach_authentication_failure_does_not_spawn(self):
        endpoint_path = self.directory / "endpoint.json"
        metadata = json.loads(endpoint_path.read_text())
        metadata["token"] = "incorrect"
        endpoint_path.write_text(json.dumps(metadata))
        with patch("host.mcp_shared.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "SHARED_AUTHENTICATION_FAILED"):
                attach(self.directory, "test-config")
            spawn.assert_not_called()

    def test_fingerprint_ignores_log_paths_but_not_configuration(self):
        a = SimpleNamespace(shared_state="same", inbox="same", log_file="a")
        b = SimpleNamespace(shared_state="same", inbox="same", log_file="b")
        self.assertEqual(fingerprint(a), fingerprint(b))
        b.inbox = "other"
        self.assertNotEqual(fingerprint(a), fingerprint(b))

    def test_cli_rejects_missing_relative_or_mapped_state(self):
        for arguments in (
            ["--shared-runtime"],
            ["--shared-state", str(self.directory)],
            ["--shared-runtime", "--shared-state", "relative"],
            ["--shared-runtime", "--shared-state", str(self.directory),
             "--inbox", str(self.directory / "inbox")],
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "host" / "mcp_server.py"), *arguments],
                    capture_output=True, timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertIn(b"--shared-", result.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {"owner", "client"}:
        child()
    else:
        unittest.main()
