"""--agent-guard: one GUI Host per PC (host/single_host.py).

- with the guard, "initialize" starts nothing; the first tools/call starts the backend (lazy)
- right before that, only OUR older Host on the ports (and its venv launcher) is ended
- without the guard nothing changes
"""

from types import SimpleNamespace

from host.mcp_server import McpServer
from host.single_host import take_over


class FakeBackend:
    def __init__(self, guard):
        self.args = SimpleNamespace(agent_guard=guard, port=17443, upload_port=17444)
        self.ident = None
        self.calls = []

    def is_alive(self):
        return self.ident is not None

    def start(self):
        self.ident = 1
        self.calls.append("start")

    def call(self, tool, arguments):
        self.calls.append(tool)
        return {"content": [{"type": "text", "text": "{}"}], "isError": False}


def init(server):
    return server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})


def test_with_the_guard_the_backend_starts_at_the_first_tool_call(monkeypatch):
    taken = []
    monkeypatch.setattr("host.single_host.take_over", lambda ports: taken.append(ports) or [])
    b = FakeBackend(True)
    server = McpServer(b, [{"name": "task_submit"}])
    init(server)
    server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert b.calls == [] and taken == []                         # open conversation: no ports
    server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "task_submit",
                                                                                   "arguments": {}}})
    assert b.calls == ["start", "task_submit"] and taken == [(17443, 17444)]
    server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "task_submit",
                                                                                   "arguments": {}}})
    assert b.calls.count("start") == 1 and len(taken) == 1


def test_without_the_guard_initialize_starts_it_as_before(monkeypatch):
    monkeypatch.setattr("host.single_host.take_over", lambda ports: (_ for _ in ()).throw(AssertionError("no")))
    b = FakeBackend(False)
    init(McpServer(b, []))
    assert b.calls == ["start"]


def test_only_our_older_host_and_its_launcher_are_ended():
    procs = {101: ("python.exe C:/x/host_control/host/mcp_server.py --inbox x", 100),
             100: ("C:/x/.venv/Scripts/python.exe C:/x/host_control/host/mcp_server.py --inbox x", 50),
             50: ("codex.exe app-server", 1),
             999: ("python.exe C:/y/host/mcp_server.py --agent-guard", 998),
             202: ("C:\\Program Files\\Other\\server.exe --port 17443", 1)}
    held = {17443: {101}, 17444: {101}}
    killed = []

    def kill(pid):
        killed.append(pid)
        for s in held.values():
            s.discard(pid)
    ended = take_over((17443, 17444), me=999, listening=lambda p: set(held[p]),
                      info=lambda pid: procs.get(pid, ("", 0)), kill=kill, wait_s=0.1)
    assert sorted(ended) == [100, 101] and 50 not in killed            # never the Codex app itself

    held = {17443: {202}, 17444: set()}
    killed.clear()
    assert take_over((17443, 17444), me=999, listening=lambda p: set(held[p]),
                     info=lambda pid: procs.get(pid, ("", 0)), kill=kill, wait_s=0.1) == []
    assert killed == []                                                # someone else's program


def test_port_zero_takes_over_nothing():
    assert take_over((0, 0), me=1, listening=lambda p: {5}, info=lambda pid: ("host/mcp_server.py", 0),
                     kill=lambda pid: (_ for _ in ()).throw(AssertionError("killed")), wait_s=0) == []
