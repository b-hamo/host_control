"""Real Host/TLS/Broker with MiniRunner test double, not Windows Sandbox E2E."""

import asyncio
from pathlib import Path

import pytest

from host.router_sandbox import BrokerSandbox
from router.ports import Receipt, Request, State
from test_broker import certs, with_broker  # noqa: F401 - shared real TLS fixture
from test_router import execution, setup  # noqa: F401 - shared fixture


class InputOnlyDriver:
    """Test adapter intentionally has NO command completion proof."""
    def __init__(self, keys):
        self.keys = keys
        self.receipt = None

    def supports(self, request):
        return True

    async def submit(self, broker, request):
        result = await broker.call("computer_hotkey", {"keys": self.keys})
        state = State.ACCEPTED if result.ok else State.DENIED
        self.receipt = Receipt(request.request_id, request.action.fingerprint, state, "GUI_INPUT_ONLY")
        return self.receipt

    async def status(self, broker, request_id):
        return self.receipt

    async def verify(self, broker, receipt):
        return False


def test_broker_policy_denial_stops_before_runner(certs, setup):
    async def body(broker, runner):
        action = execution()
        host = setup([action], sandbox=BrokerSandbox(broker, InputOnlyDriver(["win", "r"])))
        result = await host.submit(Request("boundary-denied", action))
        assert result.state == State.DENIED
        assert runner.requests == []
        assert not host.local.results
    asyncio.run(with_broker(certs, body))


def test_actual_action_result_is_only_gui_delivery(certs, setup):
    async def body(broker, runner):
        action = execution()
        host = setup([action], sandbox=BrokerSandbox(broker, InputOnlyDriver(["ctrl", "a"])))
        result = await host.submit(Request("gui-ack", action))
        assert result.state == State.ACCEPTED
        assert len(runner.requests) == 1
        assert not await host.verify(result)
        await host.submit(Request("gui-ack", action))
        assert len(runner.requests) == 1
    asyncio.run(with_broker(certs, body))


def test_bridge_uses_actual_artifact_broker_final_reference(tmp_path):
    from test_artifact_export import Host, Approver, Scanner, candidate_id

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=Scanner())
        serving = None
        try:
            runner, serving = await host.start()
            await runner.report("result.txt", b"verified artifact bytes")
            aid = candidate_id(await host.call("artifact_list"), "result.txt")
            bridge = BrokerSandbox(host.backend.broker)
            with pytest.raises(ValueError, match="not exported"):
                bridge.artifact(aid)
            await host.call("artifact_export", {"artifact_id": aid})
            await host.wait_artifact(aid)
            artifact = bridge.artifact(aid)
            assert artifact.status == "EXPORTED"
            assert Path(artifact.final_ref).read_bytes() == b"verified artifact bytes"
            assert runner.puts == [(201, b"")]
        finally:
            await host.close(serving)
    asyncio.run(body())
