"""GUI driver state machine with transport/artifact doubles, no Guest execution."""

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from host.broker import ToolResult
from host.router_command_bundle import CommandBundle, output_directory
from host.router_gui_driver import GuiCommandDriver
from host.router_gui_policy import RouterGuiPolicy
from router.ports import Request, State
from test_router_inputs import bound, adapter  # noqa: F401


IDENTITY = ("SES-GUI", "RT-GUI", 1)


class Artifacts:
    def __init__(self):
        self.views = {}

    def precheck(self, session, aid):
        return SimpleNamespace(relative_path=self.views[aid]["path"], aid=aid)

    def view(self, art):
        return self.views[art.aid]


class BrokerDouble:
    def __init__(self, manager, policy):
        self.policy = policy
        self.session = SimpleNamespace(identity=IDENTITY, ready=asyncio.Event(), actions={})
        self.launcher = SimpleNamespace(manager=manager, sandbox=None)
        self.artifacts = Artifacts()
        self.inputs, self.states = [], 0
        self.timeout_tool = None
        self.after_type = None
        self.reject_tool = self.partial_tool = None

    async def call(self, tool, args):
        decision = self.policy.decide(tool, args)
        if decision.result == "DENY":
            return ToolResult(False, error={"error": "POLICY_DENIED"})
        if tool == "computer_observe":
            return ToolResult(True, {}, image=b"test-double-image")
        if tool.startswith("computer_"):
            self.inputs.append((tool, args))
            if tool == "computer_type" and self.after_type:
                self.after_type()
            if tool == self.timeout_tool:
                return ToolResult(False, error={"error": "ACTION_TIMEOUT"}, action_id="ACT-1")
            if tool == self.reject_tool:
                self.session.actions["ACT-1"] = "REJECTED"
                return ToolResult(False, error={"error": "ACTION_FAILED"}, action_id="ACT-1")
            return ToolResult(True, {"status": "PARTIAL_SUCCESS" if tool == self.partial_tool else "SUCCESS",
                                     "result": {"input_delivered": True}}, action_id="ACT-1")
        if tool == "runtime_get_state":
            self.states += 1
            return ToolResult(True, {})
        if tool == "artifact_list":
            return ToolResult(True, {"artifacts": list(self.artifacts.views.values()), "next_cursor": None})
        raise AssertionError(tool)


async def configured(bound, tmp_path):
    action = replace(bound.action,
        command=replace(bound.action.command,
                        executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        scope=replace(bound.action.scope, writes=(output_directory(IDENTITY),),
                      capabilities=("process.execute", "gui.input", "gui.observe", "artifact.export.v1")),
        outputs=("stdout",))
    bound.action = action
    grant = bound.authority.delegations[action.delegation_ref]
    bound.authority.delegations[action.delegation_ref] = replace(grant, scope=action.scope,
                                                               execution_fingerprints=frozenset({action.fingerprint}))
    manager = adapter(bound)
    policy = RouterGuiPolicy(bound.authority, command_launch_enabled=True)
    driver = GuiCommandDriver(manager, policy, tmp_path / "transport")
    broker = BrokerDouble(manager, policy)
    request = Request("REQ-GUI", action)
    await driver.prepare(broker, request)
    broker.launcher.sandbox = manager.prepare(*IDENTITY, Path("runner.exe"))
    broker.session.ready.set()
    return driver, broker, request


def exported(broker, tmp_path, name, data, aid):
    path = tmp_path / name
    path.write_bytes(data)
    broker.artifacts.views[aid] = dict(artifact_id=aid, path=name, status="EXPORTED", generation=1,
                                     sha256=hashlib.sha256(data).hexdigest(), export_path=str(path), can_export=False)


def evidence(driver, broker, tmp_path, **changes):
    stdout = b"real stdout is simulated in this unit test\n"
    doc = {**driver.bundle.expected, "execution_count": 1, "process_id": 123, "exit_code": 0,
           "stdout_sha256": hashlib.sha256(stdout).hexdigest(), **changes}
    exported(broker, tmp_path, driver.bundle.evidence_name, json.dumps(doc).encode(), "ART-EVIDENCE")
    exported(broker, tmp_path, driver.bundle.stdout_name, stdout, "ART-STDOUT")


def test_input_ack_does_not_complete_and_duplicate_submit_does_not_replay(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        assert (await driver.submit(broker, request)).state == State.ACCEPTED
        await driver._launch_task
        assert (await driver.status(broker, request.request_id)).state == State.RUNNING
        await driver.submit(broker, request)
        await driver.status(broker, request.request_id)
        assert len(broker.inputs) == 3
        assert not await driver.verify(broker, driver.receipt)
        evidence(driver, broker, tmp_path)
        result = await driver.status(broker, request.request_id)
        assert result.state == State.SUCCEEDED
        assert result.artifacts[0].artifact_id == "ART-STDOUT"
        assert result.artifacts[0].output_name == "stdout"
        assert await driver.verify(broker, result)
    asyncio.run(check())


def test_timeout_polls_state_and_never_repeats_input(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        broker.timeout_tool = "computer_keypress"
        await driver.submit(broker, request)
        await driver._launch_task
        assert driver.receipt.state == State.UNKNOWN
        await driver.status(broker, request.request_id)
        await driver.submit(broker, request)
        assert broker.states == 1 and len(broker.inputs) == 3
        evidence(driver, broker, tmp_path)
        assert (await driver.status(broker, request.request_id)).state == State.SUCCEEDED
    asyncio.run(check())


@pytest.mark.parametrize("changed", ["source", "transport"])
def test_mutation_after_typing_prevents_enter(bound, tmp_path, changed):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        target = bound.path if changed == "source" else driver.bundle.inputs[0].path
        broker.after_type = lambda: target.write_text("changed", encoding="utf-8")
        await driver.submit(broker, request)
        await driver._launch_task
        assert driver.receipt.state == State.UNKNOWN
        assert [t for t, _ in broker.inputs] == ["computer_hotkey", "computer_type"]
    asyncio.run(check())


@pytest.mark.parametrize("changes", [{"fingerprint": "wrong"}, {"execution_count": 2}, {"process_id": 0},
                                    {"runtime_id": "OTHER"}, {"sources": {}}, {"exit_code": True}])
def test_unbound_or_incomplete_receipt_cannot_complete(bound, tmp_path, changes):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        await driver.submit(broker, request)
        await driver._launch_task
        evidence(driver, broker, tmp_path, **changes)
        assert (await driver.status(broker, request.request_id)).state == State.UNKNOWN
    asyncio.run(check())


def test_nonzero_exit_fails_without_downstream_success(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        await driver.submit(broker, request)
        await driver._launch_task
        evidence(driver, broker, tmp_path, exit_code=7)
        assert (await driver.status(broker, request.request_id)).state == State.FAILED
    asyncio.run(check())


def test_changed_final_evidence_is_not_verified(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        await driver.submit(broker, request)
        await driver._launch_task
        evidence(driver, broker, tmp_path)
        receipt = await driver.status(broker, request.request_id)
        (tmp_path / driver.bundle.evidence_name).write_text("changed", encoding="utf-8")
        assert not await driver.verify(broker, receipt)
    asyncio.run(check())


def test_changed_generation_cannot_reuse_execution(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        await driver.submit(broker, request)
        await driver._launch_task
        evidence(driver, broker, tmp_path)
        broker.session.identity = (*IDENTITY[:2], 2)
        assert (await driver.status(broker, request.request_id)).state == State.UNKNOWN
        await driver.submit(broker, request)
        assert len(broker.inputs) == 3
    asyncio.run(check())


def test_scanner_block_is_held_without_local_fallback(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        await driver.submit(broker, request)
        await driver._launch_task
        evidence(driver, broker, tmp_path)
        broker.artifacts.views["ART-EVIDENCE"]["status"] = "BLOCKED"
        assert (await driver.status(broker, request.request_id)).state == State.HELD
        assert len(broker.inputs) == 3
    asyncio.run(check())


def test_explicit_runner_rejection_is_terminal_and_not_retried(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        broker.reject_tool = "computer_hotkey"
        await driver.submit(broker, request)
        await driver._launch_task
        assert driver.receipt.state == State.DENIED
        await driver.status(broker, request.request_id)
        await driver.submit(broker, request)
        assert len(broker.inputs) == 1 and broker.states == 0
    asyncio.run(check())


def test_partial_type_does_not_press_enter_or_accept_early_receipt(bound, tmp_path):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        broker.partial_tool = "computer_type"
        await driver.submit(broker, request)
        await driver._launch_task
        assert driver.receipt.state == State.UNKNOWN
        evidence(driver, broker, tmp_path)
        assert (await driver.status(broker, request.request_id)).state == State.UNKNOWN
        assert len(broker.inputs) == 2
    asyncio.run(check())


@pytest.mark.parametrize("change", ["unreserved", "foreign_name", "runtime", "delegation"])
def test_export_delegation_is_limited_to_current_command(bound, tmp_path, change):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        evidence(driver, broker, tmp_path)
        driver._exports.add("ART-EVIDENCE")
        summary = {"tool": "artifact_export", "session_id": IDENTITY[0],
                   "runtime_id": IDENTITY[1], "artifact_id": "ART-EVIDENCE"}
        assert await driver.approve_export(summary)
        if change == "unreserved":
            summary["artifact_id"] = "ART-STDOUT"
        elif change == "foreign_name":
            broker.artifacts.views["ART-EVIDENCE"]["path"] = "unrelated.txt"
        elif change == "runtime":
            summary["runtime_id"] = "OTHER"
        else:
            del bound.authority.delegations[request.action.delegation_ref]
        assert not await driver.approve_export(summary)
    asyncio.run(check())


@pytest.mark.parametrize("failure", ["terminated", "launcher", "timeout"])
def test_failed_start_stops_without_any_input(bound, tmp_path, failure):
    async def check():
        driver, broker, request = await configured(bound, tmp_path)
        broker.session.ready.clear()
        if failure == "terminated":
            broker.session.terminated = True
        elif failure == "launcher":
            broker.launcher.state = "FAILED"
        else:
            driver.startup_timeout = 0
        await driver.submit(broker, request)
        await driver._launch_task
        assert driver.receipt.state == State.FAILED
        assert broker.inputs == []
        await driver.submit(broker, request)
        assert broker.inputs == []
    asyncio.run(check())
