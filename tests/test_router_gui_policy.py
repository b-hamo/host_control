"""Scoped policy tests. MiniRunner cases are GUI transport tests, not Guest E2E."""

import asyncio
from dataclasses import replace

import pytest

from host.policy import Decision, Policy
from host.router_gui_policy import RouterGuiPolicy
from test_router import execution, setup  # noqa: F401
from test_broker import certs, with_broker  # noqa: F401


LINE = r"powershell.exe -NoProfile -File C:\UserFiles\trusted-helper.ps1"


def configured(setup, *, enabled=True, base=None):
    original = execution()
    action = replace(original, scope=replace(original.scope,
        capabilities=("process.execute", "gui.input", "gui.observe")))
    host = setup([action])
    policy = RouterGuiPolicy(host.authority, base=base, command_launch_enabled=enabled)
    return action, host, policy


def test_default_and_unscoped_calls_preserve_denial(setup):
    action, host, policy = configured(setup, enabled=False)
    assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "DENY"
    async def check():
        with pytest.raises(ValueError, match="not authorized"):
            with policy.launch(action, LINE):
                pass
    asyncio.run(check())


def test_exact_sequence_consumed_once_and_no_other_keys_allowed(setup):
    action, _, policy = configured(setup)
    async def check():
        with policy.launch(action, LINE):
            assert policy.decide("computer_hotkey", {"keys": ["win", "x"]}).result == "DENY"
            assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).rule_id == "P-ROUTER-EXACT-COMMAND"
            assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "DENY"
            assert policy.decide("computer_type", {"text": "different command"}).result == "DENY"
            assert policy.decide("computer_type", {"text": LINE}).result == "ALLOW"
            assert policy.decide("computer_keypress", {"key": "enter"}).result == "ALLOW"
            assert policy.decide("computer_keypress", {"key": "enter"}).result == "DENY"
        assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "DENY"
    asyncio.run(check())


@pytest.mark.parametrize("failure", ["expired", "changed", "unavailable"])
def test_recheck_before_enter_fail_closed_without_replay(setup, failure):
    action, host, policy = configured(setup)
    async def check():
        with policy.launch(action, LINE):
            assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "ALLOW"
            assert policy.decide("computer_type", {"text": LINE}).result == "ALLOW"
            if failure == "expired":
                grant = host.authority.delegations[action.delegation_ref]
                host.authority.delegations[action.delegation_ref] = replace(grant, expires_at=0)
            elif failure == "changed":
                host.authority.verify_source = lambda s: False
            else:
                def unavailable(s):
                    raise RuntimeError("unavailable")
                host.authority.verify_source = unavailable
            assert policy.decide("computer_keypress", {"key": "enter"}).result == "DENY"
            host.authority.verify_source = lambda s: True
            assert policy.decide("computer_keypress", {"key": "enter"}).result == "DENY"
    asyncio.run(check())


def test_concurrent_input_cannot_use_another_tasks_grant(setup):
    action, _, policy = configured(setup)
    async def check():
        async def unrelated():
            return policy.decide("computer_hotkey", {"keys": ["win", "r"]})
        with policy.launch(action, LINE):
            assert (await asyncio.create_task(unrelated())).result == "DENY"
            assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "ALLOW"
            with pytest.raises(ValueError, match="in progress"):
                with policy.launch(action, LINE):
                    pass
    asyncio.run(check())


def test_custom_policy_denial_is_not_overridden(setup):
    class DenyingPolicy(Policy):
        def decide(self, tool, args):
            return Decision("DENY", "P-DENY-HOTKEY", "organization denies execution")
    action, _, policy = configured(setup, base=DenyingPolicy())
    async def check():
        with policy.launch(action, LINE):
            assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "DENY"
            assert policy.decide("computer_type", {"text": LINE}).rule_id == "P-ROUTER-LAUNCH-BOUNDARY"
    asyncio.run(check())


def test_additional_approval_requirement_is_retained(setup):
    action, _, policy = configured(setup, base=Policy(require_approval_for=("computer_hotkey",)))
    async def check():
        with policy.launch(action, LINE):
            assert policy.decide("computer_hotkey", {"keys": ["win", "r"]}).result == "REQUIRE_APPROVAL"
    asyncio.run(check())


def test_broker_applies_scoped_policy_before_real_transport(certs, setup):
    async def body(broker, runner):
        action, _, policy = configured(setup)
        assert policy.version == Policy().version == "POL-0.1.0"
        assert policy.revision == "router-exact-launch-v1"
        broker.policy = policy  # trusted composition, before accepting Agent work
        await broker.call("task_submit", {"goal": "test only"})
        denied = await broker.call("computer_hotkey", {"keys": ["win", "r"]})
        assert not denied.ok and runner.requests == []
        with policy.launch(action, LINE):
            allowed = await broker.call("computer_hotkey", {"keys": ["win", "r"]})
            assert allowed.ok
            refused = await broker.call("computer_type", {"text": "wrong command"})
            assert not refused.ok
        assert len(runner.requests) == 1
        assert broker.audit.records[-2]["policy"]["rule_id"] == "P-ROUTER-EXACT-COMMAND"
    asyncio.run(with_broker(certs, body))
