"""WBS 5.6: the Broker checks every tool call and only then talks SCRP.

Unit tests cover the catalog, translation and policy on their own. Server
tests put a real Broker on a real, verified RuntimeSession with MiniRunner on
the other end, and look at what actually reached the Runner.
"""

import asyncio
import itertools
import json
from datetime import datetime, timedelta, timezone

import pytest

from host import tls
from host.audit import AuditLog
from host.broker import OPERATIONS, Broker, RateLimiter, BrokerError, translate
from host.policy import Decision, Policy
from host.sender import Sessions, start_server
from host.session_registry import SessionRegistry
from host.startup import StartupProfile
from host.tool_catalog import ToolCatalog, ToolError
from mini_runner import MiniRunner
from scrp.envelope import Endpoint
from scrp.validate import validate

SES = ("SES-001", "RT-SBX-001", 1)
CATALOG = ToolCatalog()


# --------------------------------------------------------------------- catalog
def test_catalog_has_the_thirteen_tools():
    assert sorted(CATALOG.names) == sorted([
        "task_submit", "computer_observe", "computer_move", "computer_click", "computer_type",
        "computer_keypress", "computer_hotkey", "computer_scroll", "computer_click_element",
        "runtime_get_state", "artifact_list", "artifact_export", "session_stop"])


def test_validate_fills_defaults():
    assert CATALOG.validate("computer_click", {"x": 1, "y": 2}) == {"x": 1, "y": 2, "button": "left", "click_count": 1}


@pytest.mark.parametrize("tool, args, where", [
    ("computer_click", {"x": 1}, "arguments"),                        # missing y
    ("computer_click", {"x": -1, "y": 2}, "x"),                       # range
    ("computer_click", {"x": 1, "y": 2, "button": "side"}, "button"), # enum
    ("computer_click", {"x": 1, "y": 2, "session_id": "SES-002"}, "arguments"),   # unknown field
    ("computer_type", {"text": ""}, "text"),                          # length
    ("computer_hotkey", {"keys": ["ctrl"]}, "keys"),                  # too few
    ("nope", {}, None),
])
def test_invalid_arguments_are_refused(tool, args, where):
    with pytest.raises(ToolError) as e:
        CATALOG.validate(tool, args)
    assert e.value.code == "INVALID_ARGUMENT"
    if where:
        assert e.value.message.startswith(where)


def test_tools_needing_missing_capabilities_are_hidden():
    names = {t.name for t in CATALOG.available({"gui.observe", "gui.input"})}
    assert "computer_click" in names and "computer_click_element" not in names   # needs ui.automation
    assert "artifact_export" not in names and "artifact_list" not in names         # backend not built
    assert {t.name for t in CATALOG.available({"gui.observe"})} >= {"computer_observe", "task_submit"}
    assert "computer_click" not in {t.name for t in CATALOG.available({"gui.observe"})}


# --------------------------------------------------------------------- translation
def _variants(tool: str):
    """Every combination of enum values and range limits the tool schema allows."""
    props = CATALOG.get(tool).input_schema["properties"]
    required = CATALOG.get(tool).input_schema.get("required", [])
    choices = {}
    for k, p in props.items():
        if "enum" in p:
            choices[k] = p["enum"][:3] + p["enum"][-2:]
        elif p.get("type") == "integer":
            choices[k] = [p["minimum"], p["maximum"]]
        elif p.get("type") == "string":
            choices[k] = ["a", "가" * p.get("maxLength", 8)]
        elif p.get("type") == "array":
            items = p["items"]["enum"]
            choices[k] = [items[:p["minItems"]], items[-p["maxItems"]:]]
        elif k in required:
            raise AssertionError(f"no generator for {tool}.{k}")
    keys = list(choices)
    for combo in itertools.product(*(choices[k] for k in keys)):
        yield CATALOG.validate(tool, dict(zip(keys, combo)))


@pytest.mark.parametrize("tool", sorted(OPERATIONS))
def test_everything_the_tool_schema_allows_is_a_valid_protocol_message(tool):
    """Tool schema (WBS 2.4) and protocol schema (WBS 2.3) must not drift apart:
    whatever the Agent may legally send has to become a legal ACTION_REQUEST."""
    me = Endpoint(*SES, connection_id="CONN-1")
    n = 0
    for args in _variants(tool):
        op, op_args = translate(tool, args)
        validate(me.envelope("ACTION_REQUEST", {
            "operation": op, "arguments": op_args, "observation_id": "OBS-1",
            "policy_version": "POL-0.1.0", "timeout_ms": 10000}, task_id="TASK-1", action_id="ACT-1"))
        n += 1
    assert n >= 2


# --------------------------------------------------------------------- policy, limiter
@pytest.mark.parametrize("keys", [["win", "r"], ["ctrl", "alt", "delete"], ["ctrl", "shift", "escape"], ["win", "x"]])
def test_hotkeys_that_open_command_surfaces_are_denied(keys):
    d = Policy().decide("computer_hotkey", {"keys": keys})
    assert (d.result, d.rule_id) == ("DENY", "P-DENY-HOTKEY")


def test_ordinary_hotkey_is_allowed():
    assert Policy().decide("computer_hotkey", {"keys": ["ctrl", "c"]}).result == "ALLOW"


def test_rate_limiter_refuses_instead_of_waiting():
    t = [0.0]
    lim = RateLimiter({"input": 5.0}, clock=lambda: t[0])
    for _ in range(5):
        lim.take("input")
    with pytest.raises(BrokerError) as e:
        lim.take("input")
    assert e.value.code == "RATE_LIMITED" and e.value.retryable and 0 < e.value.retry_after <= 0.2
    t[0] += 0.2
    lim.take("input")                                 # one token refilled


# --------------------------------------------------------------------- broker on a live session
@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    cert, key = tls.ensure_dev_cert(tmp_path_factory.mktemp("certs"))
    return cert, key, cert.read_text()


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 20))


async def with_broker(certs, body, runner_kwargs=None, **broker_kwargs):
    cert, key, cert_pem = certs
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    sessions = Sessions(reg, heartbeat_interval_s=5.0, profile=StartupProfile(step_timeout_s=1.0))
    async with start_server(reg, cert, key, run_demo=False, host="127.0.0.1", port=0,
                            sessions=sessions) as server:
        r = MiniRunner(server.sockets[0].getsockname()[1], cert_pem, SES, **(runner_kwargs or {}))
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        while not session.ready.is_set():
            await asyncio.sleep(0.02)
        broker = Broker(session, audit=AuditLog(), **broker_kwargs)
        try:
            return await body(broker, r), broker, r
        finally:
            if not serving.done():
                r.drop()
            await serving


async def started(broker):
    assert (await broker.call("task_submit", {"goal": "test"})).ok
    assert (await broker.call("computer_observe", {})).ok


def test_happy_path_reaches_the_runner_with_broker_ids(certs):
    async def body(b, r):
        await started(b)
        click = await b.call("computer_click", {"x": 640, "y": 420})
        typed = await b.call("computer_type", {"text": "안녕하세요"})
        return click, typed

    (click, typed), b, r = run(with_broker(certs, body))
    assert click.ok and typed.ok and click.data["status"] == "SUCCESS"
    sent = {m["action_id"]: m for m in r.requests}
    assert set(sent) == {click.action_id, typed.action_id}             # same ACT id end to end (B-4)
    assert sent[click.action_id]["payload"]["arguments"] == {"x": 640, "y": 420, "button": "left", "click_count": 1}
    assert {m["task_id"] for m in r.requests} == {b.task_id}           # the submitted task, not a fresh one
    assert sent[click.action_id]["payload"]["policy_version"] == b.policy.version


def test_computer_tools_need_a_task_first(certs):
    async def body(b, r):
        return await b.call("computer_observe", {})

    res, _, r = run(with_broker(certs, body))
    assert res.error["error"] == "POLICY_DENIED" and res.error["recommended_next_step"] == "task_submit"


@pytest.mark.parametrize("args, code", [
    ({"x": 1280, "y": 10}, "INVALID_ARGUMENT"),      # x == width is already outside
    ({"x": 10, "y": 720}, "INVALID_ARGUMENT"),
    ({"x": 10, "y": 10, "click_count": 3}, "INVALID_ARGUMENT"),   # no triple click in the protocol
])
def test_refused_calls_never_reach_the_runner(certs, args, code):
    async def body(b, r):
        await started(b)
        return await b.call("computer_click", args)

    res, _, r = run(with_broker(certs, body))
    assert not res.ok and res.error["error"] == code and r.requests == []


def test_click_without_observation_is_stale(certs):
    async def body(b, r):
        await b.call("task_submit", {"goal": "g"})
        b.session.last_observation = None
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, _, r = run(with_broker(certs, body))
    assert res.error["error"] == "STALE_OBSERVATION" and res.error["recommended_next_step"] == "computer_observe"
    assert r.requests == []


def test_old_observation_is_stale(certs):
    async def body(b, r):
        await started(b)
        old = (datetime.now(timezone.utc) - timedelta(seconds=11)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        b.session.last_observation = {**b.session.last_observation, "captured_at": old}
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, _, r = run(with_broker(certs, body))
    assert res.error["error"] == "STALE_OBSERVATION" and r.requests == []


def test_denied_hotkey_is_audited_with_its_rule(certs):
    async def body(b, r):
        await started(b)
        return await b.call("computer_hotkey", {"keys": ["win", "r"]})

    res, b, r = run(with_broker(certs, body))
    assert res.error["error"] == "POLICY_DENIED" and res.error["rule_id"] == "P-DENY-HOTKEY"
    assert r.requests == []
    rec = b.audit.records[-1]
    assert rec["policy"] == {"result": "DENY", "rule_id": "P-DENY-HOTKEY", "version": "POL-0.1.0"}


def test_approval_workflow(certs):
    class TypingNeedsApproval(Policy):
        def decide(self, tool, args):
            if tool == "computer_type":
                return Decision("REQUIRE_APPROVAL", "P-TEST", "typing needs approval")
            return super().decide(tool, args)

    asked = []

    async def approver(summary):
        asked.append(summary)
        return summary["arguments"]["text"]["chars"] == 2   # approve "ok", refuse the rest

    async def body(b, r):
        await started(b)
        return await b.call("computer_type", {"text": "no!"}), await b.call("computer_type", {"text": "ok"})

    (refused, approved), _, r = run(with_broker(certs, body, policy=TypingNeedsApproval(), approver=approver))
    assert refused.error["error"] == "POLICY_DENIED" and approved.ok
    assert len(r.requests) == 1
    assert all(a["arguments"]["text"]["masked"] for a in asked)      # the approver sees no plaintext either


def test_typed_text_is_masked_in_the_audit_log(certs):
    async def body(b, r):
        await started(b)
        await b.call("computer_type", {"text": "비밀번호123"})

    _, b, _ = run(with_broker(certs, body))
    dump = json.dumps(b.audit.records, ensure_ascii=False)
    assert "비밀번호123" not in dump
    rec = b.audit.records[-1]
    assert rec["arguments"]["text"]["chars"] == 7 and rec["action_id"].startswith("ACT-")
    assert set(rec) >= {"ts", "session_id", "task_id", "action_id", "tool", "arguments", "policy",
                        "runtime_id", "result", "latency_ms"}


def test_burst_of_clicks_is_rate_limited(certs):
    async def body(b, r):
        await started(b)
        return [await b.call("computer_click", {"x": 1, "y": 1}) for _ in range(7)]

    results, _, r = run(with_broker(certs, body))
    codes = [x.error["error"] if x.error else "OK" for x in results]
    assert codes[:5] == ["OK"] * 5 and "RATE_LIMITED" in codes[5:]
    assert len(r.requests) == codes.count("OK")


def test_runner_rejection_and_failure_are_normalized(certs):
    async def rejected(b, r):
        await started(b)
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, b, _ = run(with_broker(certs, rejected, runner_kwargs={"reject_actions": True}))
    assert res.error["error"] == "ACTION_FAILED" and "queue full" in res.error["message"]
    assert b.session.actions[res.action_id] == "REJECTED"

    res, _, _ = run(with_broker(certs, rejected, runner_kwargs={"action_status": "FAILED"}))
    assert res.error["error"] == "ACTION_FAILED" and res.error["retryable"] is False


def test_get_state_only_for_own_actions(certs):
    async def body(b, r):
        await started(b)
        click = await b.call("computer_click", {"x": 1, "y": 1})
        return (await b.call("runtime_get_state", {"action_id": click.action_id}),
                await b.call("runtime_get_state", {"action_id": "ACT-999999"}))

    (mine, other), _, _ = run(with_broker(certs, body))
    assert mine.ok and mine.data["action"]["status"] == "SUCCESS" and mine.data["source"] == "runtime"
    assert other.error["error"] == "INVALID_ARGUMENT"


def test_disconnected_runtime_is_unavailable_but_state_still_answers(certs):
    async def body(b, r):
        await started(b)
        r.drop()
        while not b.session.disconnected():
            await asyncio.sleep(0.02)
        return await b.call("computer_click", {"x": 1, "y": 1}), await b.call("runtime_get_state", {})

    (click, state), _, _ = run(with_broker(certs, body))
    assert click.error["error"] == "RUNTIME_UNAVAILABLE" and click.error["retryable"] is True
    assert state.ok and state.data["source"] == "host" and state.data["connected"] is False


def test_session_stop_ends_everything(certs):
    async def body(b, r):
        await started(b)
        stop = await b.call("session_stop", {"reason": "TASK_COMPLETE"})
        return stop, await b.call("computer_observe", {})

    (stop, after), b, _ = run(with_broker(certs, body))
    assert stop.ok and b.session.terminated
    assert after.error["error"] == "SESSION_TERMINATED"


def test_artifact_tools_are_refused_before_the_runtime(certs):
    async def body(b, r):
        return await b.call("artifact_export", {"artifact_id": "ART-1"})

    res, b, _ = run(with_broker(certs, body))
    assert res.error["error"] == "POLICY_DENIED" and "Artifact Broker" in res.error["message"]
    assert "artifact_export" not in {t["name"] for t in b.tools()}
