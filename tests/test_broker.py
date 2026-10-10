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
from host.policy import POLICY_VERSION, Decision, Policy
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
        elif p.get("type") == "array" and tool == "computer_hotkey":
            # smallest and largest combinations the rule allows: 1..3 modifiers + exactly 1 key
            choices[k] = [["ctrl", "c"], ["ctrl", "alt", "shift", "f4"], ["win", "slash"]]
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
@pytest.mark.parametrize("keys", [["ctrl", "alt", "delete"], ["ctrl", "shift", "escape"], ["win", "x"], ["ctrl", "win", "x"]])
def test_hotkeys_that_open_admin_or_security_surfaces_are_denied(keys):
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
        b.session.last_observation_at -= 11            # received 11 s ago, on the Host clock
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, _, r = run(with_broker(certs, body))
    assert res.error["error"] == "STALE_OBSERVATION" and r.requests == []


def test_runner_clock_skew_does_not_make_a_fresh_capture_stale(certs):
    """The Runner's clock may be up to 60 s off (allowed at HELLO). A capture it
    stamps 30 s in the past but that just arrived is fresh."""
    async def body(b, r):
        await started(b)
        behind = (datetime.now(timezone.utc) - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        b.session.last_observation = {**b.session.last_observation, "captured_at": behind}
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, _, r = run(with_broker(certs, body))
    assert res.ok and len(r.requests) == 1


@pytest.mark.parametrize("keys", [["win", "r"], ["r", "win"]])
def test_run_dialog_hotkey_reaches_the_runner_and_is_audited(certs, keys):
    async def body(b, r):
        await started(b)
        return await b.call("computer_hotkey", {"keys": keys})

    res, b, r = run(with_broker(certs, body))
    assert res.ok and res.data["status"] == "SUCCESS"
    assert r.executed == [res.action_id]
    request, = r.requests
    assert request["payload"]["operation"] == "keyboard.hotkey"
    assert request["payload"]["arguments"] == {"keys": keys}
    assert request["payload"]["policy_version"] == POLICY_VERSION
    assert b.audit.records[-1]["policy"] == {
        "result": "ALLOW", "rule_id": "P-ALLOW-DEFAULT", "version": POLICY_VERSION}


def test_denied_hotkey_is_audited_with_its_rule(certs):
    async def body(b, r):
        await started(b)
        return await b.call("computer_hotkey", {"keys": ["win", "x"]})

    res, b, r = run(with_broker(certs, body))
    assert res.error["error"] == "POLICY_DENIED" and res.error["rule_id"] == "P-DENY-HOTKEY"
    assert r.requests == []
    rec = b.audit.records[-1]
    assert rec["policy"] == {"result": "DENY", "rule_id": "P-DENY-HOTKEY", "version": POLICY_VERSION}


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


def test_artifact_tools_are_refused_without_the_artifact_export_profile(certs):
    """Only a session that selected artifact-export-v1 is granted artifact.export.v1."""
    async def body(b, r):
        return await b.call("artifact_export", {"artifact_id": "ART-1"})

    res, b, _ = run(with_broker(certs, body))
    assert res.error["error"] == "POLICY_DENIED" and "artifact.export.v1" in res.error["message"]
    assert "artifact_export" not in {t["name"] for t in b.tools()}


# --------------------------------------------------------------------- observe wait_ms
def test_observe_waits_by_default_zero_and_caps_at_ten_seconds():
    assert CATALOG.validate("computer_observe", {}) == {"display_id": "primary", "wait_ms": 0}
    assert CATALOG.validate("computer_observe", {"wait_ms": 10000})["wait_ms"] == 10000
    with pytest.raises(ToolError) as e:
        CATALOG.validate("computer_observe", {"wait_ms": 10001})
    assert e.value.code == "INVALID_ARGUMENT" and e.value.message.startswith("wait_ms")
    with pytest.raises(ToolError):
        CATALOG.validate("computer_observe", {"wait_ms": -1})


def test_observe_captures_after_the_requested_delay(certs):
    async def body(b, r):
        assert (await b.call("task_submit", {"goal": "g"})).ok
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        res = await b.call("computer_observe", {"wait_ms": 400})
        return res, loop.time() - t0

    (res, elapsed), _, _ = run(with_broker(certs, body))
    assert res.ok and elapsed >= 0.4


def test_waiting_observes_do_not_hit_the_rate_limit(certs):
    """Polling a loading screen with a delay stays under 2 observes per second;
    polling without one does not."""
    async def body(b, r):
        await b.call("task_submit", {"goal": "g"})
        waited = [await b.call("computer_observe", {"wait_ms": 600}) for _ in range(4)]
        rushed = [await b.call("computer_observe", {}) for _ in range(4)]
        return waited, rushed

    (waited, rushed), b, _ = run(with_broker(certs, body))
    assert all(x.ok for x in waited)
    assert any(x.error and x.error["error"] == "RATE_LIMITED" for x in rushed)
    recs = [x for x in b.audit.records if x["tool"] == "computer_observe" and x["arguments"]["wait_ms"] == 600]
    assert len(recs) == 4 and all(x["latency_ms"] >= 600 for x in recs)


def test_disconnect_while_waiting_is_reported_not_hung(certs):
    async def body(b, r):
        await started(b)
        pending = asyncio.create_task(b.call("computer_observe", {"wait_ms": 1000}))
        await asyncio.sleep(0.2)
        r.drop()
        return await pending

    res, _, _ = run(with_broker(certs, body))
    assert res.error["error"] == "RUNTIME_UNAVAILABLE" and res.error["retryable"] is True


# --------------------------------------------------------------------- Runner failure reasons (review of the Runner control layer)
STALE = {"code": "STALE_OBSERVATION", "message": "observation is older than the allowed age",
         "retryable": True, "recommended_next_step": "computer_observe"}


def test_blocked_without_a_reason_is_not_reported_as_a_security_block(certs):
    """A stopping Runner answers BLOCKED for actions it never started."""
    async def body(b, r):
        await started(b)
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, _, _ = run(with_broker(certs, body, runner_kwargs={"action_status": "BLOCKED"}))
    assert res.error["error"] == "ACTION_FAILED" and res.error["recommended_next_step"] == "computer_observe"


def test_blocked_with_a_security_reason_is_a_security_block(certs):
    async def body(b, r):
        await started(b)
        return await b.call("computer_click", {"x": 1, "y": 1})

    sec = {"code": "SECURITY_BLOCKED", "message": "input to a secure desktop", "retryable": False,
           "recommended_next_step": None}
    res, _, _ = run(with_broker(certs, body, runner_kwargs={"action_status": "BLOCKED", "action_error": sec}))
    assert res.error["error"] == "SECURITY_BLOCKED"


def test_runner_reason_on_a_failed_action_reaches_the_agent(certs):
    """The Runner re-checks the observation right before executing; if that fails the
    Agent must be told to observe again, not just 'failed'."""
    async def body(b, r):
        await started(b)
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, _, _ = run(with_broker(certs, body, runner_kwargs={"action_status": "FAILED", "action_error": STALE}))
    assert res.error["error"] == "STALE_OBSERVATION" and res.error["recommended_next_step"] == "computer_observe"


def test_runner_reason_on_a_rejected_ack_reaches_the_agent(certs):
    async def body(b, r):
        await started(b)
        return await b.call("computer_click", {"x": 1, "y": 1})

    res, b, _ = run(with_broker(certs, body, runner_kwargs={"reject_actions": True, "action_error": STALE}))
    assert res.error["error"] == "STALE_OBSERVATION"
    assert b.session.actions[res.action_id] == "REJECTED"


def test_runner_error_reply_to_observe_is_passed_on(certs):
    async def body(b, r):
        await b.call("task_submit", {"goal": "g"})
        r.observe_error = {"code": "ACTION_FAILED", "message": "capture failed: BitBlt returned 0"}
        return await b.call("computer_observe", {})

    res, _, _ = run(with_broker(certs, body))
    assert res.error["error"] == "ACTION_FAILED" and "BitBlt" in res.error["message"]


# --------------------------------------------------------------------- key rules matched to the Runner's input layer
@pytest.mark.parametrize("keys", [["a", "b"], ["ctrl", "a", "b"], ["ctrl", "shift"], ["ctrl", "alt", "shift", "win"]])
def test_hotkeys_the_runner_cannot_press_are_refused_before_it(keys):
    """The Runner's input layer takes modifiers + exactly one key (control_types.h)."""
    with pytest.raises(ToolError) as e:
        CATALOG.validate("computer_hotkey", {"keys": keys})
    assert e.value.code == "INVALID_ARGUMENT"


@pytest.mark.parametrize("key", ["ctrl", "alt", "shift", "win"])
def test_a_modifier_alone_is_not_a_keypress(key):
    with pytest.raises(ToolError):
        CATALOG.validate("computer_keypress", {"key": key})
