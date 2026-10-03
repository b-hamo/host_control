"""MCP Broker core (WBS 5.6): every Agent tool call passes through here.

    Codex ──MCP──▶ MCP Server (5.7) ──▶ Broker.call(tool, args) ──▶ RuntimeSession ──SCRP──▶ Runner

For each call, in this order (spec part B):

1. Catalog (B-11)      unknown tool, or one this session cannot use → refused
2. Schema (B-2)        type / required / enum / length / range, no unknown fields;
                       declared defaults filled in                  → INVALID_ARGUMENT
3. Session (B-3)       one Broker = one session, no session_id from the Agent;
                       terminated → SESSION_TERMINATED, not READY → RUNTIME_UNAVAILABLE,
                       computer_* before task_submit → POLICY_DENIED
4. Rate limit (B-7)    observe 2/s, input 5/s, control 5/s (protocol doc §7) → RATE_LIMITED
5. Policy (B-5, B-8)   ALLOW / REQUIRE_APPROVAL / DENY with a rule id → POLICY_DENIED
6. Pre-checks          coordinates inside the last observation, observation ≤ 10 s old,
                       text ≤ 4 KiB as UTF-8                         → INVALID_ARGUMENT / STALE_OBSERVATION
                       (computer_observe with wait_ms waits here before capturing)
7. Action ID (B-4)     issued here, so the audit record, the SCRP message and the
                       Runner's record all carry the same ACT-… id
8. Translate + send    MCP tool → SCRP operation (computer_click → mouse.click, ...)
9. Normalize (B-10)    every failure becomes {error, message, retryable, retry_after,
                       recommended_next_step}; a timed-out input is never retried here
10. Audit (B-9)        one record per call, typed text masked

The Broker never re-sends an input. After ACTION_TIMEOUT the Agent is told to
call runtime_get_state (protocol doc §7).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from host.audit import AuditLog, mask
from host.policy import Decision, Policy
from host.runtime_session import RuntimeSession
from host.startup import MAX_CAPTURE_AGE_S
from host.tool_catalog import ToolCatalog, ToolError
from scrp.validate import ProtocolError

log = logging.getLogger("host-broker")

MAX_TEXT_BYTES = 4096

# MCP tool → SCRP ACTION_REQUEST operation (ADR-003 table)
OPERATIONS = {
    "computer_move": "mouse.move",
    "computer_click": "mouse.click",
    "computer_scroll": "mouse.scroll",
    "computer_type": "keyboard.type",
    "computer_keypress": "keyboard.press",
    "computer_hotkey": "keyboard.hotkey",
    "computer_click_element": "ui.click_element",
}
COORDINATE_TOOLS = {"computer_move", "computer_click", "computer_scroll"}
RUNTIME_TOOLS = {"computer_observe", *OPERATIONS}          # need a READY runtime

# Rate limits per session (protocol doc §7: input 5/s, observe 2/s)
RATE_LIMITS = {"observe": 2.0, "input": 5.0, "control": 5.0}

# session_stop reason → TERMINATE reason (the Agent's own reason stays in the audit log)
STOP_REASONS = {"TASK_COMPLETE": "TASK_COMPLETE", "CANNOT_COMPLETE": "TASK_COMPLETE",
                "USER_STOP": "USER_STOP", "SUSPICIOUS_CONTENT": "SECURITY_VIOLATION"}

# B-10: what the Agent should do next, per error code
ERROR_HINTS = {
    "INVALID_ARGUMENT": (False, "fix_arguments"),
    "POLICY_DENIED": (False, "replan"),
    "RATE_LIMITED": (True, "retry_after"),
    "STALE_OBSERVATION": (True, "computer_observe"),
    "RUNTIME_UNAVAILABLE": (True, "runtime_get_state"),
    "RUNTIME_START_FAILED": (False, "RECLASSIFY_RUNTIME"),
    "ACTION_FAILED": (False, "computer_observe"),
    "ACTION_TIMEOUT": (False, "runtime_get_state"),          # never repeat the input blindly
    "SECURITY_BLOCKED": (False, "session_stop"),
    "SESSION_TERMINATED": (False, None),
    "INTERNAL": (False, "session_stop"),
}


class BrokerError(Exception):
    def __init__(self, code: str, message: str, *, retry_after: float | None = None,
                 next_step: str | None = None, rule_id: str | None = None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.retry_after, self.rule_id = code, message, retry_after, rule_id
        retryable, hint = ERROR_HINTS.get(code, (False, None))
        self.retryable = retryable
        self.next_step = next_step or hint

    def as_dict(self) -> dict:
        d = {"error": self.code, "message": self.message, "retryable": self.retryable,
             "recommended_next_step": self.next_step}
        if self.retry_after is not None:
            d["retry_after"] = round(self.retry_after, 2)
        if self.rule_id:
            d["rule_id"] = self.rule_id
        return d


@dataclass
class ToolResult:
    ok: bool
    data: dict = field(default_factory=dict)
    error: dict | None = None
    action_id: str | None = None
    image: bytes | None = field(default=None, repr=False)   # validated PNG for the Agent, if any


class RateLimiter:
    """Token bucket per category; refuses instead of delaying (B-7)."""

    def __init__(self, rates: dict[str, float], clock=time.monotonic):
        self._rates, self._clock = rates, clock
        self._tokens = dict(rates)
        self._last = {k: clock() for k in rates}

    def take(self, category: str) -> None:
        now, rate = self._clock(), self._rates[category]
        self._tokens[category] = min(rate, self._tokens[category] + (now - self._last[category]) * rate)
        self._last[category] = now
        if self._tokens[category] < 1.0:
            raise BrokerError("RATE_LIMITED", f"more than {rate:g} {category} calls per second",
                              retry_after=(1.0 - self._tokens[category]) / rate)
        self._tokens[category] -= 1.0


def category(tool: str) -> str:
    if tool == "computer_observe":
        return "observe"
    return "input" if tool in OPERATIONS else "control"


def translate(tool: str, args: dict) -> tuple[str, dict]:
    """MCP arguments (defaults filled) → SCRP operation and arguments."""
    op = OPERATIONS[tool]
    if tool == "computer_move":
        return op, {"x": args["x"], "y": args["y"]}
    if tool == "computer_click":
        return op, {"x": args["x"], "y": args["y"], "button": args["button"], "click_count": args["click_count"]}
    if tool == "computer_scroll":
        return op, {"x": args["x"], "y": args["y"], "direction": args["direction"], "steps": args["steps"]}
    if tool == "computer_type":
        return op, {"text": args["text"]}
    if tool == "computer_keypress":
        return op, {"key": args["key"]}
    if tool == "computer_hotkey":
        return op, {"keys": list(args["keys"])}
    if tool == "computer_click_element":
        return op, {"window_id": args["window_id"], "button": args["button"],
                    "selector": {"name": args["name"], "control_type": args["control_type"]}}
    raise KeyError(tool)


Approver = Callable[[dict], Awaitable[bool]]


class Broker:
    def __init__(self, session: RuntimeSession, catalog: ToolCatalog | None = None, *,
                 policy: Policy | None = None, audit: AuditLog | None = None,
                 approver: Approver | None = None, rates: dict[str, float] | None = None,
                 clock=time.monotonic, launcher=None):
        # B-3: bound to one session. Only a new generation of that same session replaces it
        # (switch_session), when the Runner or the Sandbox had to be restarted.
        self.session = session
        # host/lifecycle.py SandboxLauncher: task_submit starts the Sandbox. None: the
        # Runtime is started some other way (by hand, run_demo.ps1).
        self.launcher = launcher
        self.catalog = catalog or ToolCatalog()
        self.policy = policy or Policy()
        self.audit = audit or AuditLog()
        self.approver = approver
        self.limiter = RateLimiter(rates or RATE_LIMITS, clock)
        self.task_id: str | None = None
        self.goal: str | None = None
        self._pending_image: bytes | None = None
        self._waited_s = 0.0
        self.notice: str | None = None               # told to the Agent once, with the next result

    def switch_session(self, session: RuntimeSession, notice: str) -> None:
        """Continue with the next generation of the same session (host/lifecycle.py recovery)."""
        assert session.identity[:2] == self.session.identity[:2], "only a new generation of this session"
        self.session = session
        self.notice = notice

    # -- B-11 ----------------------------------------------------------------
    def tools(self) -> list[dict]:
        """The tool list to show the Agent right now."""
        return [t.as_mcp() for t in self.catalog.available(self._granted())]

    def _granted(self) -> set[str]:
        return self.session.granted_capabilities or set(self.session.profile.required_capabilities)

    # -- the one entry point -------------------------------------------------
    async def call(self, tool: str, arguments: dict | None = None) -> ToolResult:
        started = time.monotonic()
        args: dict = arguments if isinstance(arguments, dict) else {}
        decision: Decision | None = None
        action_id: str | None = None
        try:
            try:
                self.catalog.get(tool)
                why = self.catalog.unavailable_reason(tool, self._granted())
                if why:
                    raise BrokerError("POLICY_DENIED", f"{tool} is not available: {why}")
                args = self.catalog.validate(tool, arguments)
            except ToolError as e:
                raise BrokerError(e.code, e.message) from None
            self._waited_s = await self._wait_for_start(tool, args)
            self._check_session(tool)
            self.limiter.take(category(tool))
            decision = self.policy.decide(tool, args)
            await self._enforce(tool, args, decision)
            if tool in OPERATIONS or tool == "computer_observe":
                action_id = self.session.next_action()
            self._pending_image = None
            data = await self._dispatch(tool, args, action_id)
            if self.notice:
                data, self.notice = {**data, "notice": self.notice}, None
            result = ToolResult(True, data, action_id=action_id, image=self._pending_image)
        except BrokerError as e:
            result = ToolResult(False, error=e.as_dict(), action_id=action_id)
        except ProtocolError as e:
            code, detail = _normalize(e.code), e.detail
            hint = self.launcher.hint() if code == "RUNTIME_UNAVAILABLE" and self.launcher is not None else None
            if hint:
                detail = f"{detail}; {hint}"             # the connection dropped just now
            result = ToolResult(False, error=BrokerError(code, detail).as_dict(), action_id=action_id)
        self._audit(tool, args, decision, result, started)
        return result

    # -- steps ---------------------------------------------------------------
    async def _wait_for_start(self, tool: str, args: dict) -> float:
        """computer_observe with wait_ms while the runtime is not READY (starting, reconnecting
        or being restarted) waits for READY instead of failing at once, so the Agent has one
        way to wait. Returns the seconds spent; the capture then follows without the extra delay.

        A restart swaps self.session for the next generation meanwhile, so whichever session
        is current is checked again every half second."""
        if tool != "computer_observe" or not args.get("wait_ms") or self.task_id is None \
                or self.session.terminated or self.session.ready.is_set():
            return 0.0
        started = time.monotonic()
        deadline = started + args["wait_ms"] / 1000
        while not self.session.terminated and not self.session.ready.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                break                                # _check_session reports RUNTIME_UNAVAILABLE
            try:
                await asyncio.wait_for(self.session.ready.wait(), min(left, 0.5))
            except asyncio.TimeoutError:
                pass
        return time.monotonic() - started

    def _check_session(self, tool: str) -> None:
        s = self.session
        if s.terminated:
            raise BrokerError("SESSION_TERMINATED", f"session ended ({s.end_reason})")
        if tool in RUNTIME_TOOLS and self.task_id is None:
            raise BrokerError("POLICY_DENIED", "call task_submit with your goal before using computer_* tools",
                              next_step="task_submit")
        if tool in RUNTIME_TOOLS and not s.ready.is_set():
            hint = self.launcher.hint() if self.launcher is not None else None
            raise BrokerError("RUNTIME_UNAVAILABLE",
                              f"runtime is {s.runtime_state}, not READY" + (f"; {hint}" if hint else ""))

    async def _enforce(self, tool: str, args: dict, decision: Decision) -> None:
        if decision.result == "DENY":
            raise BrokerError("POLICY_DENIED", decision.reason, rule_id=decision.rule_id)
        if decision.result == "REQUIRE_APPROVAL":
            if self.approver is None:
                raise BrokerError("POLICY_DENIED", f"{decision.reason}; no approver is configured",
                                  rule_id=decision.rule_id, next_step="ask_user")
            summary = {"tool": tool, "arguments": mask(tool, args), "session_id": self.session.identity[0],
                       "runtime_id": self.session.identity[1], "reason": decision.reason}
            if not await self.approver(summary):
                raise BrokerError("POLICY_DENIED", "the user did not approve this action", rule_id=decision.rule_id)

    def _observation_for(self, tool: str, args: dict) -> str:
        obs = self.session.last_observation
        if obs is None or self.session.last_observation_at is None:
            raise BrokerError("STALE_OBSERVATION", "no observation yet; call computer_observe first")
        # Host clock only (see RuntimeSession.last_observation_at): a Runner clock
        # that is off by 20 s must not make a fresh capture look stale.
        age = time.monotonic() - self.session.last_observation_at
        if age > MAX_CAPTURE_AGE_S:
            raise BrokerError("STALE_OBSERVATION", f"last observation is {age:.0f}s old (max {MAX_CAPTURE_AGE_S:.0f}s)")
        if tool in COORDINATE_TOOLS and not (0 <= args["x"] < obs["width"] and 0 <= args["y"] < obs["height"]):
            raise BrokerError("INVALID_ARGUMENT",
                              f"({args['x']}, {args['y']}) is outside the {obs['width']}x{obs['height']} screen")
        return obs["observation_id"]

    async def _dispatch(self, tool: str, args: dict, action_id: str | None) -> dict:
        s = self.session
        if tool == "task_submit":
            self.task_id, self.goal = s.next_task(), args["goal"]
            log.info("TASK %s submitted (Translator classification is WBS 7.x)", self.task_id)
            reply = {"task_id": self.task_id, "accepted": True, "runtime_id": s.identity[1],
                     "runtime_state": s.runtime_state}
            if self.launcher is not None:
                self.launcher.begin()                # returns at once; the Sandbox boots meanwhile
                reply["sandbox"] = self.launcher.status()
            if not s.ready.is_set():
                reply["message"] = ("The runtime is starting (usually 20-60 s). Call computer_observe "
                                    "with wait_ms=10000 to wait for it; repeat while it is not READY.")
            return reply
        if tool == "computer_observe":
            # Already waited for the runtime to start: capture right away (it has just come up).
            rest = 0 if self._waited_s else args["wait_ms"] / 1000
            if rest > 0:
                # Waiting happens here on the Host, so the Runner and the SCRP OBSERVE
                # message stay as they are. The Agent picks the delay (tool description
                # gives typical values); the schema caps it at 10 s.
                await asyncio.sleep(rest)
            obs = await s.observe(task_id=self.task_id, action_id=action_id)
            # The PNG comes over the separate upload path (protocol doc §8) and is only
            # attached once the Host has validated it against this OBSERVE_RESULT.
            shot = s.last_screenshot if s.last_screenshot and \
                s.last_screenshot.observation_id == obs["observation_id"] else None
            self._pending_image = shot.png if shot else None
            return {"action_id": action_id, "observation_id": obs["observation_id"], "width": obs["width"],
                    "height": obs["height"], "captured_at": obs["captured_at"], "sha256": obs["sha256"],
                    "image": "attached" if shot else None,
                    "image_state": s.last_screenshot_state or "NO_UPLOAD_PATH"}
        if tool in OPERATIONS:
            if tool == "computer_type" and len(args["text"].encode("utf-8")) > MAX_TEXT_BYTES:
                raise BrokerError("INVALID_ARGUMENT", f"text is more than {MAX_TEXT_BYTES} bytes as UTF-8")
            observation_id = self._observation_for(tool, args)
            op, op_args = translate(tool, args)
            reply = await s.action(op, op_args, observation_id, task_id=self.task_id,
                                   action_id=action_id, policy_version=self.policy.version)
            return _action_outcome(reply, action_id)
        if tool == "runtime_get_state":
            wanted = args["action_id"]
            if wanted is not None and wanted not in s.actions:
                raise BrokerError("INVALID_ARGUMENT", f"{wanted} is not an action of this session")
            host_view = {"runtime_state": s.runtime_state, "health": s.health.state.value,
                         "connected": not s.disconnected(),
                         "action": {"action_id": wanted, "status": s.actions[wanted]} if wanted else None}
            if self.launcher is not None:
                host_view["sandbox"] = self.launcher.status()
            if not s.ready.is_set():
                return {**host_view, "source": "host"}   # the Runner is not reachable right now
            st = (await s.state(wanted))["payload"]
            if wanted and st["action_state"]:
                s.actions[wanted] = st["action_state"]["status"]
            return {**host_view, "runtime_state": st["runtime_state"], "worker_alive": st["worker_alive"],
                    "queue_depth": st["queue_depth"], "action": st["action_state"], "source": "runtime"}
        if tool == "session_stop":
            if s.ready.is_set():
                await s.terminate(STOP_REASONS[args["reason"]])
            else:
                await s._end(f"STOPPED_BY_AGENT: {args['reason']}")
            return {"stopped": True, "reason": args["reason"]}
        raise BrokerError("INTERNAL", f"no handler for {tool}")

    def _audit(self, tool: str, args: dict, decision: Decision | None, result: ToolResult, started: float) -> None:
        s = self.session
        outcome = {"ok": True, "status": result.data.get("status", "OK")} if result.ok else \
                  {"ok": False, "error": result.error["error"], "message": result.error["message"]}
        self.audit.record(
            session_id=s.identity[0], runtime_id=s.identity[1], task_id=self.task_id,
            action_id=result.action_id, tool=tool, arguments=mask(tool, args),
            policy={"result": decision.result, "rule_id": decision.rule_id, "version": self.policy.version}
            if decision else None,
            result=outcome, latency_ms=round((time.monotonic() - started) * 1000, 1))
        if result.ok:
            log.info("TOOL %-22s OK   %s", tool, result.action_id or "")
        else:
            log.warning("TOOL %-22s %s %s%s", tool, result.error["error"], result.error["message"],
                        f" [{result.error['rule_id']}]" if "rule_id" in result.error else "")


def _normalize(code: str) -> str:
    """Protocol/Runtime error codes → the B-10 set the Agent sees."""
    if code in ERROR_HINTS:
        return code
    if code in ("PROTOCOL_DENIED", "UNSUPPORTED_TYPE", "MESSAGE_TOO_LARGE"):
        return "RUNTIME_UNAVAILABLE"
    return "INTERNAL"


def _runner_error(reply: dict, default_code: str, default_message: str) -> BrokerError:
    """Prefer the reason the Runner put in the envelope's error (e.g. STALE_OBSERVATION
    when its own re-check before executing failed), so the Agent gets the right next
    step instead of a generic ACTION_FAILED."""
    err = reply.get("error") or {}
    if err.get("code"):
        return BrokerError(_normalize(err["code"]), err.get("message") or default_message)
    return BrokerError(default_code, default_message)


def _action_outcome(reply: dict, action_id: str) -> dict:
    if reply["type"] == "ACK":                        # REJECTED before anything ran
        raise _runner_error(reply, "ACTION_FAILED",
                            f"runtime rejected the action: {reply['payload']['reject_reason']}")
    status, p = reply["status"], reply["payload"]
    detail = p["result"].get("detail")
    if status == "BLOCKED":
        # BLOCKED means "not executed". That is a security block only when the Runner
        # says so; a Runner that is stopping also answers BLOCKED for queued actions.
        raise _runner_error(reply, "ACTION_FAILED", detail or "the runtime did not execute this action")
    if status == "FAILED":
        raise _runner_error(reply, "ACTION_FAILED", detail or "the runtime reported failure")
    if status == "UNKNOWN":
        raise BrokerError("ACTION_FAILED", "outcome unknown", next_step="runtime_get_state")
    return {"action_id": action_id, "status": status, "result": p["result"],
            "execution_time_ms": p["execution_time_ms"]}
