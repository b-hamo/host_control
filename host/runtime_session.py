"""A Runtime session that survives reconnects (WBS 4.4).

One RuntimeSession per (session_id, runtime_id, generation). Connections come
and go underneath it; what has to outlive them lives here:

- task/action id counters, so a reconnect never reuses an action_id
- the action history: which actions got a final result, which did not
- the latest observation
- health, from the periodic HEARTBEAT (spec E-7, protocol doc §7 defaults)

Rules from protocol doc §7 that this enforces:
- A timed-out or cut-off action is never re-sent. After a reconnect the
  session asks STATE_REQUEST for every action without a final result and
  takes a new observation; only then does it accept new actions.
- While disconnected, or before that resync, new actions are refused.

And from §4 step 6 / spec J-4 (WBS 4.5, host/startup.py): the session only
becomes READY after the Host's own Startup Verification passes, within
120 s of registration. A failed or timed-out startup terminates the session
and revokes its tokens; the Lifecycle side has to create a new generation.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable

from host.connection import Connection
from host.startup import StartupProfile, StartupReport, check_hello, verify_runtime
from scrp.validate import ProtocolError

log = logging.getLogger("host-sender")

POLICY_VERSION = "POL-0.1.0"

HEARTBEAT_INTERVAL_S = 5.0     # protocol doc §7: every 5 s
ALIVE_TIMEOUT_S = 3.0          # ALIVE within 3 s
DEGRADED_AFTER = 2             # consecutive misses
UNRESPONSIVE_AFTER = 3
RECONNECT_GRACE_S = 30.0       # Runner backoff is 1+2+4+8 s plus jitter; after that, central recovery

REPLACED_CLOSE_CODE = 4001     # private-use close code: a newer connection took over

UNRESOLVED = ("SENT", "UNKNOWN")   # no final ACTION_RESULT seen


class Health(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    UNRESPONSIVE = "UNRESPONSIVE"


HealthCallback = Callable[[tuple[str, str, int], Health, Health, str], None]


class HealthTracker:
    """Consecutive missed heartbeats → DEGRADED / UNRESPONSIVE; any ALIVE → OK."""

    def __init__(self, identity: tuple[str, str, int], on_change: HealthCallback | None = None):
        self.identity = identity
        self.state = Health.OK
        self.misses = 0
        self._on_change = on_change

    def _set(self, new: Health, why: str) -> None:
        if new is self.state:
            return
        old, self.state = self.state, new
        level = logging.INFO if new is Health.OK else logging.WARNING
        log.log(level, "HEALTH %s %s -> %s (%s)", self.identity[0], old.value, new.value, why)
        if self._on_change:
            self._on_change(self.identity, old, new, why)   # Runtime Manager hook (spec D-7)

    def alive(self, why: str = "ALIVE received") -> None:
        self.misses = 0
        self._set(Health.OK, why)

    def missed(self) -> None:
        self.misses += 1
        if self.misses >= UNRESPONSIVE_AFTER:
            self._set(Health.UNRESPONSIVE, f"{self.misses} heartbeats missed")
        elif self.misses >= DEGRADED_AFTER:
            self._set(Health.DEGRADED, f"{self.misses} heartbeats missed")
        else:
            log.warning("HEALTH %s heartbeat missed (%d)", self.identity[0], self.misses)

    def lost(self, why: str) -> None:
        self._set(Health.UNRESPONSIVE, why)


def _utc_in(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class RuntimeSession:
    def __init__(self, identity: tuple[str, str, int], *,
                 heartbeat_interval_s: float = HEARTBEAT_INTERVAL_S,
                 alive_timeout_s: float = ALIVE_TIMEOUT_S,
                 reconnect_grace_s: float = RECONNECT_GRACE_S,
                 on_health: HealthCallback | None = None,
                 on_terminated: Callable[[tuple[str, str, int]], None] | None = None,
                 profile: StartupProfile | None = None,
                 on_startup: Callable[[tuple[str, str, int], StartupReport], None] | None = None):
        self.identity = identity
        self.profile = profile or StartupProfile()
        self.startup = StartupReport()
        self.verified = False                  # Startup Verification passed at least once
        self.end_reason: str | None = None
        self.conn: Connection | None = None
        self.connections = 0
        self.ready = asyncio.Event()           # connected and resynced: actions allowed
        self.terminated = False
        self.health = HealthTracker(identity, on_health)
        self.actions: dict[str, str] = {}      # action_id -> SENT / UNKNOWN / final status
        self.last_observation: dict | None = None
        self.granted_capabilities: set[str] = set()   # from the latest HELLO_ACK
        self.last_action_id: str | None = None
        self.heartbeat_interval_s = heartbeat_interval_s
        self.alive_timeout_s = alive_timeout_s
        self.reconnect_grace_s = reconnect_grace_s
        self._on_terminated = on_terminated
        self._task_seq = 0
        self._action_seq = 0
        self._grace: asyncio.Task | None = None
        self._watchdog: asyncio.Task | None = None
        self._on_startup = on_startup
        self.demo_task: asyncio.Task | None = None

    # -- state (spec D-2 Runtime states) ----------------------------------------
    @property
    def runtime_state(self) -> str:
        if self.terminated:
            return "TERMINATED"
        if not self.verified:
            return "PREPARING"
        if self.health.state is not Health.OK:
            return self.health.state.value
        if self.conn is None:
            return "DEGRADED"                 # verified, waiting for a reconnect
        if any(v == "SENT" for v in self.actions.values()):
            return "RUNNING"
        return "READY"

    def status(self) -> dict:
        """Snapshot for the Runtime Manager / Dashboard."""
        return {
            "session_id": self.identity[0], "runtime_id": self.identity[1], "generation": self.identity[2],
            "state": self.runtime_state,
            "health": self.health.state.value,
            "missed_heartbeats": self.health.misses,
            "connected": not self.disconnected(),
            "connection_id": self.conn.id if self.conn else None,
            "connections": self.connections,
            "startup": self.startup.as_dict(),
            "end_reason": self.end_reason,
            "actions": dict(self.actions),
        }

    # -- startup (WBS 4.5) -----------------------------------------------------
    def start_watchdog(self) -> None:
        """Fail the session if it is not READY within profile.timeout_s of now."""
        self._watchdog = asyncio.get_running_loop().create_task(self._startup_deadline())

    async def _startup_deadline(self) -> None:
        await asyncio.sleep(self.profile.timeout_s)
        if not self.verified and not self.terminated:
            why = "runner never connected" if self.connections == 0 else "verification did not finish"
            await self.fail_startup(f"timeout after {self.profile.timeout_s:.0f}s: {why}")

    async def admit_hello(self, hello: dict) -> None:
        """HELLO checks on every connection, before any credential is handed out.

        Failing them ends the session either way: at startup it never became
        trustworthy, and a Runner that reconnects with less than it started
        with (e.g. a monitor gone) is not the Runtime we verified.
        """
        report = self.startup if not self.verified else StartupReport()
        if check_hello(hello, self.profile, report):
            return
        if not self.verified:
            await self.fail_startup(report.reason)
        else:
            log.error("RECONNECT REJECTED %s: %s", self.identity[0], report.reason)
            await self._end(f"RECONNECT_REJECTED: {report.reason}")
        raise ProtocolError("RUNTIME_START_FAILED", report.reason)

    async def fail_startup(self, reason: str) -> None:
        if self.terminated:
            return
        self.startup.finish(False, reason)
        log.error("STARTUP FAILED %s: %s", self.identity[0], self.startup.reason)
        await self._end(f"RUNTIME_START_FAILED: {self.startup.reason}")
        if self._on_startup:
            self._on_startup(self.identity, self.startup)

    async def _end(self, reason: str) -> None:
        self.terminated = True
        self.end_reason = reason
        self.ready.clear()
        for t in (self._watchdog, self._grace):
            if t and t is not asyncio.current_task():
                t.cancel()
        if self._on_terminated:
            self._on_terminated(self.identity)       # revoke every token of this session
        if self.conn is not None and not self.conn.closed.is_set():
            await self.conn.ws.close(code=1008, reason="RUNTIME_START_FAILED")

    # -- ids (per session, never reused across connections) -------------------
    def next_task(self) -> str:
        self._task_seq += 1
        return f"TASK-{self._task_seq:06d}"

    def next_action(self) -> str:
        self._action_seq += 1
        return f"ACT-{self._action_seq:06d}"

    # -- connection lifecycle ------------------------------------------------
    async def attach(self, conn: Connection) -> None:
        """Make `conn` the live connection. A reconnect resyncs before READY."""
        old, self.conn = self.conn, conn
        self.connections += 1
        self.ready.clear()
        if self._grace:
            self._grace.cancel()
            self._grace = None
        if old is not None and not old.closed.is_set():
            log.warning("connection %s replaced by %s", old.id, conn.id)
            await old.ws.close(code=REPLACED_CLOSE_CODE, reason="REPLACED")
        if not self.verified:
            log.info("STARTUP verifying %s on %s ...", self.identity[0], conn.id)
            if not await verify_runtime(self, conn, self.profile, self.startup):
                await self.fail_startup(self.startup.reason)
                raise ProtocolError("RUNTIME_START_FAILED", self.startup.reason)
            self.startup.finish(True)
            self.verified = True
            if self._watchdog:
                self._watchdog.cancel()
            log.info("STARTUP OK %s in %.1fs: %s", self.identity[0], self.startup.as_dict()["elapsed_s"],
                     ", ".join(f"{c.name}={c.detail}" for c in self.startup.checks))
            if self._on_startup:
                self._on_startup(self.identity, self.startup)
        elif self.connections > 1:
            await self.resync(conn)
        if self.conn is conn and not conn.closed.is_set():
            if self.connections > 1:
                self.health.alive("reconnected and resynced")
            self.ready.set()
            log.info("READY %s on %s", self.identity[0], conn.id)

    def detach(self, conn: Connection) -> None:
        if self.conn is not conn:
            return                                   # already replaced
        self.conn = None
        self.ready.clear()
        cut = [a for a, s in self.actions.items() if s == "SENT"]
        for a in cut:
            self.actions[a] = "UNKNOWN"
        if cut:
            log.warning("connection %s lost with %s unresolved; they will NOT be re-sent", conn.id, cut)
        if not self.terminated:
            self._grace = asyncio.get_running_loop().create_task(self._reconnect_grace())

    async def _reconnect_grace(self) -> None:
        await asyncio.sleep(self.reconnect_grace_s)
        if self.conn is None and not self.terminated:
            self.health.lost(f"no reconnect within {self.reconnect_grace_s:.0f}s; central recovery needed")

    async def resync(self, conn: Connection) -> None:
        """After a reconnect: learn what happened to cut-off actions, then look again."""
        for action_id in [a for a, s in self.actions.items() if s in UNRESOLVED]:
            st = await self._state(conn, action_id)
            known = st["payload"]["action_state"]
            status = known["status"] if known else "NOT_DELIVERED"
            self.actions[action_id] = status
            log.info("RESYNC %s was %s on the Runner (not re-sent)", action_id, status)
        await self._observe(conn)
        log.info("RESYNC done: new observation %s", self.last_observation["observation_id"])

    def disconnected(self) -> bool:
        return self.conn is None or self.conn.closed.is_set()

    def _drop_if_closed(self) -> None:
        # The connection's reader notices a close before its handler calls
        # detach(); don't let anyone use the dead connection in between.
        if self.conn is not None and self.conn.closed.is_set():
            self.detach(self.conn)

    async def wait_ready(self, timeout: float) -> None:
        self._drop_if_closed()
        try:
            await asyncio.wait_for(self.ready.wait(), timeout)
        except asyncio.TimeoutError:
            raise ProtocolError("RUNTIME_UNAVAILABLE", f"runtime not back within {timeout:.0f}s") from None

    def _live(self) -> Connection:
        self._drop_if_closed()
        if self.terminated:
            raise ProtocolError("SESSION_TERMINATED", "session is terminated")
        if self.conn is None or not self.ready.is_set():
            raise ProtocolError("RUNTIME_UNAVAILABLE", "no ready connection (disconnected or resyncing)")
        if self.health.state is Health.UNRESPONSIVE:
            raise ProtocolError("RUNTIME_UNAVAILABLE", "runtime is UNRESPONSIVE")
        return self.conn

    # -- heartbeat -----------------------------------------------------------
    async def heartbeat_loop(self, conn: Connection) -> None:
        """Every interval on the monotonic clock, for as long as `conn` is live."""
        loop = asyncio.get_running_loop()
        next_beat = loop.time() + self.heartbeat_interval_s
        while not conn.closed.is_set() and self.conn is conn and not self.terminated:
            await asyncio.sleep(max(0.0, next_beat - loop.time()))
            next_beat += self.heartbeat_interval_s
            if conn.closed.is_set() or self.conn is not conn or self.terminated:
                return
            try:
                await self._heartbeat(conn)
            except ProtocolError as e:
                if e.code == "ACTION_TIMEOUT":
                    self.health.missed()
                else:
                    return                         # connection gone; detach handles it

    async def _heartbeat(self, conn: Connection, timeout: float | None = None) -> dict:
        lease_s = self.heartbeat_interval_s * UNRESPONSIVE_AFTER
        msg = conn.me.envelope("HEARTBEAT", {"lease_expires_at": _utc_in(lease_s)})
        alive = await conn.request(msg, ("ALIVE",), timeout=timeout or self.alive_timeout_s)
        self.health.alive()
        log.info("  alive: %s queue=%s", alive["payload"]["runtime_state"], alive["payload"]["queue_depth"])
        return alive

    async def heartbeat_once(self) -> dict:
        try:
            return await self._heartbeat(self._live())
        except ProtocolError as e:
            if e.code == "ACTION_TIMEOUT":
                self.health.missed()
            raise

    # -- operations (what the Broker will call) -------------------------------
    async def _observe(self, conn: Connection, timeout: float = 5.0, *,
                       task_id: str | None = None, action_id: str | None = None) -> dict:
        upload_id = uuid.uuid4().hex + uuid.uuid4().hex[:8]   # one-time, >=16 chars
        msg = conn.me.envelope("OBSERVE", {
            "display_id": "primary", "capture_format": "png", "upload_id": upload_id,
        }, task_id=task_id or self.next_task(), action_id=action_id or self.next_action())
        result = await conn.request(msg, ("OBSERVE_RESULT",), timeout=timeout)
        p = result["payload"]
        self.last_observation = p
        log.info("  observation %s %sx%s sha256=%s…", p["observation_id"], p["width"], p["height"], p["sha256"][:12])
        return p

    async def observe(self, *, task_id: str | None = None, action_id: str | None = None) -> dict:
        return await self._observe(self._live(), task_id=task_id, action_id=action_id)

    async def action(self, operation: str, arguments: dict, observation_id: str | None = None,
                     timeout_ms: int = 10000, *, task_id: str | None = None,
                     action_id: str | None = None, policy_version: str = POLICY_VERSION) -> dict:
        """Returns the ACTION_RESULT, or the ACK itself if the Runner rejected the action."""
        conn = self._live()
        if observation_id is None:
            if self.last_observation is None:
                raise ProtocolError("STALE_OBSERVATION", "observe before acting")
            observation_id = self.last_observation["observation_id"]
        action_id = action_id or self.next_action()
        msg = conn.me.envelope("ACTION_REQUEST", {
            "operation": operation, "arguments": arguments, "observation_id": observation_id,
            "policy_version": policy_version, "timeout_ms": timeout_ms,
        }, task_id=task_id or self.next_task(), action_id=action_id)
        self.actions[action_id] = "SENT"
        self.last_action_id = action_id
        try:
            result = await conn.request(msg, ("ACK", "ACTION_RESULT"), timeout=timeout_ms / 1000,
                                        final_if=lambda m: m["type"] == "ACK" and m["status"] == "REJECTED")
        except ProtocolError:
            self.actions[action_id] = "UNKNOWN"      # §7: find out with STATE_REQUEST, never re-send
            raise
        if result["type"] == "ACK":                   # REJECTED: never queued, nothing ran
            self.actions[action_id] = "REJECTED"
            log.warning("  %s %s rejected by Runner: %s", action_id, operation, result["payload"]["reject_reason"])
            return result
        self.actions[action_id] = result["status"]
        log.info("  %s %s -> %s %s", action_id, operation, result["status"], result["payload"]["result"])
        return result

    async def _state(self, conn: Connection, action_id: str | None, timeout: float = 3.0) -> dict:
        msg = conn.me.envelope("STATE_REQUEST", {"action_id": action_id})
        state = await conn.request(msg, ("STATE_RESULT",), timeout=timeout)
        log.info("  state: %s action=%s", state["payload"]["runtime_state"], state["payload"]["action_state"])
        return state

    async def state(self, action_id: str | None = None) -> dict:
        return await self._state(self._live(), action_id)

    async def terminate(self, reason: str = "TASK_COMPLETE") -> dict:
        conn = self._live()
        msg = conn.me.envelope("TERMINATE", {"reason": reason, "grace_ms": 1000})
        self.terminated = True                     # no reconnects from here on, even if the reply is lost
        self.end_reason = reason
        self.ready.clear()
        if self._on_terminated:
            self._on_terminated(self.identity)
        return await conn.request(msg, ("TERMINATE_RESULT",), timeout=5.0)
