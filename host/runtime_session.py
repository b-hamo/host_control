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
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable

from host.connection import Connection
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
                 on_terminated: Callable[[tuple[str, str, int]], None] | None = None):
        self.identity = identity
        self.conn: Connection | None = None
        self.connections = 0
        self.ready = asyncio.Event()           # connected and resynced: actions allowed
        self.terminated = False
        self.health = HealthTracker(identity, on_health)
        self.actions: dict[str, str] = {}      # action_id -> SENT / UNKNOWN / final status
        self.last_observation: dict | None = None
        self.last_action_id: str | None = None
        self.heartbeat_interval_s = heartbeat_interval_s
        self.alive_timeout_s = alive_timeout_s
        self.reconnect_grace_s = reconnect_grace_s
        self._on_terminated = on_terminated
        self._task_seq = 0
        self._action_seq = 0
        self._grace: asyncio.Task | None = None
        self.demo_task: asyncio.Task | None = None

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
        if self.connections > 1:
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

    async def _heartbeat(self, conn: Connection) -> dict:
        lease_s = self.heartbeat_interval_s * UNRESPONSIVE_AFTER
        msg = conn.me.envelope("HEARTBEAT", {"lease_expires_at": _utc_in(lease_s)})
        alive = await conn.request(msg, ("ALIVE",), timeout=self.alive_timeout_s)
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
    async def _observe(self, conn: Connection) -> dict:
        upload_id = uuid.uuid4().hex + uuid.uuid4().hex[:8]   # one-time, >=16 chars
        msg = conn.me.envelope("OBSERVE", {
            "display_id": "primary", "capture_format": "png", "upload_id": upload_id,
        }, task_id=self.next_task(), action_id=self.next_action())
        result = await conn.request(msg, ("OBSERVE_RESULT",), timeout=5.0)
        p = result["payload"]
        self.last_observation = p
        log.info("  observation %s %sx%s sha256=%s…", p["observation_id"], p["width"], p["height"], p["sha256"][:12])
        return p

    async def observe(self) -> dict:
        return await self._observe(self._live())

    async def action(self, operation: str, arguments: dict, observation_id: str | None = None,
                     timeout_ms: int = 10000) -> dict:
        conn = self._live()
        if observation_id is None:
            if self.last_observation is None:
                raise ProtocolError("STALE_OBSERVATION", "observe before acting")
            observation_id = self.last_observation["observation_id"]
        action_id = self.next_action()
        msg = conn.me.envelope("ACTION_REQUEST", {
            "operation": operation, "arguments": arguments, "observation_id": observation_id,
            "policy_version": POLICY_VERSION, "timeout_ms": timeout_ms,
        }, task_id=self.next_task(), action_id=action_id)
        self.actions[action_id] = "SENT"
        self.last_action_id = action_id
        try:
            result = await conn.request(msg, ("ACK", "ACTION_RESULT"), timeout=timeout_ms / 1000)
        except ProtocolError:
            self.actions[action_id] = "UNKNOWN"      # §7: find out with STATE_REQUEST, never re-send
            raise
        self.actions[action_id] = result["status"]
        log.info("  %s %s -> %s %s", action_id, operation, result["status"], result["payload"]["result"])
        return result

    async def _state(self, conn: Connection, action_id: str | None) -> dict:
        msg = conn.me.envelope("STATE_REQUEST", {"action_id": action_id})
        state = await conn.request(msg, ("STATE_RESULT",), timeout=3.0)
        log.info("  state: %s action=%s", state["payload"]["runtime_state"], state["payload"]["action_state"])
        return state

    async def state(self, action_id: str | None = None) -> dict:
        return await self._state(self._live(), action_id)

    async def terminate(self, reason: str = "TASK_COMPLETE") -> dict:
        conn = self._live()
        msg = conn.me.envelope("TERMINATE", {"reason": reason, "grace_ms": 1000})
        self.terminated = True                     # no reconnects from here on, even if the reply is lost
        self.ready.clear()
        if self._on_terminated:
            self._on_terminated(self.identity)
        return await conn.request(msg, ("TERMINATE_RESULT",), timeout=5.0)
