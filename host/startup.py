"""Startup Verification: the Host decides READY, not the Runner (WBS 4.5).

Protocol doc §4 step 6: the Host confirms Worker, required monitors and a
first capture, and only then promotes the Runtime to READY; the Runner saying
it is ready is not enough. Spec J-4: every required check must pass, and the
timeout and failure reasons are recorded in a standard form.

Two groups of checks:
- HELLO checks, on every connection (a reconnecting Runner must not come back
  with less than it started with): version, capabilities, monitoring
  coverage, clock skew.
- Runtime checks, on the first connection only: Worker alive (STATE_REQUEST),
  a first capture (OBSERVE), a heartbeat round trip (HEARTBEAT → ALIVE).
  Reconnects run the resync in runtime_session.py instead, which observes too.

Workspace readiness (mapped folders etc.) is checked on the Lifecycle side
(WBS 3.2·3.3) and is not part of this.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from scrp.envelope import parse_utc
from scrp.validate import ProtocolError

if TYPE_CHECKING:
    from host.connection import Connection
    from host.runtime_session import RuntimeSession

PROTOCOL_VERSION = "1.0"
STARTUP_TIMEOUT_S = 120.0         # protocol doc §7: boot + Startup Verification
MAX_CLOCK_SKEW_S = 60.0           # §7: large skew means no READY
MAX_CAPTURE_AGE_S = 10.0          # §6: older than 10 s is stale


@dataclass(frozen=True)
class StartupProfile:
    """What this session needs from its Runtime. Initial values; to be agreed
    with the Runner and Security owners (issue #6)."""
    required_capabilities: tuple[str, ...] = ("gui.observe", "gui.input")
    required_monitoring: tuple[str, ...] = ("file",)
    timeout_s: float = STARTUP_TIMEOUT_S
    step_timeout_s: float = 5.0   # per request during verification


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class StartupReport:
    ok: bool | None = None                    # None while still running
    checks: list[Check] = field(default_factory=list)
    reason: str | None = None                 # first failure, or the timeout
    started_at: float = field(default_factory=time.monotonic)
    finished_at: float | None = None

    def add(self, name: str, ok: bool, detail: str) -> bool:
        self.checks.append(Check(name, ok, detail))
        if not ok and self.reason is None:
            self.reason = f"{name}: {detail}"
        return ok

    def finish(self, ok: bool, reason: str | None = None) -> None:
        self.ok = ok and all(c.ok for c in self.checks)
        if reason and self.reason is None:
            self.reason = reason
        self.finished_at = time.monotonic()

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "elapsed_s": round((self.finished_at or time.monotonic()) - self.started_at, 2),
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
        }


def check_hello(hello: dict, profile: StartupProfile, report: StartupReport) -> bool:
    """Static checks on what the Runner declared. Returns True if all passed."""
    p = hello["payload"]
    ok = report.add("version", PROTOCOL_VERSION in p["supported_versions"],
                    f"supports {p['supported_versions']}, need {PROTOCOL_VERSION}")
    missing = [c for c in profile.required_capabilities if c not in p["capabilities"]]
    ok &= report.add("capabilities", not missing,
                     f"missing {missing}" if missing else f"has {sorted(profile.required_capabilities)}")
    cov = p["monitoring_coverage"]
    missing = [m for m in profile.required_monitoring if not cov.get(m)]
    ok &= report.add("monitoring", not missing,
                     f"missing {missing} monitor" if missing else f"has {sorted(profile.required_monitoring)}")
    skew = abs((datetime.now(timezone.utc) - parse_utc(hello["timestamp"])).total_seconds())
    ok &= report.add("clock", skew <= MAX_CLOCK_SKEW_S, f"skew {skew:.0f}s (max {MAX_CLOCK_SKEW_S:.0f}s)")
    return ok


async def verify_runtime(session: RuntimeSession, conn: Connection,
                         profile: StartupProfile, report: StartupReport) -> bool:
    """Ask the Runtime to prove it works. Stops at the first failure."""
    t = profile.step_timeout_s
    try:
        st = (await session._state(conn, None, timeout=t))["payload"]
    except ProtocolError as e:
        return report.add("worker", False, f"no STATE_RESULT ({e.code})")
    if not report.add("worker", st["worker_alive"] and st["runtime_state"] not in ("FROZEN", "TERMINATED"),
                      f"worker_alive={st['worker_alive']} runtime_state={st['runtime_state']}"):
        return False

    started = time.monotonic()
    try:
        obs = await session._observe(conn, timeout=t)
    except ProtocolError as e:
        return report.add("first_capture", False, f"no usable capture ({e.code}: {e.detail})")
    took = time.monotonic() - started
    # Fresh by construction: it answered our request within the step timeout.
    # captured_at comes from the Runner's clock, so only check it is plausible
    # given the skew already allowed at HELLO.
    drift = abs((datetime.now(timezone.utc) - parse_utc(obs["captured_at"])).total_seconds())
    if not report.add("first_capture", drift <= MAX_CLOCK_SKEW_S + MAX_CAPTURE_AGE_S,
                      f"{obs['observation_id']} {obs['width']}x{obs['height']}, answered in {took * 1000:.0f} ms"
                      + ("" if drift <= MAX_CLOCK_SKEW_S + MAX_CAPTURE_AGE_S
                         else f", captured_at is {drift:.0f}s off the Host clock")):
        return False

    try:
        await session._heartbeat(conn, timeout=t)
    except ProtocolError as e:
        return report.add("heartbeat", False, f"no ALIVE ({e.code})")
    if not report.add("heartbeat", True, "ALIVE received"):
        return False

    # Profile-specific steps, e.g. artifact-export-v1: the Telemetry channel must be up
    # before work starts, because the Runner reports only files created after that.
    for step in session.startup_checks:
        name, ok, detail = await step(session)
        if not report.add(name, ok, detail):
            return False
    return True
