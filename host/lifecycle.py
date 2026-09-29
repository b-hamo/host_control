"""The Host's side of the Lifecycle team's Sandbox Manager (b-hamo/sandbox_manager).

When the Agent submits its task, the Windows Sandbox is started for this
session; when the session ends, it is stopped and its workspace removed.

    task_submit ─▶ begin() ── returns at once, the Agent sees PREPARING
                     └▶ prepare → start (Host address) → certificate + bootstrap → publish_bootstrap
    Runner READY ─▶ mark_ready            (the spent token file is deleted)
    session ends ─▶ stop → cleanup        (TERMINATE first when the Runner is still there)

READY is decided only by the Host's Startup Verification, never here. The
Sandbox Manager blocks (wsb start, `wsb list` checks), so each call runs in
a worker thread; calls are never made from two threads at once.

The Host part the Sandbox Manager cannot do (certificate with the address in
its SAN, token, bootstrap.json) is the `publish` callable:
    publish(host_address, bootstrap_path) -> certificate PEM
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

from host.runtime_session import RuntimeSession
from host.startup import StartupReport

log = logging.getLogger("host-lifecycle")

# Sandbox Manager stop reasons (manager.TERMINATION_REASONS). What terminate() sets
# as end_reason is one of these; anything else is a failure path.
TERMINATION_REASONS = ("TASK_COMPLETE", "USER_STOP", "SECURITY_VIOLATION", "TIMEOUT", "RUNTIME_ERROR")
RUNNER_EXIT_WAIT_S = 5.0          # after TERMINATE_RESULT, before `wsb stop` (grace_ms is 1 s)

IDLE, LAUNCHING, PUBLISHED, READY, STOPPING, STOPPED, FAILED = (
    "IDLE", "LAUNCHING", "PUBLISHED", "READY", "STOPPING", "STOPPED", "FAILED")


class _Aborted(Exception):
    """The session ended while the Sandbox was still starting."""


def _describe(exc: BaseException) -> str:
    code = getattr(exc, "code", None)             # SandboxManagerError(code, message)
    message = getattr(exc, "message", None) or str(exc)
    return f"{code}: {message}" if code else f"{type(exc).__name__}: {message}"


class SandboxLauncher:
    def __init__(self, manager, runner_exe: Path, session: RuntimeSession,
                 publish: Callable[[str, Path], str], *, runner_exit_wait_s: float = RUNNER_EXIT_WAIT_S):
        self.manager = manager
        self.runner_exe = Path(runner_exe)
        self.session = session
        self.publish = publish
        self.runner_exit_wait_s = runner_exit_wait_s
        self.state = IDLE
        self.error: str | None = None
        self.host_address: str | None = None
        self.sandbox = None                          # SandboxSession once prepared
        self.cleanup_result: dict | None = None
        self._launch: asyncio.Task | None = None
        self._finish: asyncio.Task | None = None

    def status(self) -> dict:
        return {"state": self.state, "host_address": self.host_address, "error": self.error}

    # -- start -----------------------------------------------------------------
    def begin(self) -> bool:
        """Start the Sandbox in the background. Only the first call does anything."""
        if self._launch is not None or self.session.terminated:
            return False
        self.state = LAUNCHING
        # Boot + Startup Verification must finish within profile.timeout_s from now (protocol doc §7).
        self.session.start_watchdog()
        self._launch = asyncio.get_running_loop().create_task(self._run_launch())
        return True

    async def _run_launch(self) -> None:
        s = self.session
        try:
            self.sandbox = await self._call(self.manager.prepare, *s.identity, self.runner_exe)
            self.host_address = await self._call(self.manager.start, self.sandbox)
            log.info("SANDBOX %s started, Host address for the Runner: %s", s.identity[0], self.host_address)
            self._alive()
            cert_pem = self.publish(self.host_address, self.sandbox.bootstrap_path)
            await self._call(self.manager.publish_bootstrap, self.sandbox, cert_pem)
            self.state = PUBLISHED
            log.info("SANDBOX %s bootstrap published; waiting for the Runner", s.identity[0])
        except _Aborted:
            log.warning("SANDBOX %s start abandoned: session already ended (%s)", s.identity[0], s.end_reason)
        except Exception as e:  # noqa: BLE001 - every failure ends the session the same way
            self.state, self.error = FAILED, _describe(e)
            log.error("SANDBOX %s could not start: %s", s.identity[0], self.error)
            await s.fail_startup(f"sandbox {self.error}")

    async def _call(self, fn, *args):
        self._alive()
        return await asyncio.to_thread(fn, *args)

    def _alive(self) -> None:
        if self.session.terminated:
            raise _Aborted()

    # -- READY -----------------------------------------------------------------
    def on_startup(self, identity: tuple[str, str, int], report: StartupReport) -> None:
        """RuntimeSession's on_startup. Failures arrive through session_ended instead."""
        if report.ok and self._launch is not None:
            asyncio.get_running_loop().create_task(self._mark_ready())

    async def _mark_ready(self) -> None:
        await asyncio.gather(self._launch, return_exceptions=True)   # publish_bootstrap has returned
        if self.state != PUBLISHED or self.session.terminated:
            return
        try:
            await asyncio.to_thread(self.manager.mark_ready, self.sandbox)
            self.state = READY
        except Exception as e:  # noqa: BLE001 - the Runner is verified; only the token file lingers
            log.error("SANDBOX %s mark_ready failed: %s", self.session.identity[0], _describe(e))

    # -- end -------------------------------------------------------------------
    def session_ended(self, identity: tuple[str, str, int]) -> None:
        """Called whenever the session ends, whatever the reason (Sessions on_end)."""
        if self._finish is None:
            self._finish = asyncio.get_running_loop().create_task(self._stop_and_clean())

    async def _stop_and_clean(self) -> None:
        s = self.session
        if self._launch is not None:
            # Never call stop() while start() is still running in its thread.
            await asyncio.gather(self._launch, return_exceptions=True)
        if self.sandbox is None:
            return
        reason, emergency = self._stop_reason()
        if not emergency and s.conn is not None:
            try:                                     # let the Runner exit after TERMINATE_RESULT
                await asyncio.wait_for(s.conn.closed.wait(), self.runner_exit_wait_s)
            except asyncio.TimeoutError:
                pass
        failed = self.state == FAILED
        self.state = STOPPING
        log.info("SANDBOX %s stopping: %s%s", s.identity[0], reason, " (emergency)" if emergency else "")
        try:
            await asyncio.to_thread(self.manager.stop, self.sandbox, reason, emergency=emergency)
            self.cleanup_result = await asyncio.to_thread(self.manager.cleanup, self.sandbox)
            self.state = FAILED if failed else STOPPED
            log.info("SANDBOX %s stopped and cleaned up: %s", s.identity[0], self.cleanup_result)
        except Exception as e:  # noqa: BLE001 - reported; a Sandbox may still be running
            self.state, self.error = FAILED, _describe(e)
            log.error("SANDBOX %s stop/cleanup failed: %s (check `wsb list`)", s.identity[0], self.error)

    def _stop_reason(self) -> tuple[str, bool]:
        """(Sandbox Manager reason, emergency). Emergency: the Runner got no TERMINATE."""
        why = self.session.end_reason or ""
        if why in TERMINATION_REASONS:
            return why, False                        # terminate(): TERMINATE was sent
        if why.startswith(("STOPPED_BY_AGENT", "HOST_EXIT")):
            return "USER_STOP", True                 # stopped before READY: no Runner to tell
        if why.startswith("RUNTIME_START_FAILED") and "timeout" in why:
            return "TIMEOUT", True
        return "RUNTIME_ERROR", True

    async def shutdown(self, timeout: float = 60.0) -> None:
        """The Host is exiting (Codex closed stdin): end the session, then stop the Sandbox."""
        s = self.session
        if not s.terminated:
            if s.ready.is_set():
                try:
                    await s.terminate("USER_STOP")
                except Exception as e:  # noqa: BLE001 - stop the Sandbox anyway
                    log.warning("TERMINATE on exit failed: %s", e)
            else:
                await s._end("HOST_EXIT")
        if self._finish is None:
            self.session_ended(s.identity)
        try:
            await asyncio.wait_for(asyncio.shield(self._finish), timeout)
        except asyncio.TimeoutError:
            log.error("SANDBOX %s not stopped within %.0fs of Host exit", s.identity[0], timeout)
