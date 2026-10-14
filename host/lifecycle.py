"""The Host's side of the Lifecycle team's Sandbox Manager (b-hamo/sandbox_manager).

When the Agent submits its task, the Windows Sandbox is started for this
session; when the session ends, it is stopped and its workspace removed.

    task_submit ─▶ begin() ── returns at once, the Agent sees PREPARING
                     └▶ prepare → start (Host address) → certificate + bootstrap → publish_bootstrap
    Runner READY ─▶ mark_ready            (the spent token file is deleted)
    session ends ─▶ stop → cleanup        (TERMINATE first when the Runner is still there)

Recovery while the Host is alive (the Host decides when; the Sandbox Manager does it):

    connection lost, no reconnect within the grace period
        Sandbox still there  ─▶ restart_runner(generation+1)   same Sandbox, new Runner (2~5 s)
        Sandbox gone         ─▶ no restart: the user closed it; end the session
    connected but UNRESPONSIVE (heartbeats missed) ─▶ reset_sandbox(generation+1)   new Sandbox
    restart_runner fails ─▶ reset_sandbox;  that fails too, or the limit is reached ─▶ end the session

    then, as at start: new token + bootstrap for the new generation → publish_bootstrap → READY → mark_ready

Each recovery is a new generation of the same session: a new RuntimeSession,
the old generation's tokens revoked and its messages refused. Actions that
had no result stay UNKNOWN and are never re-sent; the Agent is told once.
Sessions that ended for security reasons or failed their first Startup
Verification are not restarted (they never reach the health hook).

READY is decided only by the Host's Startup Verification, never here. The
Sandbox Manager blocks (wsb start, `wsb list` checks), so each call runs in
a worker thread; calls are never made from two threads at once.

Shared inbox (optional, --inbox): the folder inbox_download writes into is
mapped read-only and live into the Sandbox at prepare(), and the Sandbox
Manager's InboxWatcher lists each finished file for the Guest every second
until the session is stopped.

Shared folder (optional, --shared, 배주한 요청 2026-10-15): each session gets a
new folder under the --shared root, mapped writable at C:\\Shared. The Guest
copies its Desktop\\Shared there, so portable programs and files the Agent
saves appear on this computer, where nothing in that folder can run. At
session end sandbox_manager.finish_shared scans it with Microsoft Defender and
copies a clean folder to Downloads\\SandboxShared\\<session> (status()["shared"]).

The Host part the Sandbox Manager cannot do (certificate with the address in
its SAN, token, bootstrap.json) is the `publish` callable:
    publish(host_address, bootstrap_path, identity) -> certificate PEM
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

from host.runtime_session import Health, RuntimeSession
from host.startup import StartupReport

log = logging.getLogger("host-lifecycle")

Identity = tuple[str, str, int]

# Sandbox Manager stop reasons (manager.TERMINATION_REASONS). What terminate() sets
# as end_reason is one of these; anything else is a failure path.
TERMINATION_REASONS = ("TASK_COMPLETE", "USER_STOP", "SECURITY_VIOLATION", "TIMEOUT", "RUNTIME_ERROR")
RUNNER_EXIT_WAIT_S = 5.0          # after TERMINATE_RESULT, before `wsb stop` (grace_ms is 1 s)
WAIT_HINT = "call computer_observe with wait_ms=10000 to wait for it"

IDLE, LAUNCHING, PUBLISHED, READY, RECOVERING, STOPPING, STOPPED, FAILED = (
    "IDLE", "LAUNCHING", "PUBLISHED", "READY", "RECOVERING", "STOPPING", "STOPPED", "FAILED")


class _Aborted(Exception):
    """The session ended while the Sandbox was still starting."""


class _Gone(Exception):
    """The Sandbox is no longer there: treated as closed by the user, not restarted."""


def _describe(exc: BaseException) -> str:
    code = getattr(exc, "code", None)             # SandboxManagerError(code, message)
    message = getattr(exc, "message", None) or str(exc)
    return f"{code}: {message}" if code else f"{type(exc).__name__}: {message}"


class SandboxLauncher:
    def __init__(self, manager, runner_exe: Path, session: RuntimeSession,
                 publish: Callable[[str, Path, Identity], str], *,
                 new_session: Callable[[Identity], RuntimeSession] | None = None,
                 on_switch: Callable[[RuntimeSession, str], None] | None = None,
                 auto_recover: bool = True, runner_exit_wait_s: float = RUNNER_EXIT_WAIT_S,
                 inbox: Path | None = None, inbox_watcher=None,
                 shared_root: Path | None = None, shared_watcher=None, finish_shared=None):
        self.manager = manager
        self.inbox = Path(inbox) if inbox is not None else None
        self.shared_root = Path(shared_root) if shared_root is not None else None
        self.shared: Path | None = None              # this session's folder under shared_root
        self.shared_result: dict | None = None       # finish_shared() at session end
        self._make_shared_watcher = shared_watcher   # default: sandbox_manager.SharedWatcher
        self._finish_shared = finish_shared          # default: sandbox_manager.finish_shared
        self._shared_watcher = None
        # (manager, sandbox) -> object with start()/stop(); default: sandbox_manager.inbox.InboxWatcher
        self._make_watcher = inbox_watcher
        self._watcher = None
        self.runner_exe = Path(runner_exe)
        self.session = session                       # the current generation
        self.publish = publish
        self.new_session = new_session               # Sessions.get: a RuntimeSession for an identity
        self.on_switch = on_switch                   # tell the Broker about the new generation
        self.auto_recover = auto_recover and new_session is not None
        self.runner_exit_wait_s = runner_exit_wait_s
        self.state = IDLE
        self.error: str | None = None
        self.host_address: str | None = None
        self.sandbox = None                          # SandboxSession once prepared
        self.recoveries: list[str] = []              # what was done, in order
        self._first_generation = session.identity[2]
        self.cleanup_result: dict | None = None
        self._launch: asyncio.Task | None = None
        self._recovery: asyncio.Task | None = None
        self._ready: asyncio.Task | None = None
        self._finish: asyncio.Task | None = None

    def status(self) -> dict:
        st = {"state": self.state, "host_address": self.host_address, "error": self.error,
              "generation": self.session.identity[2], "recoveries": list(self.recoveries)}
        if self.shared_root is not None:
            st["shared"] = {"guest_folder": "Desktop\\Shared", "host_folder": str(self.shared) if self.shared else None,
                            "at_end": self.shared_result}
        return st

    def hint(self) -> str | None:
        """What the Agent should do while the runtime is not READY."""
        if self.state == RECOVERING or (self.state == PUBLISHED and not self.session.verified
                                        and self.session.identity[2] > self._first_generation):
            return f"it is being restarted after it stopped answering; {WAIT_HINT}"
        if self.state in (LAUNCHING, PUBLISHED) and not self.session.verified:
            return f"the Sandbox is starting; {WAIT_HINT}"
        if self.session.verified and self.session.disconnected() and self.auto_recover:
            return ("the connection to the Runner was lost; if it does not come back it is restarted "
                    f"automatically; {WAIT_HINT}")
        return None

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
            if self.shared_root is not None:
                from sandbox_manager import make_share
                self._alive()
                self.shared = await asyncio.to_thread(make_share, self.shared_root, s.identity[0])
                log.info("SHARED %s: %s mapped writable at C:\\Shared", s.identity[0], self.shared)
            extra = {k: v for k, v in (("inbox", self.inbox), ("shared", self.shared)) if v is not None}
            if not extra:
                self.sandbox = await self._call(self.manager.prepare, *s.identity, self.runner_exe)
            else:
                self._alive()
                self.sandbox = await asyncio.to_thread(
                    lambda: self.manager.prepare(*s.identity, self.runner_exe, **extra))
                if self.inbox is not None:
                    self._start_watcher()
                if self.shared is not None:
                    self._start_shared_watcher()
            self.host_address = await self._call(self.manager.start, self.sandbox)
            log.info("SANDBOX %s started, Host address for the Runner: %s", s.identity[0], self.host_address)
            await self._publish()
            log.info("SANDBOX %s bootstrap published; waiting for the Runner", s.identity[0])
        except _Aborted:
            log.warning("SANDBOX %s start abandoned: session already ended (%s)", s.identity[0], s.end_reason)
        except Exception as e:  # noqa: BLE001 - every failure ends the session the same way
            self.state, self.error = FAILED, _describe(e)
            log.error("SANDBOX %s could not start: %s", s.identity[0], self.error)
            await s.fail_startup(f"sandbox {self.error}")

    def _start_watcher(self) -> None:
        if self._make_watcher is None:
            from sandbox_manager.inbox import InboxWatcher
            self._make_watcher = InboxWatcher
        self._watcher = self._make_watcher(self.manager, self.sandbox)
        self._watcher.start()
        log.info("INBOX %s mapped read-only into the Sandbox; watching it for finished files",
                 self.session.identity[0])

    def _clear_inbox(self, session_id: str) -> None:
        """Session over: the inbox is emptied (team decision 2026-10-11: default delete; what the user
        wanted to keep was copied to Downloads by inbox_finish before). The folder itself stays."""
        try:
            from sandbox_manager import clear_inbox
            n = clear_inbox(self.inbox)
            log.info("INBOX %s emptied at session end: %d files deleted", session_id, n)
        except Exception as e:  # noqa: BLE001 - a file in use stays; the next session's start lists it again
            log.warning("INBOX %s could not be emptied: %s", session_id, _describe(e))

    def _stop_watcher(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()
            self._watcher = None
        if self._shared_watcher is not None:
            self._shared_watcher.stop()
            self._shared_watcher = None

    def _start_shared_watcher(self) -> None:
        if self._make_shared_watcher is None:
            from sandbox_manager import SharedWatcher
            self._make_shared_watcher = SharedWatcher
        self._shared_watcher = self._make_shared_watcher(self.manager, self.sandbox)
        self._shared_watcher.start()

    def _end_shared(self, session_id: str) -> None:
        """Session over: scan the shared folder; a clean one is copied to Downloads\\SandboxShared."""
        try:
            if self._finish_shared is None:
                from sandbox_manager import finish_shared
                self._finish_shared = finish_shared
            self.shared_result = self._finish_shared(self.shared)
            r = self.shared_result
            log.info("SHARED %s at session end: %s, %d files, scan %s, copied to %s", session_id, r["status"],
                     len(r["files"]), r["scan"], r["dest"])
            if r["status"] in ("BLOCKED", "QUARANTINED"):
                log.warning("SECURITY shared folder %s kept where nothing runs: %s", r["share"], r["scan"])
        except Exception as e:  # noqa: BLE001 - the folder stays where nothing can run
            self.shared_result = {"status": "QUARANTINED", "share": str(self.shared), "dest": None, "files": [],
                                  "scan": f"error: {_describe(e)}", "events": []}
            log.warning("SHARED %s could not be finished: %s", session_id, _describe(e))

    async def _publish(self) -> None:
        """Certificate for the address, token and bootstrap for the current generation, then hand over."""
        self._alive()
        cert_pem = self.publish(self.host_address, self.sandbox.bootstrap_path, self.session.identity)
        await self._call(self.manager.publish_bootstrap, self.sandbox, cert_pem)
        self.state = PUBLISHED

    async def _call(self, fn, *args):
        self._alive()
        return await asyncio.to_thread(fn, *args)

    def _alive(self) -> None:
        if self.session.terminated:
            raise _Aborted()

    # -- READY -----------------------------------------------------------------
    def on_startup(self, identity: Identity, report: StartupReport) -> None:
        """RuntimeSession's on_startup. Failures arrive through session_ended instead."""
        if (report.ok and identity == self.session.identity and self._launch is not None
                and self._ready is None):
            self._ready = asyncio.get_running_loop().create_task(self._mark_ready(identity))

    async def _mark_ready(self, identity: Identity) -> None:
        # publish_bootstrap has returned (first start or a recovery)
        await asyncio.gather(*[t for t in (self._launch, self._recovery) if t], return_exceptions=True)
        if self.state != PUBLISHED or self.session.terminated or identity != self.session.identity:
            return
        try:
            await asyncio.to_thread(self.manager.mark_ready, self.sandbox)
            self.state = READY
        except Exception as e:  # noqa: BLE001 - the Runner is verified; only the token file lingers
            log.error("SANDBOX %s mark_ready failed: %s", identity[0], _describe(e))

    # -- recovery --------------------------------------------------------------
    def on_health(self, identity: Identity, old: Health, new: Health, why: str) -> None:
        """RuntimeSession's on_health. Only UNRESPONSIVE of a verified current generation matters."""
        s = self.session
        if (new is not Health.UNRESPONSIVE or identity != s.identity or not s.verified or s.terminated
                or self.sandbox is None or self._finish is not None
                or (self._recovery is not None and not self._recovery.done())):
            return
        loop = asyncio.get_running_loop()
        if not self.auto_recover:
            log.error("SANDBOX %s %s; automatic restart is off, ending the session", identity[0], why)
            loop.create_task(s._end(f"RUNTIME_LOST: {why}"))
            return
        kind = "runner" if s.conn is None else "sandbox"    # lost and not back / connected but silent
        self._recovery = loop.create_task(self._recover(kind, why))

    def _next_generation(self, why: str) -> RuntimeSession:
        """Swap to a new RuntimeSession for generation+1 and retire the current one."""
        old = self.session
        new = self.new_session((*old.identity[:2], old.identity[2] + 1))
        unresolved = new.inherit(old)
        self.session, self._ready = new, None
        notice = (f"The runtime stopped answering ({why}) and was restarted (generation {new.identity[2]}). "
                  "Its screen may have changed: call computer_observe before acting.")
        if unresolved:
            notice += (f" Actions {unresolved} had no result and were NOT re-sent; "
                       "check the screen before repeating any of them.")
        if self.on_switch:
            self.on_switch(new, notice)
        return new

    async def _recover(self, kind: str, why: str) -> None:
        old = self.session
        self.state = RECOVERING
        log.warning("SANDBOX %s recovering (%s): %s", old.identity[0], kind, why)
        # First: is the Sandbox still there? A closed window also looks like "connected but
        # silent" (no TCP close arrives when the virtual adapter vanishes), so this check
        # decides before anything is restarted. Gone = closed by the user: never restarted.
        try:
            gone = not await self._call(self.manager.is_running, self.sandbox)
        except _Aborted:
            return
        except Exception as e:  # noqa: BLE001 - cannot tell; do not restart blindly
            log.error("SANDBOX %s is_running failed: %s", old.identity[0], _describe(e))
            gone = False
        if gone:
            log.warning("SANDBOX %s is gone (closed); not restarting", old.identity[0])
            await old._end("RUNTIME_GONE: the Sandbox was closed")
            return
        new = self._next_generation(why)
        await old._end(f"REPLACED: {why}")          # its tokens are revoked; it is not current any more
        new.start_watchdog()                         # READY again within profile.timeout_s
        try:
            if kind == "runner":
                try:
                    await self._restart_runner()
                    self.recoveries.append("restart_runner")
                except _Gone:
                    raise
                except Exception as e:  # noqa: BLE001 - next step up is a fresh Sandbox
                    if "restart limit" in _describe(e):
                        raise
                    log.warning("SANDBOX %s Runner restart failed (%s); resetting the Sandbox",
                                new.identity[0], _describe(e))
                    if self.sandbox.generation >= self.session.identity[2]:
                        # restart_runner had already moved to this generation: use the next one
                        retired = self.session
                        new = self._next_generation(why)
                        await retired._end("REPLACED: Runner restart failed")
                        new.start_watchdog()
                    kind = "sandbox"
            if kind == "sandbox":
                self.host_address = await self._call(self.manager.reset_sandbox, self.sandbox,
                                                     self.session.identity[2])
                self.recoveries.append("reset_sandbox")
                log.info("SANDBOX %s reset, Host address for the Runner: %s", new.identity[0], self.host_address)
            await self._publish()
            log.info("SANDBOX %s generation %d published; waiting for the Runner",
                     self.session.identity[0], self.session.identity[2])
        except _Aborted:
            log.warning("SANDBOX %s recovery abandoned: session ended (%s)",
                        self.session.identity[0], self.session.end_reason)
        except _Gone:
            log.warning("SANDBOX %s is gone (closed); not restarting", self.session.identity[0])
            await self.session._end("RUNTIME_GONE: the Sandbox was closed")
        except Exception as e:  # noqa: BLE001 - nothing left to try
            self.state, self.error = FAILED, _describe(e)
            log.error("SANDBOX %s recovery failed: %s", self.session.identity[0], self.error)
            await self.session.fail_startup(f"recovery {self.error}")

    async def _restart_runner(self) -> None:
        if not await self._call(self.manager.is_running, self.sandbox):
            raise _Gone()
        try:
            await self._call(self.manager.restart_runner, self.sandbox, self.session.identity[2])
        except Exception as e:
            if getattr(e, "code", None) == "RUNTIME_UNAVAILABLE" and "gone" in _describe(e):
                raise _Gone() from e
            raise

    # -- end -------------------------------------------------------------------
    def session_ended(self, identity: Identity) -> None:
        """Called whenever a session ends (Sessions on_end). A retired generation does not stop anything."""
        if identity != self.session.identity:
            return
        if self._finish is None:
            self._finish = asyncio.get_running_loop().create_task(self._stop_and_clean())

    async def _stop_and_clean(self) -> None:
        # Never call stop() while start(), a recovery or mark_ready() is still running in its thread.
        for task in (self._launch, self._recovery, self._ready):
            if task is not None and task is not asyncio.current_task():
                await asyncio.gather(task, return_exceptions=True)
        s = self.session
        self._stop_watcher()                         # before stop(): no more scans of a closing Sandbox
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
            if self.inbox is not None:
                await asyncio.to_thread(self._clear_inbox, s.identity[0])
            if self.shared is not None:
                await asyncio.to_thread(self._end_shared, s.identity[0])
        except Exception as e:  # noqa: BLE001 - reported; a Sandbox may still be running
            self.state, self.error = FAILED, _describe(e)
            log.error("SANDBOX %s stop/cleanup failed: %s (check `wsb list`)", s.identity[0], self.error)

    def _stop_reason(self) -> tuple[str, bool]:
        """(Sandbox Manager reason, emergency). Emergency: the Runner got no TERMINATE."""
        why = self.session.end_reason or ""
        if why in TERMINATION_REASONS:
            return why, False                        # terminate(): TERMINATE was sent
        if why.startswith(("STOPPED_BY_AGENT", "HOST_EXIT", "RUNTIME_GONE")):
            return "USER_STOP", True                 # no Runner to tell
        if why.startswith("RUNTIME_START_FAILED") and "timeout" in why:
            return "TIMEOUT", True
        return "RUNTIME_ERROR", True

    async def shutdown(self, timeout: float = 60.0) -> None:
        """The Host is exiting (Codex closed stdin): end the session, then stop the Sandbox."""
        try:
            async with asyncio.timeout(timeout):
                await self._shutdown()
        except asyncio.TimeoutError:
            log.error("SANDBOX %s not stopped within %.0fs of Host exit", self.session.identity[0], timeout)
            raise TimeoutError("Sandbox shutdown unconfirmed") from None

    async def _shutdown(self) -> None:
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
            self.session_ended(self.session.identity)
        if self._finish is None:
            return
        await asyncio.shield(self._finish)
        if self.sandbox is not None and (self.cleanup_result is None or self.cleanup_result.get("failed")):
            raise RuntimeError("Sandbox cleanup unconfirmed")
