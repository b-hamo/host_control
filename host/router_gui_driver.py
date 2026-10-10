"""Concrete SCRP GUI driver with Manager inputs and inspected execution receipts.

The helper's receipt is observable Guest evidence, not hardware attestation: a
hostile process sharing the Guest account can tamper with Guest results. Host
policy, source verification and artifact inspection remain separate decisions.
No command, downloaded file or child process runs on the Host in this module.
"""

import asyncio
from dataclasses import replace
import hashlib
from pathlib import Path

from host.router_command_bundle import CommandBundle
from host.router_gui_policy import RouterGuiPolicy
from host.router_inputs import InputBoundManager
from router.models import Artifact, EXECUTION
from router.ports import Receipt, State


class GuiCommandDriver:
    def __init__(self, manager: InputBoundManager, policy: RouterGuiPolicy,
                 private_directory: Path, *, startup_timeout=180):
        self.manager, self.policy = manager, policy
        self.directory = Path(private_directory)
        self.startup_timeout = startup_timeout
        self.bundle = self.receipt = self._verified = None
        self._launch_task = None
        self._last_input = None
        self._execution_dispatched = False
        self._exports = set()
        self._poll_lock = asyncio.Lock()
        self._broker = None

    def supports(self, request):
        action = request.action
        return (action.operation in EXECUTION and action.fingerprint == self.manager.action.fingerprint
                and len(action.outputs) <= 1 and action.command is not None
                and {"process.execute", "gui.input", "gui.observe", "artifact.export.v1"}
                    <= set(action.scope.capabilities)
                and self.policy.command_launch_enabled)

    async def prepare(self, broker, request):
        if self.bundle is not None:
            if self.bundle.request != request:
                raise ValueError("driver already reserved for another request")
            return
        if (not self.supports(request) or broker.policy is not self.policy
                or broker.launcher is None or broker.launcher.manager is not self.manager
                or broker.artifacts is None):
            raise ValueError("Host command composition is incomplete")
        if self.manager.authority.check(request.action) != "ALLOW":
            raise ValueError("command authorization changed")
        self.bundle = CommandBundle(request, broker.session.identity, self.manager.bindings,
                                    self.directory / request.request_id)
        self.manager.configure_transport(self.bundle.inputs)
        self._broker = broker
        self._set(State.ACCEPTED, "COMMAND_PREPARED")

    def _set(self, state, reason, *, artifacts=(), evidence_ref=""):
        request, identity = self.bundle.request, self.bundle.identity
        self.receipt = Receipt(request.request_id, request.action.fingerprint, state, reason,
                               "EXEC-" + self.bundle.nonce, evidence_ref, artifacts, identity[1], identity[2])
        return self.receipt

    async def submit(self, broker, request):
        if self.bundle is None or request != self.bundle.request:
            raise ValueError("command was not prepared")
        if self._launch_task is None:
            # Set once, before yielding. Repeated submits/status never create another task.
            self._launch_task = asyncio.create_task(self._launch(broker))
        return self.receipt

    async def _launch(self, broker):
        try:
            deadline = asyncio.get_running_loop().time() + self.startup_timeout
            while not broker.session.ready.is_set():
                if getattr(broker.session, "terminated", False) or getattr(broker.launcher, "state", "") == "FAILED":
                    self._set(State.FAILED, "SANDBOX_START_FAILED")
                    return
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    self._set(State.FAILED, "SANDBOX_START_TIMEOUT")
                    return
                try:
                    await asyncio.wait_for(broker.session.ready.wait(), min(1, remaining))
                except TimeoutError:
                    pass
            if broker.session.identity != self.bundle.identity:
                self._set(State.UNKNOWN, "RUNTIME_CHANGED")
                return
            observed = await broker.call("computer_observe", {"wait_ms": 0})
            if not observed.ok or not observed.image:
                self._set(State.HELD, "VALIDATED_OBSERVATION_REQUIRED")
                return
            self.bundle.verify_files()
            self.manager.validate_prepared(broker.launcher.sandbox)
            with self.policy.launch(self.bundle.request.action, self.bundle.launch_line):
                steps = (("computer_hotkey", {"keys": ["win", "r"]}),
                         ("computer_type", {"text": self.bundle.launch_line}),
                         ("computer_keypress", {"key": "enter"}))
                for index, (tool, args) in enumerate(steps):
                    if index == 2:
                        self.bundle.verify_files()
                        self.manager.validate_prepared(broker.launcher.sandbox)
                        self._execution_dispatched = True
                    result = await broker.call(tool, args)
                    self._last_input = result.action_id
                    if not result.ok:
                        code = (result.error or {}).get("error")
                        rejected = getattr(broker.session, "actions", {}).get(result.action_id) in {"REJECTED", "BLOCKED"}
                        refused = code == "POLICY_DENIED" or rejected
                        self._set(State.DENIED if refused else State.UNKNOWN,
                                  "GUI_INPUT_REFUSED" if refused else "GUI_INPUT_UNCONFIRMED")
                        return
                    delivered = result.data.get("result", {})
                    if result.data.get("status") != "SUCCESS" or delivered.get("input_delivered") is not True:
                        self._set(State.UNKNOWN, "GUI_INPUT_PARTIAL_OR_UNCONFIRMED")
                        return
                    if index == 0:
                        observed = await broker.call("computer_observe", {"wait_ms": 500})
                        if not observed.ok or not observed.image:
                            self._set(State.UNKNOWN, "LAUNCH_SURFACE_UNCONFIRMED")
                            return
            self._set(State.RUNNING, "INPUT_DELIVERED_AWAITING_PROCESS_RESULT")
        except asyncio.CancelledError:
            self._set(State.UNKNOWN, "LAUNCH_INTERRUPTED")
            raise
        except Exception:
            self._set(State.UNKNOWN, "LAUNCH_UNCONFIRMED")

    async def approve_export(self, summary):
        """Host-owned per-request delegation, usable as Broker's approver.

        Only this command's receipt/stdout are delegated. This does not approve
        arbitrary files or waive the scanner; do not expose it as an Agent tool.
        """
        if self.bundle is None or self._broker is None or summary.get("tool") != "artifact_export":
            return False
        if (summary.get("session_id"), summary.get("runtime_id")) != self.bundle.identity[:2]:
            return False
        if self.manager.authority.check(self.bundle.request.action) != "ALLOW":
            return False
        artifact_id = summary.get("artifact_id")
        if artifact_id not in self._exports:
            return False
        art = self._broker.artifacts.precheck(self._broker.session, artifact_id)
        allowed = {self.bundle.evidence_name}
        if self.bundle.request.action.outputs:
            allowed.add(self.bundle.stdout_name)
        return art.relative_path in allowed

    async def _exported(self, broker, name):
        # Read Host registry via its public interface; pagination is required.
        candidates, cursor = [], None
        while True:
            result = await broker.call("artifact_list", {"limit": 200, "cursor": cursor})
            if not result.ok:
                return None
            candidates.extend(a for a in result.data["artifacts"]
                              if a["path"] == name and a["generation"] == self.bundle.identity[2])
            cursor = result.data["next_cursor"]
            if cursor is None:
                break
        if not candidates:
            return None
        if len(candidates) != 1:
            raise ValueError("ambiguous execution artifact")
        view = candidates[0]
        aid = view["artifact_id"]
        if view["status"] == "BLOCKED":
            self._set(State.HELD, "EXECUTION_ARTIFACT_BLOCKED")
            return None
        if view["status"] != "EXPORTED":
            if aid not in self._exports and view["can_export"]:
                self._exports.add(aid)  # reserve before awaiting; never retry after uncertainty
                result = await broker.call("artifact_export", {"artifact_id": aid,
                    "reason": "Verify the delegated Router command result"})
                if not result.ok:
                    self._set(State.HELD, "EXECUTION_ARTIFACT_EXPORT_REFUSED")
            return None
        art = broker.artifacts.precheck(broker.session, aid)
        current = broker.artifacts.view(art)
        if current["status"] != "EXPORTED":
            return None
        data = Path(current["export_path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != current["sha256"]:
            raise ValueError("exported execution artifact changed")
        return Artifact(aid, "EXPORTED", current["export_path"], current["sha256"]), data

    async def status(self, broker, request_id):
        if self.bundle is None or request_id != self.bundle.request.request_id:
            return Receipt(request_id, "", State.UNKNOWN, "REQUEST_NOT_FOUND")
        async with self._poll_lock:
            if broker.session.identity != self.bundle.identity:
                return self._set(State.UNKNOWN, "RUNTIME_CHANGED")
            if self.receipt.state in {State.SUCCEEDED, State.FAILED, State.DENIED, State.HELD}:
                return self.receipt
            if self._launch_task is None or not self._launch_task.done():
                return self.receipt
            try:
                if self.receipt.state == State.UNKNOWN:
                    await broker.call("runtime_get_state", {"action_id": self._last_input})
                if not self._execution_dispatched:
                    return self.receipt
                exported = await self._exported(broker, self.bundle.evidence_name)
                if exported is None:
                    return self.receipt
                evidence_art, data = exported
                evidence = self.bundle.validate_evidence(data)
                if evidence["exit_code"] != 0:
                    return self._set(State.FAILED, "GUEST_PROCESS_FAILED", evidence_ref=evidence_art.artifact_id)
                artifacts = ()
                if self.bundle.request.action.outputs:
                    output = await self._exported(broker, self.bundle.stdout_name)
                    if output is None:
                        return self.receipt
                    artifact, _ = output
                    if artifact.sha256 != evidence["stdout_sha256"]:
                        raise ValueError("stdout does not match process result")
                    artifacts = (replace(artifact, output_name=self.bundle.request.action.outputs[0]),)
                self._verified = self._set(State.SUCCEEDED, "GUEST_PROCESS_VERIFIED", artifacts=artifacts,
                                           evidence_ref=evidence_art.artifact_id)
                return self.receipt
            except Exception:
                return self._set(State.UNKNOWN, "EXECUTION_EVIDENCE_UNCONFIRMED")

    async def verify(self, broker, receipt):
        if self._verified != receipt or broker.session.identity != self.bundle.identity:
            return False
        art = broker.artifacts.precheck(broker.session, receipt.evidence_ref)
        view = broker.artifacts.view(art)
        if view["status"] != "EXPORTED":
            return False
        data = Path(view["export_path"]).read_bytes()
        return (hashlib.sha256(data).hexdigest() == view["sha256"]
                and self.bundle.validate_evidence(data)["exit_code"] == 0)

    async def close(self):
        if self._launch_task is not None and not self._launch_task.done():
            self._launch_task.cancel()
            await asyncio.gather(self._launch_task, return_exceptions=True)
