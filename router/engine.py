"""Dependency scheduling, incremental plans and conservative completion tracking.

One Router instance owns one plan. Host idempotency must outlive this instance.
Task interpretation and alternative selection belong to the Agent/Skill.
"""

import asyncio
import hashlib
from dataclasses import replace
from uuid import uuid4

from router.models import Action, Task
from router.ports import HostPort, Receipt, Request, State


class Router:
    def __init__(self, host: HostPort):
        self.host = host
        self._tasks: dict[str, Task] = {}
        self._actions: dict[str, Action] = {}
        self._receipts: dict[str, Receipt] = {}
        self._requests: dict[str, Request] = {}
        self._replacement: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self.events: list[dict] = []  # allowlisted IDs/hashes/codes only

    def add_task(self, task: Task) -> None:
        if task.task_id in self._tasks or any(d not in self._tasks for d in task.depends_on):
            raise ValueError("duplicate task or unknown dependency")
        self._tasks[task.task_id] = task

    def add_action(self, action: Action) -> None:
        task = self._tasks[action.task_id]
        if action.action_id in self._actions or action.location != task.location:
            raise ValueError("duplicate action or mixed execution locations; split the task")
        if any(d not in self._actions for d in action.depends_on):
            raise ValueError("unknown action dependency")
        if self._task_started(task.task_id):
            raise ValueError("add discovered work as a separate task")
        self._actions[action.action_id] = action
        try:
            self._check_cycles()
        except ValueError:
            del self._actions[action.action_id]
            raise

    def _task_started(self, task_id: str) -> bool:
        return any(a.task_id == task_id and aid in self._requests for aid, a in self._actions.items())

    def require_task(self, task_id: str, discovered_task: str) -> None:
        """Insert newly discovered work before an unstarted continuation."""
        if self._task_started(task_id) or discovered_task not in self._tasks:
            raise ValueError("continuation already started or dependency unknown")
        old = self._tasks[task_id]
        self._tasks[task_id] = replace(old, depends_on=(*old.depends_on, discovered_task))
        try:
            self._check_cycles()
        except ValueError:
            self._tasks[task_id] = old
            raise

    def _check_cycles(self):
        graph = {"t:" + k: ["t:" + d for d in t.depends_on] +
                 ["a:" + a.action_id for a in self._actions.values() if a.task_id == k]
                 for k, t in self._tasks.items()}
        graph.update({"a:" + k: ["a:" + d for d in a.depends_on] +
                      ["t:" + d for d in self._tasks[a.task_id].depends_on]
                      for k, a in self._actions.items()})
        done, active = set(), set()

        def visit(node):
            if node in active:
                raise ValueError("cyclic plan")
            if node in done:
                return
            active.add(node)
            for dep in graph[node]:
                visit(dep)
            active.remove(node)
            done.add(node)

        for node in graph:
            visit(node)

    def _succeeded(self, action_id: str) -> bool:
        actual = self._replacement.get(action_id, action_id)
        receipt = self._receipts.get(actual)
        return receipt is not None and receipt.state == State.SUCCEEDED

    def task_complete(self, task_id: str) -> bool:
        actions = [a for a in self._actions.values() if a.task_id == task_id]
        return bool(actions) and all(self._succeeded(a.action_id) for a in actions)

    def snapshot(self) -> dict:
        """Safe progress summary: no source text, command arguments or private paths."""
        return {"tasks": {tid: {"location": task.location.value,
                                "depends_on": list(task.depends_on), "complete": self.task_complete(tid)}
                          for tid, task in self._tasks.items()},
                "actions": {aid: {"task_id": action.task_id, "access": action.access,
                                  "state": self._receipts[aid].state.value if aid in self._receipts else "PLANNED",
                                  "fingerprint": action.fingerprint,
                                  "replacement": self._replacement.get(aid)}
                            for aid, action in self._actions.items()}}

    async def run(self, action_id: str) -> Receipt:
        async with self._lock:
            action = self._actions[action_id]
            if action_id in self._requests:
                # Every repeat queries Host, even after a timeout; never submit again.
                return await self._poll(action_id)
            if any(not self.task_complete(d) for d in self._tasks[action.task_id].depends_on) or \
                    any(not self._succeeded(d) for d in action.depends_on):
                raise ValueError("dependencies have no verified completion")
            for aid in action.inputs:
                artifact = await self.host.artifact(aid)
                if artifact.status != "EXPORTED" or not artifact.final_ref:
                    raise ValueError("input is not exported")
            request = Request("REQ-" + uuid4().hex, action)
            self._requests[action_id] = request
            try:
                receipt = await self.host.submit(request)
            except asyncio.CancelledError:
                self._receipts[action_id] = self._unknown(request)
                raise
            except Exception:
                return await self._poll(action_id)
            return await self._accept(action_id, receipt)

    async def _poll(self, action_id: str) -> Receipt:
        request = self._requests[action_id]
        try:
            receipt = await self.host.status(request.request_id)
        except Exception:
            receipt = self._unknown(request)
        return await self._accept(action_id, receipt)

    @staticmethod
    def _unknown(request: Request) -> Receipt:
        return Receipt(request.request_id, request.action.fingerprint, State.UNKNOWN, "STATUS_UNCONFIRMED")

    async def _accept(self, action_id: str, receipt: Receipt) -> Receipt:
        request = self._requests[action_id]
        if receipt.request_id != request.request_id or receipt.fingerprint != request.action.fingerprint:
            receipt = self._unknown(request)
        elif receipt.state == State.SUCCEEDED:
            try:
                valid = bool(receipt.execution_id and receipt.evidence_ref) and await self.host.verify(receipt)
                names = [a.output_name or a.artifact_id for a in receipt.artifacts]
                valid = valid and len(names) == len(set(names)) and set(request.action.outputs) == set(names)
            except Exception:
                valid = False
            if not valid:
                receipt = self._unknown(request)
        self._receipts[action_id] = receipt
        # Do not log raw Host reason strings; even errors may contain secrets.
        self.events.append({"task_id": request.action.task_id, "action_id": action_id,
                            "request_id": request.request_id, "fingerprint": receipt.fingerprint,
                            "location": request.action.location.value, "state": receipt.state.value,
                            "reason_sha256": hashlib.sha256(receipt.reason.encode()).hexdigest()})
        return receipt

    def use_alternative(self, denied_action: str, completed_alternative: str) -> None:
        """Only a separately Host-authorized, verified alternative can unblock consumers."""
        old = self._receipts.get(denied_action)
        if old is None or old.state != State.DENIED or not self._succeeded(completed_alternative):
            raise ValueError("a denied action and an allowed completed alternative are required")
        if self._actions[denied_action].outputs != self._actions[completed_alternative].outputs:
            raise ValueError("alternative output contract differs")
        self._replacement[denied_action] = completed_alternative
