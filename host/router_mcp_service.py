"""One Host-provisioned plan exposed through an allowlisted MCP contract.

Submission reservations survive stdio restarts. Lost responses never permit a
new dispatch. After a Host restart, unavailable execution evidence stays UNKNOWN.
"""

import asyncio
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sqlite3

from host.router_codec import action, task
from router import Router
from router.ports import Receipt, State


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


class RouterService:
    def __init__(self, runtime, plan_id, database: Path):
        self.host, self.plan_id = runtime, plan_id
        self.router = Router(runtime)
        self.tasks, self.actions, self.jobs = {}, {}, {}
        self.lock = asyncio.Lock()
        self.db = sqlite3.connect(database)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS submissions "
                        "(key TEXT PRIMARY KEY, action_id TEXT, fingerprint TEXT, contract TEXT, canonical TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS control (key TEXT PRIMARY KEY)")
        self.db.commit()
        self.stopped = self.db.execute("SELECT 1 FROM control WHERE key='stopped'").fetchone() is not None

    def _contract(self, aid):
        nodes = {}

        def visit_action(key):
            if "a:" + key in nodes:
                return
            a = self.actions[key]
            nodes["a:" + key] = a.fingerprint
            for dep in a.depends_on:
                visit_action(dep)
            for dep in self.tasks[a.task_id].depends_on:
                visit_task(dep)

        def visit_task(key):
            nodes["t:" + key] = asdict(self.tasks[key])
            for a in self.actions.values():
                if a.task_id == key:
                    visit_action(a.action_id)

        visit_action(aid)
        return checksum({"plan": self.plan_id, "nodes": nodes})

    def _row(self, request_id):
        return self.db.execute("SELECT action_id,fingerprint,contract,canonical FROM submissions WHERE key=?",
                               (checksum(request_id),)).fetchone()

    async def call(self, name, args):
        async with self.lock:
            if name == "router_stop":
                # Retire before waiting; even process death cannot reopen submissions.
                with self.db:
                    self.db.execute("INSERT OR IGNORE INTO control VALUES ('stopped')")
                self.stopped = True
                for job in self.jobs.values():
                    if not job.done():
                        job.cancel()
                await asyncio.gather(*self.jobs.values(), return_exceptions=True)
                await self.host.stop_sandbox()
                return {"ok": True, "plan_id": self.plan_id, "stopped": True}
            if name == "router_plan":
                if args["plan_id"] != self.plan_id:
                    raise ValueError("plan not provisioned")
                if any(not j.done() for j in self.jobs.values()):
                    return {"ok": False, "error": "PLAN_BUSY"}
                tasks = tuple(task(v) for v in args["tasks"])
                actions = tuple(action(v) for v in args["actions"])
                if len(self.tasks) + len(tasks) > 512 or len(self.actions) + len(actions) > 1024:
                    raise ValueError("plan limit exceeded")
                self.router.extend(tasks, actions)
                self.tasks.update((t.task_id, t) for t in tasks)
                self.actions.update((a.action_id, a) for a in actions)
                return {"ok": True, "plan_id": self.plan_id, "progress": self.router.snapshot()}
            if name == "router_submit":
                if self.stopped:
                    return {"ok": False, "error": "PLAN_STOPPED", "recommended_next_step": "router_status"}
                return await self._submit(args)
            if name in {"router_status", "router_result"}:
                result = await self._status(args["request_id"])
                if name == "router_result" and result["ok"]:
                    receipt = result["receipt"]
                    if receipt["state"] != State.SUCCEEDED:
                        return {**result, "ok": False, "error": "RESULT_NOT_VERIFIED"}
                    row = self._row(args["request_id"])
                    trusted = await self.host.status(row[3])
                    if not await self.host.verify(trusted):
                        return {"ok": False, "error": "RESULT_NOT_VERIFIED"}
                    if trusted.execution_id.startswith("LOCAL-"):
                        result["text"] = (await self.host.read_result(trusted)).decode("utf-8")
                    else:
                        result["outputs"] = []
                        for art in trusted.artifacts:
                            current = await self.host.artifact(art.output_name or art.artifact_id)
                            with Path(current.final_ref).open("rb") as stream:
                                data = stream.read(1048577)
                            if len(data) > 1048576 or hashlib.sha256(data).hexdigest() != current.sha256:
                                raise ValueError("result changed or too large")
                            result["outputs"].append({"artifact": asdict(current), "text": data.decode("utf-8")})
                return result
            return {"ok": False, "error": "TOOL_NOT_EXPOSED"}

    async def _submit(self, args):
        rid, aid = args["request_id"], args["action_id"]
        a = self.actions[aid]
        contract = self._contract(aid)
        old = self._row(rid)
        if old is not None:
            if old[:3] != (aid, a.fingerprint, contract):
                return {"ok": False, "error": "IDEMPOTENCY_CONFLICT"}
            return await self._status(rid)
        canonical = "REQ-" + checksum([self.plan_id, a.fingerprint])
        previous = self.db.execute("SELECT contract FROM submissions WHERE canonical=? LIMIT 1", (canonical,)).fetchone()
        if previous and previous[0] != contract:
            return {"ok": False, "error": "IDEMPOTENCY_CONFLICT"}
        if not previous and not self.router.ready(aid):
            return {"ok": False, "error": "DEPENDENCIES_UNCONFIRMED"}
        with self.db:
            self.db.execute("INSERT INTO submissions VALUES (?,?,?,?,?)",
                            (checksum(rid), aid, a.fingerprint, contract, canonical))
        if not previous:
            # Durable reservation before scheduling; caller disconnect cannot undo it.
            self.jobs[aid] = asyncio.create_task(self.router.run(aid, request_id=canonical))
        return await self._status(rid)

    async def _status(self, rid):
        row = self._row(rid)
        if row is None:
            return {"ok": False, "error": "REQUEST_NOT_FOUND"}
        aid, fp, contract, canonical = row
        pending = self.jobs.get(aid)
        if pending is not None and not pending.done():
            receipt = Receipt(canonical, fp, State.ACCEPTED, "REQUEST_RESERVED")
        elif aid not in self.actions:
            receipt = Receipt(canonical, fp, State.UNKNOWN, "PLAN_RECONCILIATION_REQUIRED")
        elif self.actions[aid].fingerprint != fp or self._contract(aid) != contract:
            return {"ok": False, "error": "IDEMPOTENCY_CONFLICT"}
        else:
            if pending is not None:
                # Retrieve exceptions without publishing their possibly sensitive text.
                try:
                    pending.result()
                except (Exception, asyncio.CancelledError):
                    pass
            receipt = await self.router.reconcile(aid, canonical)
        return {"ok": True, "plan_id": self.plan_id, "action_id": aid,
                "task_id": self.actions[aid].task_id if aid in self.actions else None,
                "receipt": asdict(replace(receipt, request_id=rid)), "progress": self.router.snapshot()}

    async def close(self):
        for job in self.jobs.values():
            if not job.done():
                job.cancel()
        await asyncio.gather(*self.jobs.values(), return_exceptions=True)
        self.db.close()
        await self.host.close()
