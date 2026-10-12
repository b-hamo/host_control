"""One Host-provisioned plan exposed through an allowlisted MCP contract.

Retirement persists verified results before releasing the execution Host.
Stopped plans reopen query-only; missing completion evidence stays UNKNOWN.
"""

import asyncio
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import closing

from host.router_codec import action, task
from router import Router
from router.ports import Receipt, State

CANCEL_WAIT_S = 5.0
SNAPSHOT_WAIT_S = 10.0


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
        self.db.execute("CREATE TABLE IF NOT EXISTS retired_results (canonical TEXT PRIMARY KEY, value TEXT)")
        self.db.commit()
        self.stopped = self.db.execute("SELECT 1 FROM control WHERE key='stopped'").fetchone() is not None
        self._retirement = None
        self._closed = False
        self._watcher = (asyncio.create_task(self._watch_runtime())
                         if runtime is not None and hasattr(runtime, "wait_unavailable") and not self.stopped else None)

    @staticmethod
    def is_retired(database: Path) -> bool:
        if not database.exists():
            return False
        with closing(sqlite3.connect(database)) as db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='control'").fetchone()
            return bool(exists and db.execute("SELECT 1 FROM control WHERE key='stopped'").fetchone())

    async def _watch_runtime(self):
        await self.host.wait_unavailable()
        await self.call("router_stop", {})

    async def _result_data(self, receipt):
        if not await self.host.verify(receipt):
            raise ValueError("unverified result")
        if receipt.execution_id.startswith("LOCAL-"):
            return {"text": (await self.host.read_result(receipt)).decode("utf-8")}
        outputs = []
        for art in receipt.artifacts:
            current = await self.host.artifact(art.output_name or art.artifact_id)
            with Path(current.final_ref).open("rb") as stream:
                data = stream.read(1048577)
            if len(data) > 1048576 or hashlib.sha256(data).hexdigest() != current.sha256:
                raise ValueError("result changed or too large")
            outputs.append({"artifact": asdict(current), "text": data.decode("utf-8")})
        return {"outputs": outputs}

    async def _retire(self):
        # Commit the submission barrier before cancellation or any slow cleanup.
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO control VALUES ('stopped')")
        self.stopped = True
        if self.db.execute("SELECT 1 FROM control WHERE key='cleaned'").fetchone():
            return True
        if self.host is None:
            return False
        try:
            for job in self.jobs.values():
                if not job.done():
                    job.cancel()
            if self.jobs:
                _, pending = await asyncio.wait(self.jobs.values(), timeout=CANCEL_WAIT_S)
                if pending:
                    raise TimeoutError("Router jobs did not stop")
                await asyncio.gather(*self.jobs.values(), return_exceptions=True)
            try:
                async with asyncio.timeout(SNAPSHOT_WAIT_S):
                    await self._capture_results()
            except TimeoutError:
                # Unsaved reservations remain UNKNOWN; never hold ports for a
                # stalled evidence provider or replay work to reconstruct it.
                pass
        finally:
            # Even failed evidence capture must attempt to release owned listeners.
            await self.host.stop_sandbox()
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO control VALUES ('cleaned')")
        return True

    async def _capture_results(self):
        rows = self.db.execute("SELECT DISTINCT action_id,fingerprint,canonical FROM submissions").fetchall()
        for aid, fp, canonical in rows:
            receipt = Receipt(canonical, fp, State.UNKNOWN, "EXECUTION_UNCONFIRMED")
            result = {}
            try:
                receipt = await self.host.status(canonical)
                if receipt.request_id != canonical or receipt.fingerprint != fp:
                    raise ValueError("receipt identity changed")
                if receipt.state in {State.ACCEPTED, State.RUNNING}:
                    receipt = replace(receipt, state=State.UNKNOWN, reason="EXECUTION_UNCONFIRMED")
                if receipt.state == State.SUCCEEDED:
                    if not receipt.execution_id or not receipt.evidence_ref:
                        raise ValueError("missing completion evidence")
                    result = await self._result_data(receipt)
            except Exception:
                receipt = Receipt(canonical, fp, State.UNKNOWN, "EXECUTION_UNCONFIRMED")
            snapshot = {"receipt": asdict(receipt), "result": result,
                        "task_id": self.actions[aid].task_id if aid in self.actions else None,
                        "progress": self.router.snapshot()}
            with self.db:
                self.db.execute("INSERT OR REPLACE INTO retired_results VALUES (?,?)",
                                (canonical, json.dumps(snapshot)))

    async def _stop(self):
        if self._retirement is None:
            self._retirement = asyncio.create_task(self._retire())
        try:
            cleaned = await asyncio.shield(self._retirement)
        except Exception:
            cleaned = False
        return {"ok": cleaned, "plan_id": self.plan_id, "stopped": cleaned,
                **({} if cleaned else {"error": "CLEANUP_UNCONFIRMED", "recommended_next_step": "router_status"})}

    def _retired_result(self, canonical):
        row = self.db.execute("SELECT value FROM retired_results WHERE canonical=?", (canonical,)).fetchone()
        return json.loads(row[0]) if row else None

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
                return await self._stop()
            if name == "router_plan":
                if self.stopped:
                    return {"ok": False, "error": "PLAN_STOPPED"}
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
                    if self.stopped:
                        cached = self._retired_result(row[3])
                        if not cached or not cached["result"]:
                            return {**result, "ok": False, "error": "RESULT_NOT_VERIFIED"}
                        for output in cached["result"].get("outputs", []):
                            art = output["artifact"]
                            try:
                                with Path(art["final_ref"]).open("rb") as stream:
                                    data = stream.read(1048577)
                                valid = art["status"] == "EXPORTED" and hashlib.sha256(data).hexdigest() == art["sha256"]
                            except OSError:
                                valid = False
                            if not valid:
                                return {**result, "ok": False, "error": "RESULT_NOT_VERIFIED"}
                        return {**result, **cached["result"]}
                    trusted = await self.host.status(row[3])
                    try:
                        result.update(await self._result_data(trusted))
                    except ValueError:
                        return {"ok": False, "error": "RESULT_NOT_VERIFIED"}
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
        if self.stopped:
            cached = self._retired_result(canonical)
            receipt = cached["receipt"] if cached else asdict(Receipt(canonical, fp, State.UNKNOWN, "EXECUTION_UNCONFIRMED"))
            return {"ok": True, "plan_id": self.plan_id, "action_id": aid,
                    "task_id": cached["task_id"] if cached else None,
                    "receipt": {**receipt, "request_id": rid},
                    "progress": cached["progress"] if cached else self.router.snapshot()}
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
        if self._closed:
            return
        if self._watcher is not None and self._watcher is not asyncio.current_task():
            self._watcher.cancel()
            await asyncio.gather(self._watcher, return_exceptions=True)
        try:
            async with self.lock:
                result = await self._stop()
                if not result["ok"]:
                    raise RuntimeError("Router cleanup unconfirmed")
        finally:
            try:
                if self.host is not None:
                    await self.host.close()
            finally:
                self.db.close()
                self._closed = True
