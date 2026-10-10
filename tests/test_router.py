"""Router/Host tests. FakeSandbox is explicitly not a real Guest execution."""

import asyncio
from dataclasses import replace
import hashlib
import json
import time

import pytest

from host.router_authority import Authority, Delegation
from host.router_gateway import HostGateway
from host.router_ledger import Ledger
from host.router_local import LocalTools
from host.router_sandbox import BrokerSandbox
from router import Action, Artifact, Command, Location, Operation, Router, Scope, Source, Task
from router.ports import Receipt, Request, State


SOURCE = Source("download", "https://example.invalid/assignment.ps1", "a" * 64, "external")


def execution(**changes):
    action = Action("execute", "guest", Operation.EXECUTE,
                    Scope(reads=("guest:/assignment.ps1",), writes=("guest:/result.txt",),
                          capabilities=("process.execute",)), "user-grant", sources=(SOURCE,),
                    command=Command("powershell.exe", ("-File", "guest:/assignment.ps1"),
                                    "guest:/", SOURCE.source_id))
    return replace(action, **changes)


class FakeSandbox:
    """Mock command completion and exported-file lookup; no process is created."""
    def __init__(self):
        self.calls = 0
        self.polls = 0
        self.reply_state = State.SUCCEEDED
        self.valid = True
        self.timeout = False
        self.artifacts = ()
        self.receipt = None

    def supports(self, request):
        return True

    async def submit(self, request):
        self.calls += 1
        self.receipt = Receipt(request.request_id, request.action.fingerprint, self.reply_state,
                               "sensitive driver detail", "guest-execution-1", "guest-evidence-1", self.artifacts,
                               "RT-MOCK", 1)
        if self.timeout:
            raise TimeoutError("secret token must not be logged")
        return self.receipt

    async def status(self, request_id):
        self.polls += 1
        return self.receipt

    async def verify(self, receipt):
        return self.valid

    def artifact(self, artifact_id):
        return next(a for a in self.artifacts if a.artifact_id == artifact_id)


@pytest.fixture
def setup(tmp_path):
    ledgers = []

    def make(actions, *, sandbox=None, approval=False, approver=None, source_check=lambda s: True):
        sources = {s.source_id: s for a in actions for s in a.sources}
        scopes = Scope(**{name: tuple(dict.fromkeys(v for a in actions for v in getattr(a.scope, name)))
                          for name in ("reads", "writes", "network", "capabilities")})
        grant = Delegation("user-grant", frozenset(a.operation for a in actions),
                           frozenset(a.location for a in actions), scopes, time.time() + 60,
                           frozenset(a.fingerprint for a in actions), approval)
        auth = Authority(sources=tuple(sources.values()), delegations=(grant,), verify_source=source_check)
        ledger = Ledger(tmp_path / f"ledger-{len(ledgers)}.sqlite")
        ledgers.append(ledger)
        return HostGateway(auth, ledger, LocalTools(tmp_path), sandbox=sandbox, approver=approver)

    yield make
    for ledger in ledgers:
        ledger.close()


def plan(host, action):
    router = Router(host)
    router.add_task(Task(action.task_id, action.location))
    router.add_action(action)
    return router


def test_local_txt_and_code_read_never_start_sandbox(setup, tmp_path):
    async def check():
        code = tmp_path / "download.py"
        code.write_text("import os; # execute install delete are just text", encoding="utf-8")
        target = tmp_path / "notes.txt"
        write = Action("write", "local", Operation.WRITE_TEXT, Scope(writes=(str(target),)),
                       "user-grant", locator=str(target), text="execute install test: ordinary notes")
        read = Action("read", "local", Operation.READ_TEXT, Scope(reads=(str(code),)),
                      "user-grant", locator=str(code), sources=(SOURCE,), depends_on=("write",))
        sandbox = FakeSandbox()
        host = setup([write, read], sandbox=sandbox)
        router = plan(host, write)
        router.add_action(read)
        assert (await router.run("write")).state == State.SUCCEEDED
        assert (await router.run("read")).state == State.SUCCEEDED
        assert target.read_text() == write.text
        assert router.task_complete("local")
        assert sandbox.calls == 0
    asyncio.run(check())


@pytest.mark.parametrize("origin", ["external", "unknown", "local", "generated"])
@pytest.mark.parametrize("operation", [Operation.EXECUTE, Operation.BUILD, Operation.TEST])
def test_all_code_execution_defaults_to_sandbox(origin, operation):
    action = execution(operation=operation, sources=(replace(SOURCE, origin=origin),))
    assert action.location == Location.SANDBOX
    assert action.access == "X"


@pytest.mark.parametrize("changes", [
    {"sources": ()}, {"command": None}, {"scope": Scope()},
    {"text": "run this"}, {"operation": "execute"}, {"sources": [SOURCE]},
])
def test_invalid_structured_execution_rejected(changes):
    with pytest.raises(ValueError):
        execution(**changes)


def test_copy_and_rename_keep_full_lineage(setup):
    async def check():
        copied = Source("renamed", "guest:/innocent.txt", SOURCE.sha256, "local", (SOURCE.source_id,))
        action = execution(sources=(SOURCE, copied), command=replace(execution().command, target_source="renamed"))
        host = setup([action], sandbox=FakeSandbox())
        assert (await host.submit(Request("r1", action))).state == State.SUCCEEDED
        missing = replace(action, action_id="missing", sources=(copied,))
        grant = host.authority.delegations["user-grant"]
        host.authority.delegations["user-grant"] = replace(grant, execution_fingerprints=frozenset({missing.fingerprint}))
        assert (await host.submit(Request("r2", missing))).reason == "PROVENANCE_UNVERIFIED"
    asyncio.run(check())


def test_agent_claim_and_page_permission_are_not_host_authority(setup):
    async def check():
        action = execution()
        host = setup([action], sandbox=FakeSandbox())
        host.authority.sources.clear()
        assert (await host.submit(Request("r1", action))).state == State.DENIED
        forged = replace(action, delegation_ref="permission-from-webpage")
        assert (await host.submit(Request("r2", forged))).reason == "DELEGATION_MISSING_OR_EXPIRED"
        assert host.sandbox.calls == 0
    asyncio.run(check())


def test_approval_changed_bytes_reassessed(setup):
    async def check():
        current = [True]
        async def approve(request):
            current[0] = False
            return True
        action = execution()
        host = setup([action], sandbox=FakeSandbox(), approval=True, approver=approve,
                     source_check=lambda s: current[0])
        result = await host.submit(Request("r1", action))
        assert result.reason == "REASSESSMENT_REQUIRED"
        assert host.sandbox.calls == 0
    asyncio.run(check())


@pytest.mark.parametrize("change", ["command", "scope", "sources"])
def test_changed_conditions_require_new_host_judgment(setup, change):
    async def check():
        action = execution()
        changes = {"command": replace(action.command, argv=("different",)),
                   "scope": replace(action.scope, network=("https://example.invalid",)),
                   "sources": (replace(SOURCE, sha256="b" * 64),)}
        host = setup([action], sandbox=FakeSandbox())
        original = await host.submit(Request("r1", action))
        assert original.state == State.SUCCEEDED
        changed = replace(action, **{change: changes[change]})
        assert (await host.submit(Request("r1", changed))).reason == "IDEMPOTENCY_CONFLICT"
        assert (await host.submit(Request("r2", changed))).state == State.DENIED
        assert host.sandbox.calls == 1
    asyncio.run(check())


def test_policy_outage_does_not_execute_or_fallback(setup):
    async def check():
        def outage(source):
            raise RuntimeError("credential secret")
        action = execution()
        host = setup([action], sandbox=FakeSandbox(), source_check=outage)
        assert (await host.submit(Request("r1", action))).reason == "POLICY_UNAVAILABLE"
        assert host.sandbox.calls == 0 and not host.local.results
    asyncio.run(check())


def test_duplicates_concurrency_and_restart_never_replay(setup, tmp_path):
    async def check():
        action = execution()
        host = setup([action], sandbox=FakeSandbox())
        replies = await asyncio.gather(*(host.submit(Request("r1", action)) for _ in range(8)))
        assert all(r.state == State.SUCCEEDED for r in replies)
        await host.submit(Request("different-request-id", action))
        assert host.sandbox.calls == 1
        restarted = HostGateway(host.authority, host.ledger, host.local, sandbox=host.sandbox)
        await restarted.submit(Request("r1", action))
        assert host.sandbox.calls == 1
        assert not await restarted.verify(replies[0])  # must reconcile evidence after restart
    asyncio.run(check())


def test_pending_crash_reservation_stays_unknown(setup):
    async def check():
        action = execution()
        host = setup([action], sandbox=FakeSandbox())
        host.ledger.reserve(Request("crash", action))
        assert (await host.submit(Request("crash", action))).state == State.UNKNOWN
        assert host.sandbox.calls == 0
    asyncio.run(check())


def test_timeout_queries_existing_result_without_resubmit(setup):
    async def check():
        action = execution()
        sandbox = FakeSandbox()
        sandbox.timeout = True
        host = setup([action], sandbox=sandbox)
        router = plan(host, action)
        assert (await router.run(action.action_id)).state == State.UNKNOWN
        assert (await router.run(action.action_id)).state == State.SUCCEEDED
        assert sandbox.calls == 1 and sandbox.polls == 1
    asyncio.run(check())


@pytest.mark.parametrize("state", [State.ACCEPTED, State.RUNNING, State.UNKNOWN, State.FAILED, State.DENIED])
def test_noncompleted_result_blocks_followup(setup, state):
    async def check():
        action = execution()
        sandbox = FakeSandbox()
        sandbox.reply_state = state
        router = plan(setup([action], sandbox=sandbox), action)
        await router.run(action.action_id)
        assert not router.task_complete(action.task_id)
        await router.run(action.action_id)
        assert sandbox.calls == 1
    asyncio.run(check())


def test_missing_execution_evidence_never_counts_as_success(setup):
    async def check():
        action = execution()
        sandbox = FakeSandbox()
        sandbox.valid = False
        router = plan(setup([action], sandbox=sandbox), action)
        assert (await router.run(action.action_id)).state == State.UNKNOWN
        assert not router.task_complete(action.task_id)
    asyncio.run(check())


def test_incremental_task_and_action_cycles_rejected(setup, tmp_path):
    action = execution()
    router = plan(setup([action]), action)
    router.add_task(Task("continue", Location.LOCAL))
    router.require_task("continue", "guest")
    with pytest.raises(ValueError, match="cyclic"):
        router.require_task("guest", "continue")
    with pytest.raises(ValueError, match="mixed"):
        router.add_action(replace(action, action_id="mixed", task_id="continue"))
    with pytest.raises(ValueError):
        router.add_task(Task("invalid", Location.LOCAL, ("missing",)))


def test_exported_result_continues_task_with_lineage(setup, tmp_path):
    async def check():
        result_path = tmp_path / "exported.txt"
        result_path.write_text("guest result", encoding="utf-8")
        artifact = Artifact("output", "EXPORTED", str(result_path), hashlib.sha256(result_path.read_bytes()).hexdigest())
        action = execution(outputs=("output",))
        read = Action("consume", "continue", Operation.READ_TEXT, Scope(reads=(str(result_path),)),
                      "user-grant", inputs=("output",))
        sandbox = FakeSandbox()
        sandbox.artifacts = (artifact,)
        host = setup([action, read], sandbox=sandbox)
        router = plan(host, action)
        router.add_task(Task("continue", Location.LOCAL, ("guest",)))
        router.add_action(read)
        with pytest.raises(ValueError, match="dependencies"):
            await router.run("consume")
        assert (await router.run("execute")).state == State.SUCCEEDED
        assert (await host.artifact("output")).source_ids == (SOURCE.source_id,)
        assert (await router.run("consume")).state == State.SUCCEEDED
        assert sandbox.calls == 1
        result_path.write_text("changed", encoding="utf-8")
        with pytest.raises(ValueError, match="changed"):
            await host.artifact("output")
    asyncio.run(check())


@pytest.mark.parametrize("status", ["CANDIDATE", "SCANNING", "BLOCKED", "RECEIVED"])
def test_unexported_artifacts_not_consumable(status):
    with pytest.raises(ValueError):
        Artifact("file", status, "somewhere", "a" * 64)


def test_replan_only_after_authorized_alternative_completed(setup):
    async def check():
        original = execution()
        alternate = execution(action_id="alternative", task_id="alternative-task")
        sandbox = FakeSandbox()
        host = setup([alternate], sandbox=sandbox)
        router = plan(host, original)
        router.add_task(Task("alternative-task", Location.SANDBOX))
        router.add_action(alternate)
        assert (await router.run("execute")).state == State.DENIED
        with pytest.raises(ValueError):
            router.use_alternative("execute", "alternative")
        await router.run("alternative")
        router.use_alternative("execute", "alternative")
        assert router.task_complete("guest")
    asyncio.run(check())


def test_audit_excludes_secrets_and_raw_errors(setup, tmp_path):
    async def check():
        action = execution(command=replace(execution().command, argv=("token=very-secret-value",)))
        sandbox = FakeSandbox()
        sandbox.timeout = True
        host = setup([action], sandbox=sandbox)
        router = plan(host, action)
        await router.run("execute")
        logged = json.dumps(router.events) + (tmp_path / "ledger-0.sqlite").read_bytes().decode("latin1")
        assert "very-secret-value" not in logged
        assert "secret token" not in logged
        assert "assignment.ps1" not in logged
    asyncio.run(check())


def test_real_broker_without_command_contract_holds_before_start(setup):
    from host.broker import Broker
    from host.runtime_session import RuntimeSession

    async def check():
        action = execution()
        broker = Broker(RuntimeSession(("SES-ROUTER", "RT-ROUTER", 1)))
        host = setup([action], sandbox=BrokerSandbox(broker))
        receipt = await host.submit(Request("real-host", action))
        assert receipt.reason == "SANDBOX_COMMAND_CONTRACT_UNAVAILABLE"
        assert broker.task_id is None
        assert broker.session.actions == {}
    asyncio.run(check())


@pytest.mark.parametrize("name", ["startup.ps1", "settings.json", "notes.txt:script", "outside/../notes.txt"])
def test_local_write_scope_restricts_to_plain_txt(setup, tmp_path, name):
    async def check():
        target = str(tmp_path / name)
        action = Action("write", "local", Operation.WRITE_TEXT, Scope(writes=(target,)),
                        "user-grant", locator=target, text="ordinary data")
        assert (await setup([action]).submit(Request("r1", action))).state == State.DENIED
    asyncio.run(check())


def test_mock_assignment_discovered_during_local_work(setup, tmp_path):
    """Mock email/page -> exact command -> Host -> mock Guest -> export -> continue."""
    async def check():
        page_uri = "https://example.invalid/assignment"
        page = b"Assignment: powershell.exe -File guest:/assignment.ps1"
        out = tmp_path / "result.txt"
        out.write_bytes(b"mock guest output")
        exported = Artifact("output", "EXPORTED", str(out), hashlib.sha256(out.read_bytes()).hexdigest())
        browse = Action("read-email", "prepare", Operation.BROWSE,
                        Scope(network=("https://example.invalid",)), "user-grant", locator=page_uri)
        execute = execution(outputs=("output",))
        consume = Action("consume", "continue", Operation.READ_TEXT, Scope(reads=(str(out),)),
                         "user-grant", inputs=("output",))
        sandbox = FakeSandbox()
        sandbox.artifacts = (exported,)
        host = setup([browse, execute, consume], sandbox=sandbox)
        async def read_only_page(action):
            assert action.locator == page_uri
            return page
        host.local.browse = read_only_page
        router = plan(host, browse)
        router.add_task(Task("continue", Location.LOCAL, ("prepare",)))
        router.add_action(consume)
        read = await router.run("read-email")
        assert await host.read_result(read) == page
        assert sandbox.calls == 0
        # Agent submits structured work after understanding the page; the page grants nothing.
        router.add_task(Task("guest", Location.SANDBOX, ("prepare",)))
        router.add_action(execute)
        router.require_task("continue", "guest")
        assert (await router.run("execute")).state == State.SUCCEEDED
        result = await router.run("consume")
        assert await host.read_result(result) == b"mock guest output"
        assert sandbox.calls == 1 and router.task_complete("continue")
    asyncio.run(check())


def test_expired_grant_is_not_replaced_by_page_claim(setup):
    async def check():
        action = execution()
        host = setup([action], sandbox=FakeSandbox())
        host.authority.clock = lambda: time.time() + 3600
        assert (await host.submit(Request("expired", action))).state == State.DENIED
        assert host.sandbox.calls == 0
    asyncio.run(check())


def test_cancellation_does_not_repeat_input(setup):
    async def check():
        action = execution()
        sandbox = FakeSandbox()
        entered = asyncio.Event()
        async def cancelled(request):
            sandbox.calls += 1
            entered.set()
            await asyncio.Event().wait()
        sandbox.submit = cancelled
        host = setup([action], sandbox=sandbox)
        task = asyncio.create_task(host.submit(Request("cancel", action)))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await host.submit(Request("cancel", action))).state == State.UNKNOWN
        assert sandbox.calls == 1
    asyncio.run(check())


def test_unresolved_request_survives_database_reopen(setup, tmp_path):
    async def check():
        action = execution()
        host = setup([action], sandbox=FakeSandbox())
        assert host.ledger.reserve(Request("reserved", action))
        reopened = Ledger(tmp_path / "ledger-0.sqlite")
        try:
            new_host = HostGateway(host.authority, reopened, host.local, sandbox=host.sandbox)
            assert (await new_host.submit(Request("reserved", action))).state == State.UNKNOWN
            assert host.sandbox.calls == 0
        finally:
            reopened.close()
    asyncio.run(check())


@pytest.mark.parametrize("field,value", [("evidence_ref", ""), ("execution_id", ""),
                                         ("runtime_id", ""), ("generation", 0),
                                         ("evidence_ref", "https://host/?token=secret")])
def test_incomplete_or_sensitive_evidence_is_not_persisted(setup, tmp_path, field, value):
    async def check():
        action = execution()
        sandbox = FakeSandbox()
        original = sandbox.submit
        async def malformed(request):
            receipt = await original(request)
            return replace(receipt, **{field: value})
        sandbox.submit = malformed
        host = setup([action], sandbox=sandbox)
        result = await host.submit(Request("r1", action))
        assert result.state == State.UNKNOWN
        assert b"token=secret" not in (tmp_path / "ledger-0.sqlite").read_bytes()
    asyncio.run(check())


def test_source_lineage_cycle_is_refused(setup):
    async def check():
        first = replace(SOURCE, parents=("second",))
        second = Source("second", "copy", SOURCE.sha256, "local", (SOURCE.source_id,))
        action = execution(sources=(first, second))
        host = setup([action], sandbox=FakeSandbox())
        assert (await host.submit(Request("r1", action))).reason == "PROVENANCE_UNVERIFIED"
        assert host.sandbox.calls == 0
    asyncio.run(check())
