import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from host.router_authority import Authority
from host.router_workflow import RouterWorkflow
from host.router_workflow_connection import WorkflowConnection
from host.router_provisioning import load
from router import Scope, Artifact
from router.ports import Request, State
from test_router import SOURCE, execution, FakeSandbox, setup
from test_router_mcp import local_action, configuration


def test_only_task_grants_are_skipped():
    a = execution()
    authority = Authority(sources=(SOURCE,), verify_source=lambda s: True, task_checks=False)
    assert authority.check(a) == 'ALLOW'
    assert Authority().check(a) == 'DELEGATION_MISSING_OR_EXPIRED'
    with pytest.raises(ValueError, match='execution source missing'):
        replace(a, sources=())
    authority.verify_source = lambda s: False
    assert authority.check(a) == 'PROVENANCE_UNVERIFIED'
    with pytest.raises(ValueError):
        Authority(task_checks='false')


def test_gateway_keeps_sandbox_receipts_and_no_replay(setup):
    async def run():
        a = execution()
        sandbox = FakeSandbox()
        host = setup([a], sandbox=sandbox)
        host.authority.task_checks = False
        host.authority.delegations.clear()
        request = Request('one', a)
        assert (await host.submit(request)).state == State.SUCCEEDED
        assert (await host.submit(request)).state == State.SUCCEEDED
        assert sandbox.calls == 1
        sandbox.valid = False
        changed = replace(a, command=replace(a.command, argv=('-File', 'guest:/assignment.ps1', '-Different')))
        assert (await host.submit(Request('two', changed))).state != State.SUCCEEDED
    asyncio.run(run())


def test_local_file_boundary_survives_without_task_grants(setup, tmp_path):
    async def run():
        good = local_action(tmp_path)
        host = setup([good])
        host.authority.task_checks = False
        host.authority.delegations.clear()
        assert (await host.submit(Request('good', good))).state == State.SUCCEEDED
        outside = str(tmp_path.parent/'outside.txt')
        bad = replace(good, action_id='bad', locator=outside, scope=Scope(writes=(outside,)))
        assert (await host.submit(Request('bad', bad))).reason == 'LOCAL_SCOPE_INVALID'
        executable = str(tmp_path/'run.ps1')
        bad = replace(good, action_id='script', locator=executable, scope=Scope(writes=(executable,)))
        assert (await host.submit(Request('script', bad))).reason == 'LOCAL_SCOPE_INVALID'
    asyncio.run(run())


def test_host_profile_selects_mode_without_mcp_claims(tmp_path):
    import json
    path, doc, _, _ = configuration(tmp_path)
    doc['task_checks'] = False
    doc['delegations'] = []
    path.write_text(json.dumps(doc))
    assert load(path)['authority'].task_checks is False


def test_task_approval_skipped_but_unexported_artifact_stays_rejected(setup):
    async def run():
        a = execution(outputs=('stdout',))
        sandbox = FakeSandbox()
        with pytest.raises(ValueError, match='only EXPORTED'):
            Artifact('ART-1', 'PENDING', '', 'a'*64, (), 'stdout')
        sandbox.artifacts = ()  # A claimed success without the required export.
        approver = AsyncMock(return_value=False)
        host = setup([a], sandbox=sandbox, approval=True, approver=approver)
        host.authority.task_checks = False
        result = await host.submit(Request('unexported', a))
        assert sandbox.calls == 1
        assert result.state != State.SUCCEEDED
        approver.assert_not_awaited()
    asyncio.run(run())


def test_workflow_ignores_old_task_file_but_preserves_protocol_and_execution_gates(tmp_path):
    async def run():
        class Browser:
            def __init__(self, *args):
                self.close = AsyncMock()
        c = WorkflowConnection(directory=tmp_path/'run', task_file=str(tmp_path/'missing.json'),
            origins=['https://old.example'], task_checks=False, allow_gui=True,
            allow_execution=False, runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox',
            browser_factory=Browser)
        try:
            # Invalid operation creates the workflow without touching a browser.
            with pytest.raises(ValueError):
                await c.call('router_gui', {'request_id':'bad','operation':'unknown'})
            w = c.workflows[0]
            assert not w.authority.task_checks
            a = w.prepare_gui({'request_id':'nav','operation':'navigate','url':'http://127.0.0.1:8787/'})
            assert a.scope.network == ('http://*', 'https://*')
            with pytest.raises(ValueError):
                w.prepare_gui({'request_id':'file','operation':'navigate','url':'file:///C:/secret'})
            with pytest.raises(ValueError, match='disabled'):
                w.prepare_execution({'source_id':'missing'})
            assert (await c.call('router_stop', {}))['stopped']
        finally:
            await c.close()
    asyncio.run(run())
