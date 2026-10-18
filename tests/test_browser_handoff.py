import asyncio
from dataclasses import replace

import pytest

from host.router_workflow_connection import WorkflowConnection
from host.router_workflow_server import tool_list
from router.models import Location, Scope


def test_external_capture_lifecycle_and_execution_boundary(tmp_path):
    async def run():
        c = WorkflowConnection(directory=tmp_path/'runs', origins=[],
            runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox',
            allow_external_capture=True, allow_execution=False)
        args = dict(request_id='capture', source_url='http://127.0.0.1:8787/',
                    text='Write-Output harmless')
        try:
            got = await c.call('router_capture', args)
            assert not got['independently_verified']
            w = c.workflows[-1]
            assert w.browser is None and w.execution is None
            assert got['source']['origin'] == 'external'
            assert (await c.call('router_capture', args))['source'] == got['source']
            assert (await c.call('router_capture', {**args, 'text':'changed'}))['error'] == 'IDEMPOTENCY_CONFLICT'
            execute = dict(request_id='exec', source_id=got['source']['source_id'], form='powershell-script')
            with pytest.raises(ValueError, match='disabled'):
                await c.call('router_execute', execute)
            w.allow_execution = True
            action = w.prepare_execution(execute)
            assert action.location == Location.SANDBOX
            assert w.authority.check(action) == 'DELEGATION_MISSING_OR_EXPIRED'
            w.grant(action)
            assert w.authority.check(action) == 'ALLOW'
            for key, value in [('reads', ('C:\\Users\\private.txt',)),
                               ('writes', ('C:\\Windows\\escape',)),
                               ('network', ('https://upload.example',))]:
                changed = replace(action, scope=replace(action.scope, **{key: value}))
                assert w.authority.check(changed) == 'DELEGATION_SCOPE'
            w.paths[got['source']['source_id']].write_text('tampered')
            assert w.authority.check(action) == 'PROVENANCE_UNVERIFIED'
            assert (await c.call('router_stop', {}))['stopped']
            assert (await c.call('router_result', {'request_id':'capture'}))['stopped']
            await c.call('router_capture', {**args, 'request_id':'fresh'})
            assert len(c.workflows) == 2
        finally:
            await c.close()
    asyncio.run(run())


def test_capture_is_opt_in_and_rejects_paths_and_oversized_bytes(tmp_path):
    async def run():
        c = WorkflowConnection(directory=tmp_path/'runs', origins=[],
            runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox')
        args = dict(request_id='one', source_url='https://example.test', text='test')
        try:
            with pytest.raises(ValueError, match='disabled'):
                await c.call('router_capture', args)
            c.workflows[-1].allow_external_capture = True
            for fields in ({'source_url':'file:///C:/secret'}, {'text':'가'*30000},
                           {'host_path':'C:/secret'}, {'location':'LOCAL'}):
                with pytest.raises(ValueError):
                    await c.call('router_capture', {**args, **fields})
            assert not c.workflows[-1].requests
        finally:
            await c.close()
    asyncio.run(run())


def test_capture_schema_has_no_permission_or_host_path_fields():
    from jsonschema import validate, ValidationError
    schema = next(t['inputSchema'] for t in tool_list() if t['name']=='router_capture')
    args = dict(request_id='one', source_url='https://example.test', text='whoami')
    validate(args, schema)
    for key in ('delegation', 'host_path', 'location', 'allow_execution'):
        with pytest.raises(ValidationError):
            validate({**args, key: True}, schema)
