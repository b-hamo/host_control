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


@pytest.mark.parametrize('flag', ['allow_gui', 'auto_analyze_clipboard'])
def test_handoff_server_rejects_router_browser_config(tmp_path, flag):
    import json
    from host.router_workflow_server import WorkflowBackend
    cfg = dict(directory=str(tmp_path/'run'), origins=[], runner_exe=str(tmp_path/'runner.exe'),
               sandbox_root=str(tmp_path/'sandbox'), allow_execution=False, **{flag: True})
    path = tmp_path/'config.json'
    path.write_text(json.dumps(cfg))
    backend = WorkflowBackend(path)
    with pytest.raises(ValueError, match='In-app browser handoff'):
        asyncio.run(backend._main())
    assert backend.service is None


def test_real_stdio_hides_and_rejects_router_clipboard_and_gui(tmp_path):
    import json
    from pathlib import Path
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[1]
    cfg = dict(directory=str(tmp_path/'run'), origins=[], runner_exe=str(tmp_path/'runner.exe'),
               sandbox_root=str(tmp_path/'sandbox'), allow_execution=False, allow_external_capture=True)
    path = tmp_path/'config.json'
    path.write_text(json.dumps(cfg))
    messages = [
        dict(id=1, method='initialize', params=dict(protocolVersion='2025-06-18', capabilities={},
             clientInfo=dict(name='internal-browser-test',version='1'))),
        dict(id=2, method='tools/list', params={}),
    ]
    for number, name, args in [
        (3, 'router_clipboard_read', {'request_id':'clip'}),
        (4, 'router_gui', {'request_id':'gui','operation':'observe'}),
        (5, 'router_capture', {'request_id':'capture','source_url':'http://127.0.0.1:8787/',
                              'text':'Write-Output harmless'}),
    ]:
        messages.append(dict(id=number,method='tools/call',params=dict(name=name,arguments=args)))
    wire=''.join(json.dumps(dict(jsonrpc='2.0',**m))+'\n' for m in messages)
    proc=subprocess.run([sys.executable,str(root/'scripts/launch_router_workflow.py'),'--config',str(path)],
                        input=wire,capture_output=True,text=True,timeout=40)
    assert proc.returncode==0,proc.stderr
    responses={r['id']:r for r in map(json.loads,proc.stdout.splitlines())}
    names={t['name'] for t in responses[2]['result']['tools']}
    assert not {'router_clipboard_read','router_gui'} & names
    for number in (3,4):
        assert responses[number]['result']['isError']
    capture=json.loads(responses[5]['result']['content'][0]['text'])
    assert capture['ok'] and not capture['independently_verified']
    assert not list((tmp_path/'run').glob('*/private/execution'))


@pytest.mark.parametrize('stop_before_execute', [False, True])
def test_capture_and_execute_share_id_without_replaying(tmp_path, stop_before_execute):
    from unittest.mock import patch
    from test_router_workflow_connection import Runtime, completed
    async def run():
        c = WorkflowConnection(directory=tmp_path/'runs', origins=[],
            runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox',
            allow_external_capture=True, allow_execution=True)
        runtimes = []
        async def open_runtime(w, action):
            w.execution = Runtime(w.private)
            runtimes.append(w.execution)
            w.runtime_ready.set()
        cap = dict(request_id='shared', source_url='http://127.0.0.1:8787/', text='Write-Output harmless')
        try:
            got = await c.call('router_capture', cap)
            if stop_before_execute:
                assert (await c.call('router_stop', {}))['stopped']
            execute = dict(request_id='shared', source_id=got['source']['source_id'], form='powershell-script')
            with patch('host.router_workflow.RouterWorkflow.open_execution', open_runtime):
                assert (await c.call('router_execute', execute))['ok']
                result = await completed(c, 'shared')
                assert result['ok'] and result['receipt']['state'] == 'SUCCEEDED'
                assert 'receipt' in await c.call('router_status', {'request_id':'shared'})
                assert (await c.call('router_capture', cap))['source'] == got['source']
                assert (await c.call('router_execute', execute))['ok']
                assert (await c.call('router_execute', {**execute, 'source_id':'SRC-other'}))['error'] == 'IDEMPOTENCY_CONFLICT'
                assert (await c.call('router_capture', {**cap, 'text':'changed'}))['error'] == 'IDEMPOTENCY_CONFLICT'
                assert (await c.call('router_stop', {}))['stopped']
                assert (await c.call('router_execute', execute))['stopped']
                retained = await c.call('router_result', {'request_id':'shared'})
                assert [o['text'] for o in retained['outputs']] == [o['text'] for o in result['outputs']]
                assert retained['receipt']['fingerprint'] == result['receipt']['fingerprint']
                assert len(runtimes) == 1 and len(runtimes[0].submissions) == 1
        finally:
            await c.close()
    asyncio.run(run())
