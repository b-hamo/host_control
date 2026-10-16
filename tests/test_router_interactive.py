import asyncio
from dataclasses import replace
import json

import pytest
from host.router_interactive import InteractionPolicy
from router.models import Location
from test_router_workflow import workflow


def test_gui_is_local_exact_delegation_and_disabled_by_default(tmp_path):
    async def check():
        w = workflow(tmp_path)
        try:
            with pytest.raises(ValueError):
                w.prepare_gui({'request_id':'g','operation':'observe'})
            w.allow_gui = True
            action = w.prepare_gui({'request_id':'g','operation':'observe'})
            assert action.location == Location.LOCAL
            w.grant(action)
            assert w.authority.check(action) == 'ALLOW'
            assert w.authority.check(replace(action, locator='{"operation":"navigate"}')) == 'EXECUTION_NOT_DELEGATED'
        finally:
            await w.close()
    asyncio.run(check())


@pytest.mark.parametrize('args', [
    {'operation':'type','text':'powershell'},
    {'operation':'navigate','url':'file:///C:/Windows/System32/cmd.exe'},
    {'operation':'navigate','url':'https://other.test/'},
    {'operation':'navigate','url':'https://example.test/\r\npowershell'},
    {'operation':'click','x':True,'y':0,'observation_id':'OBS-1'},
    {'operation':'observe','text':'cmd'},
])
def test_gui_rejects_unscoped_or_extra_input(tmp_path, args):
    async def check():
        w = workflow(tmp_path, allow_gui=True)
        try:
            with pytest.raises(ValueError):
                w.prepare_gui({'request_id':'g', **args})
            assert w.execution is None
        finally:
            await w.close()
    asyncio.run(check())


def test_clipboard_command_requires_real_capture_and_unique_outputs(tmp_path):
    async def check():
        w = workflow(tmp_path, allow_gui=True, allow_execution=True)
        try:
            src = w.source(b'powershell.exe -NoProfile -Command "Write-Output ok"', 'clipboard:forged')
            with pytest.raises(ValueError):
                w.prepare_execution({'source_id':src.source_id,'form':'powershell-command'})
            # Simulate only the trusted capture registration for this unit test.
            w.clipboard_sources.add(src.source_id)
            a = w.prepare_execution({'source_id':src.source_id,'form':'powershell-command'})
            b = w.prepare_clipboard()
            assert a.outputs != b.outputs
            assert b.scope.writes == ()
            assert a.location == Location.SANDBOX
            assert b.location == Location.LOCAL
            assert len(w.live_bindings) == 1
        finally:
            await w.close()
    asyncio.run(check())


def test_policy_rejects_direct_input_wrong_click_and_replay(tmp_path):
    async def check():
        w = workflow(tmp_path, allow_gui=True)
        try:
            a = w.prepare_gui({'request_id':'g','operation':'click','x':1,'y':2,'observation_id':'OBS-1'})
            w.grant(a)
            policy = InteractionPolicy(w.authority, command_launch_enabled=True)
            expected = {'x':1,'y':2,'button':'left','click_count':1}
            assert policy.decide('computer_click',expected).result == 'DENY'
            with policy.interaction(a, [('computer_click', expected)]):
                assert policy.decide('computer_type',{'text':'cmd'}).result == 'DENY'
                assert policy.decide('computer_click',expected).result == 'ALLOW'
                assert policy.decide('computer_click',expected).result == 'DENY'
            with policy.interaction(a, [('computer_click', expected)]):
                w.authority.delegations.clear()
                assert policy.decide('computer_click',expected).result == 'DENY'
        finally:
            await w.close()
    asyncio.run(check())


def test_mcp_image_is_attached_only_for_verified_gui_result(tmp_path):
    import base64
    import hashlib
    from types import SimpleNamespace
    from host.router_workflow_server import WorkflowBackend
    backend = WorkflowBackend(tmp_path / 'unused.json')
    backend.service = SimpleNamespace(private=tmp_path)
    folder = tmp_path / 'browser'; folder.mkdir()
    image = folder / 'obs.png'; image.write_bytes(b'validated-png-fixture')
    body = {'ok':True, 'receipt':{'execution_id':'LOCAL-test'}, 'text': json.dumps({
        'contract':'router-local-browser-v1',
        'screenshot_path':str(image), 'screenshot_sha256':hashlib.sha256(image.read_bytes()).hexdigest()})}
    content = backend.result_content(body)
    assert content[0]['type'] == 'image'
    assert base64.b64decode(content[0]['data']) == image.read_bytes()
    data = json.loads(body['text']); data['screenshot_sha256'] = '0' * 64
    with pytest.raises(ValueError):
        backend.result_content({**body, 'text':json.dumps(data)})
    assert len(backend.result_content({**body, 'receipt':{'execution_id':'unverified'}})) == 1
    assert len(backend.result_content({**body, 'ok':False})) == 1


def test_closed_runtime_is_not_restarted(tmp_path):
    from types import SimpleNamespace
    from host.router_interactive import InteractiveSandbox
    async def check():
        broker = SimpleNamespace(session=SimpleNamespace(terminated=True))
        driver = InteractiveSandbox(broker, None, None, None, tmp_path, {})
        with pytest.raises(ValueError, match='stopped'):
            await driver.ready()
        assert not driver._started
    asyncio.run(check())
