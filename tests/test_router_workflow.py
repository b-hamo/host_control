"""Enforcement is code/config, never AGENTS.md or Agent trust claims."""
import asyncio
import json
from unittest.mock import patch

import pytest
from host.router_workflow import RouterWorkflow, script_from_source
from host.router_workflow_server import tool_list
from host.mcp_server import McpServer
from router.models import Location


def workflow(tmp_path, **kwargs):
    mail = tmp_path / 'mail'; mail.mkdir()
    (mail / 'one.eml').write_text('From: sender@example.test\nSubject: Interview\nContent-Type: text/plain; charset=utf-8\n\nSee https://example.test/portal', encoding='utf-8')
    return RouterWorkflow(directory=tmp_path/'run', mailbox=mail, origins=['https://example.test'],
                          runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox', **kwargs)


async def result(w, rid):
    await asyncio.gather(*w.service.jobs.values())
    return await w.call('router_result', {'request_id': rid})


def test_mail_is_routed_and_raw_gui_is_not_exposed(tmp_path):
    async def check():
        w = workflow(tmp_path)
        try:
            await w.call('router_read', {'request_id': 'read', 'uri': 'mailbox:one'})
            got = await result(w, 'read')
            assert got['ok'] and 'Interview' in got['text'] and got['source']['origin'] == 'external'
            assert got['receipt']['execution_id'].startswith('LOCAL-')
            for tool in ('computer_type', 'computer_hotkey', 'task_submit', 'sandbox_run', 'exec_command'):
                assert (await w.call(tool, {}))['error'] == 'TOOL_NOT_EXPOSED'
            assert w.execution is None
            assert w.service.router.snapshot()
        finally:
            await w.close()
    asyncio.run(check())


def test_mcp_cannot_invoke_hidden_tool_or_supply_location():
    from jsonschema import validate, ValidationError
    class Backend:
        def call(self, *args):
            raise AssertionError('must never dispatch')
    server = McpServer(Backend(), tool_list(), strict_tools=True)
    got = server.handle({'jsonrpc':'2.0','id':1,'method':'tools/call',
                         'params':{'name':'computer_type','arguments':{'text':'powershell'}}})
    assert got['result']['isError']
    schema = next(t['inputSchema'] for t in tool_list() if t['name']=='router_execute')
    with pytest.raises(ValidationError):
        validate({'request_id':'one','source_id':'SRC-one','form':'powershell-script','location':'LOCAL'}, schema)


def test_source_tamper_and_no_operator_grant_refused(tmp_path):
    async def check():
        w = workflow(tmp_path)
        try:
            src = w.source(b'Write-Output test', 'test')
            args = {'request_id':'run','source_id':src.source_id,'form':'powershell-script'}
            with pytest.raises(ValueError, match='disabled'):
                await w.call('router_execute', args)
            w.allow_execution = True
            w.paths[src.source_id].write_text('changed')
            with pytest.raises(ValueError, match='changed'):
                await w.call('router_execute', args)
            assert w.execution is None
        finally:
            await w.close()
    asyncio.run(check())


def test_execution_always_sandbox_and_failure_does_not_fallback(tmp_path):
    async def check():
        w = workflow(tmp_path, allow_execution=True)
        try:
            src = w.source(b'Write-Output test', 'test')
            with patch.object(w, 'open_execution', side_effect=RuntimeError('start failed')) as start, \
                 patch.object(w.local.local, 'run', side_effect=AssertionError('Host payload execution')):
                args = {'request_id':'run','source_id':src.source_id,'form':'powershell-script'}
                await w.call('router_execute', args)
                await asyncio.gather(*w.service.jobs.values(), return_exceptions=True)
                assert w.execution_action.location == Location.SANDBOX
                assert w.authority.check(w.execution_action) == 'ALLOW'
                assert (await w.call('router_result', {'request_id':'run'}))['ok'] is False
                await w.call('router_execute', args)
                assert start.call_count == 1
        finally:
            await w.close()
    asyncio.run(check())


def test_data_url_and_mail_path_escape_are_refused(tmp_path):
    async def check():
        w = workflow(tmp_path)
        try:
            for uri in ('file:///C:/Windows/win.ini','https://other.test/','mailbox:../secret'):
                with pytest.raises(ValueError):
                    w.read_sync(uri)
        finally:
            await w.close()
    asyncio.run(check())


def test_literal_parser_does_not_evaluate_dynamic_code():
    source = "const command = 'powershell.exe -NoProfile -NoExit -Command \"Write-Host \\'test\\'\"';"
    start, end = source.index("'"), source.rindex("'")+1
    body, transform = script_from_source(source, 'powershell-command-literal', start, end)
    assert body == "Write-Host 'test'"
    assert transform['interactive_noexit_removed']
    with pytest.raises(ValueError):
        script_from_source("'a' + execute()", 'powershell-command-literal', 0, 15)


def test_existing_sandbox_is_not_replaced(tmp_path):
    async def check():
        factory = __import__('unittest.mock', fromlist=['AsyncMock']).AsyncMock()
        w = workflow(tmp_path, allow_execution=True, runtime_factory=factory)
        try:
            src = w.source(b'Write-Output test', 'test')
            action = w.prepare_execution({'source_id':src.source_id,'form':'powershell-script'})
            w.grant(action)
            with patch('host.router_workflow.subprocess.run') as run:
                run.return_value.stdout = b'{"WindowsSandboxEnvironments":[{"Id":"user-session"}]}'
                with pytest.raises(ValueError, match='Existing Sandbox'):
                    await w.open_execution(action)
            factory.assert_not_called()
        finally:
            await w.close()
    asyncio.run(check())
