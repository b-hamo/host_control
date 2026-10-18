import asyncio
import base64
import json
from unittest.mock import AsyncMock, patch

import pytest
from host.router_local_browser import LocalBrowser
from host.router_command_intake import decode_powershell
from host.router_workflow import RouterWorkflow
from test_router_workflow import workflow, result


def test_web_workflow_needs_no_mail_adapter(tmp_path):
    async def check():
        w = RouterWorkflow(directory=tmp_path/'run', origins=['https://example.test'],
            runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox')
        try:
            assert w.mailbox is None
            with pytest.raises(ValueError, match='not configured'):
                w.read_sync('mailbox:')
        finally:
            await w.close()
    asyncio.run(check())


@pytest.mark.parametrize('url', ['file:///C:/Windows/cmd.exe', 'javascript:alert(1)',
    'ms-appinstaller:https://example.test/a', 'https://example.test.evil/a',
    'https://user@example.test/', 'http://example.test/'])
def test_non_scoped_navigation_blocked(tmp_path, url):
    b = LocalBrowser(tmp_path/'browser', ['https://example.test'])
    assert not b.allowed(url)


def test_redirect_is_checked_before_network_request(tmp_path):
    async def check():
        b = LocalBrowser(tmp_path/'browser', ['https://example.test'])
        b.command = AsyncMock()
        await b.event({'method':'Fetch.requestPaused', 'sessionId':'owned',
            'params':{'requestId':'redirect', 'request':{'url':'https://other.test/'}}})
        assert b.command.call_args.args[0] == 'Fetch.failRequest'
    asyncio.run(check())


def test_clipboard_requires_click_and_unchanged_sequence(tmp_path):
    current = {'sequence':1, 'text':'powershell -Command "hi"'}
    b = LocalBrowser(tmp_path/'browser', [], clipboard=lambda: dict(current))
    with pytest.raises(ValueError):
        b.read_clipboard()
    b.captured = {**current, 'source_url':'https://example.test/', 'after_observation':'OBS-1'}
    assert b.read_clipboard()['text'] == current['text']
    current['sequence'] += 1
    with pytest.raises(ValueError):
        b.read_clipboard()


def test_stale_click_never_dispatches_input(tmp_path):
    async def check():
        b = LocalBrowser(tmp_path/'browser', [])
        b.start = AsyncMock()
        b.command = AsyncMock()
        b.observation = 'OBS-current'
        with pytest.raises(ValueError, match='Fresh'):
            await b.run({'operation':'click', 'x':1, 'y':1, 'observation_id':'OBS-old'})
        b.command.assert_not_called()
    asyncio.run(check())


@pytest.mark.parametrize('command', ['cmd /c whoami', 'powershell -File evil.ps1',
    'powershell -EncodedCommand !', 'powershell -Command "ok" && calc.exe',
    'powershell -ExecutionPolicy Bypass -Command "hi"'])
def test_unknown_command_is_held_without_host_evaluation(command):
    with pytest.raises((ValueError, UnicodeError)):
        decode_powershell(command)


def test_encoded_and_plain_script_preserve_content():
    script = "Write-Output ('a' + 'b')"
    encoded = base64.b64encode(script.encode('utf-16-le')).decode()
    assert decode_powershell('PowerShell.exe -NonInteractive -EncodedCommand '+encoded)[0] == script
    body, transform = decode_powershell('powershell -NoExit -NoProfile -Command "'+script+'"')
    assert body == script and transform['interactive_noexit_removed']


def test_local_click_clipboard_and_sandbox_dispatch_without_agents_file(tmp_path):
    class Browser:
        def __init__(self, *args):
            self.run = AsyncMock(return_value={'contract':'router-local-browser-v1', 'location':'LOCAL'})
            self.close = AsyncMock()
        def read_clipboard(self):
            return {'sequence':123, 'text':'powershell -Command "Write-Output ok"',
                'source_url':'https://example.test/', 'after_observation':'OBS-1'}
    async def check():
        w = workflow(tmp_path, allow_gui=True, allow_execution=True, browser_factory=Browser)
        try:
            await w.call('router_gui', {'request_id':'view', 'operation':'observe'})
            assert (await result(w, 'view'))['receipt']['execution_id'].startswith('LOCAL-')
            await w.call('router_clipboard_read', {'request_id':'clip'})
            captured = await result(w, 'clip')
            assert captured['source']['origin'] == 'external'
            assert w.execution is None and w.execution_identity is None
            with patch.object(w, 'open_execution', side_effect=RuntimeError('Unavailable')) as start:
                await w.call('router_execute', {'request_id':'run', 'source_id':captured['source']['source_id'],
                    'form':'powershell-command'})
                await asyncio.gather(*w.service.jobs.values(), return_exceptions=True)
                assert w.execution_action.location.value == 'SANDBOX'
                assert start.call_count == 1
                assert w.browser.run.await_count == 1
                assert not (await result(w, 'run'))['ok']
        finally:
            await w.close()
    asyncio.run(check())


def test_operator_auto_analysis_does_not_require_agent_execute_call(tmp_path):
    class Browser:
        def __init__(self, *args):
            self.close = AsyncMock()
        def read_clipboard(self):
            return {'sequence':9, 'text':'powershell -Command "Write-Output ok"',
                'source_url':'https://example.test', 'after_observation':'OBS-1'}
    async def check():
        w = workflow(tmp_path, allow_gui=True, allow_execution=True,
            auto_analyze_clipboard=True, browser_factory=Browser)
        try:
            with patch.object(w, 'open_execution', side_effect=RuntimeError('Unavailable')) as start:
                await w.call('router_clipboard_read', {'request_id':'first'})
                got = await result(w, 'first')
                analysis = got['analysis']
                assert analysis['request_id'].startswith('AUTO-')
                await asyncio.gather(*w.service.jobs.values(), return_exceptions=True)
                await w.call('router_clipboard_read', {'request_id':'second'})
                again = await result(w, 'second')
                assert again['analysis'] == analysis
                assert start.call_count == 1
                assert w.execution_action.location.value == 'SANDBOX'
        finally:
            await w.close()
    asyncio.run(check())


def test_click_starts_analysis_without_any_result_or_clipboard_call(tmp_path):
    class Browser:
        def __init__(self, *args):
            self.close = AsyncMock()
            self.run = AsyncMock(return_value={'clipboard_changed':True})
        def read_clipboard(self):
            return {'sequence':11, 'text':'powershell -Command "Write-Output ok"',
                'source_url':'https://example.test', 'after_observation':'OBS-1'}
    async def check():
        w = workflow(tmp_path, allow_gui=True, allow_execution=True,
            auto_analyze_clipboard=True, browser_factory=Browser)
        try:
            with patch.object(w, 'open_execution', side_effect=RuntimeError('Unavailable')) as start:
                args = {'request_id':'click', 'operation':'click', 'x':1, 'y':1, 'observation_id':'OBS-1'}
                await w.call('router_gui', args)
                await asyncio.gather(*list(w.service.jobs.values()))
                await asyncio.gather(*list(w.followups))
                await asyncio.gather(*list(w.service.jobs.values()), return_exceptions=True)
                assert start.call_count == 1
                assert w.execution_action.location.value == 'SANDBOX'
                state = next(iter(w.click_analyses.values()))
                assert state['request_id'].startswith('AUTO-')
                await w.call('router_gui', args)
                assert start.call_count == 1
        finally:
            await w.close()
    asyncio.run(check())


def test_clipboard_change_between_click_and_capture_never_executes(tmp_path):
    class Browser:
        def __init__(self, *args):
            self.close = AsyncMock()
            self.run = AsyncMock(return_value={'clipboard_changed':True})
        def read_clipboard(self):
            raise ValueError('Clipboard changed')
    async def check():
        w = workflow(tmp_path, allow_gui=True, allow_execution=True,
            auto_analyze_clipboard=True, browser_factory=Browser)
        try:
            with patch.object(w, 'open_execution') as start:
                await w.call('router_gui', {'request_id':'click', 'operation':'click',
                    'x':1, 'y':1, 'observation_id':'OBS-1'})
                await asyncio.gather(*list(w.service.jobs.values()))
                await asyncio.gather(*list(w.followups))
                assert next(iter(w.click_analyses.values()))['state'] == 'HELD'
                start.assert_not_called()
        finally:
            await w.close()
    asyncio.run(check())
