import asyncio
from unittest.mock import AsyncMock, patch
from urllib.request import Request

import pytest

from host.router_web_policy import WebPolicy
from host.router_local_browser import LocalBrowser
from host.router_workflow import RouterWorkflow, NoRedirect


@pytest.mark.parametrize('url', ['https://example.org/page?q=hello#section',
    'http://example.net/', 'https://cdn.example.org/script.js',
    'https://EXAMPLE.org:443/', 'https://[::1]:9443/', 'https://한글.example/'])
def test_general_web_accepts_non_demo_origins(url):
    assert WebPolicy([], 'web').allowed(url)


@pytest.mark.parametrize('url', ['file:///C:/Windows/cmd.exe', 'javascript:alert(1)',
    'data:text/html,hello', 'ms-appinstaller:https://example.org/a',
    'https://user:pass@example.org/', 'https://@example.org/',
    'https://example.org:99999/', 'https://example.org\\@evil.test/',
    'https://example.org/\npowershell', 'https:///missing-host'])
def test_general_web_denies_non_web_and_ambiguous_urls(url):
    assert not WebPolicy([], 'web').allowed(url)


def test_scoped_default_remains_restricted_and_invalid_mode_fails():
    policy = WebPolicy(['https://example.org'])
    assert policy.allowed('https://EXAMPLE.org:443/a')
    assert not policy.allowed('https://other.org/')
    assert not policy.allowed('http://example.org/')
    with pytest.raises(ValueError):
        WebPolicy([], 'anything')


def test_redirects_check_each_target():
    handler = NoRedirect(WebPolicy([], 'web'))
    request = Request('https://example.org')
    redirected = handler.redirect_request(request, None, 302, 'Found', {}, 'https://other.org/page')
    assert redirected.full_url == 'https://other.org/page'
    with pytest.raises(ValueError):
        handler.redirect_request(request, None, 302, 'Found', {}, 'file:///C:/Windows/win.ini')
    with pytest.raises(ValueError):
        NoRedirect(WebPolicy(['https://example.org'])).redirect_request(
            request, None, 302, 'Found', {}, 'https://other.org/')


def test_cross_origin_resources_follow_general_policy(tmp_path):
    async def check():
        browser = LocalBrowser(tmp_path/'browser', [])
        browser.policy = WebPolicy([], 'web')
        browser.command = AsyncMock()
        for url, expected in [('https://cdn.example.org/a.js', 'Fetch.continueRequest'),
                              ('file:///secret', 'Fetch.failRequest')]:
            await browser.event({'method':'Fetch.requestPaused', 'sessionId':'owned',
                'params':{'requestId':'r', 'request':{'url':url}}})
            assert browser.command.call_args.args[0] == expected
    asyncio.run(check())


def test_non_demo_click_automatically_submits_sandbox_command(tmp_path):
    class Browser:
        def __init__(self, *args):
            self.close = AsyncMock()
            self.run = AsyncMock(return_value={'clipboard_changed':True})
        def read_clipboard(self):
            return {'sequence':123, 'text':'powershell -Command "Write-Output harmless"',
                    'source_url':'https://unlisted.example/captcha', 'after_observation':'OBS-1'}
    async def check():
        w = RouterWorkflow(directory=tmp_path/'run', origins=[], browsing_policy='web',
            runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox',
            allow_gui=True, allow_execution=True, auto_analyze_clipboard=True, browser_factory=Browser)
        try:
            nav = w.prepare_gui({'request_id':'nav', 'operation':'navigate', 'url':'https://unlisted.example'})
            assert nav.scope.network == ('http://*', 'https://*')
            with patch.object(w, 'open_execution', side_effect=RuntimeError('Test runtime unavailable')) as opened:
                await w.call('router_gui', {'request_id':'click', 'operation':'click', 'x':1, 'y':1, 'observation_id':'OBS-1'})
                await asyncio.gather(*list(w.service.jobs.values()))
                await asyncio.gather(*list(w.followups))
                assert opened.call_count == 1
                assert w.execution_action.location.value == 'SANDBOX'
                assert next(iter(w.clipboard_sources)) in w.authority.sources
                assert len([r for r in w.requests if r.startswith('AUTO-')]) == 1
        finally:
            await w.close()
    asyncio.run(check())


def test_page_changed_since_observation_never_receives_click(tmp_path):
    async def check():
        b = LocalBrowser(tmp_path/'browser', [], clipboard=lambda: {'sequence':1, 'text':''})
        b.policy = WebPolicy([], 'web')
        b.start = AsyncMock()
        b.observation, b.url = 'OBS-1', 'https://first.example/'
        b.command = AsyncMock(return_value={'frameTree':{'frame':{'url':'https://second.example/'}}})
        with pytest.raises(ValueError, match='Page changed'):
            await b.run({'operation':'click', 'x':1, 'y':1, 'observation_id':'OBS-1'})
        assert [c.args[0] for c in b.command.call_args_list] == ['Page.getFrameTree']
    asyncio.run(check())
