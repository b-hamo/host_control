import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from host.router_task_scope import load_task
from host.router_web_policy import WebPolicy, WebScopeError
from host.router_workflow_connection import WorkflowConnection


def test_user_urls_canonicalize_without_demo_or_wildcard(tmp_path):
    path = tmp_path/'task.json'
    path.write_text(json.dumps({'goal':'Play game', 'urls':['https://MINESWEEPER.online:443/game', 'https://minesweeper.online/']}))
    assert load_task(path)['origins'] == ['https://minesweeper.online']
    for urls in ([], ['https://*.example.org'], ['file:///secret'], ['https://user:secret@example.org']):
        path.write_text(json.dumps({'goal':'Task', 'urls':urls}))
        with pytest.raises(ValueError):
            load_task(path)


def test_denials_are_structured_and_redact_url_secrets():
    policy = WebPolicy(['https://minesweeper.online'])
    with pytest.raises(WebScopeError) as caught:
        policy.require('https://other.example/path?token=secret', 'navigate')
    assert caught.value.body['error'] == 'WEB_SCOPE_DENIED'
    assert caught.value.body['requested_origin'] == 'https://other.example'
    assert 'secret' not in json.dumps(caught.value.body)
    assert caught.value.body['allowed_origins'] == ['https://minesweeper.online']


def test_scope_changes_only_after_stop_and_invalid_navigation_never_submits(tmp_path):
    async def run():
        path = tmp_path/'task.json'
        def task(url):
            path.write_text(json.dumps({'goal':'User task', 'urls':[url]}))
        task('https://minesweeper.online')
        class Browser:
            def __init__(self, *args):
                self.close = AsyncMock()
        c = WorkflowConnection(directory=tmp_path/'run', task_file=str(path), origins=[],
            browsing_policy='web', allow_gui=True, browser_factory=Browser,
            runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox')
        try:
            with pytest.raises(WebScopeError):
                await c.call('router_gui', {'request_id':'denied', 'operation':'navigate', 'url':'https://other.example'})
            first = c.workflows[0]
            assert first.web_policy.scope == ('https://minesweeper.online',)
            assert not first.requests and not first.service.jobs
            task('https://other.example')
            with pytest.raises(WebScopeError):
                await c.call('router_read', {'request_id':'still-denied','uri':'https://other.example'})
            assert (await c.call('router_stop', {}))['stopped']
            with pytest.raises(WebScopeError):
                await c.call('router_gui', {'request_id':'new-scope', 'operation':'navigate','url':'https://minesweeper.online'})
            assert c.workflows[-1].web_policy.scope == ('https://other.example',)
            assert first.web_policy.scope == ('https://minesweeper.online',)
        finally:
            await c.close()
    asyncio.run(run())
