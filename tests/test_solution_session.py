import io
import json
import queue
from types import SimpleNamespace

import pytest

from host.solution_session import Client


def client():
    value = Client.__new__(Client)
    value.seq = 0
    value.process = SimpleNamespace(stdin=io.StringIO())
    value.responses = queue.Queue()
    return value


def test_rpc_ignores_notifications_and_matches_response_id():
    c = client()
    c.responses.put({'method': 'notifications/progress'})
    c.responses.put({'id': 1, 'result': {'content': [{'type': 'text', 'text': '{"ok": true}'}]}})
    assert c.call('runtime_get_state')['ok']
    request = json.loads(c.process.stdin.getvalue())
    assert request['params']['name'] == 'runtime_get_state'


def test_input_failure_is_not_repeated_or_reported_successful():
    c = client()
    c.responses.put({'id': 1, 'result': {'isError': True, 'content': [
        {'type': 'text', 'text': '{"ok":false,"error":"ACTION_TIMEOUT"}'}]}})
    with pytest.raises(RuntimeError, match='ACTION_TIMEOUT'):
        c.call('computer_keypress', key='enter')
    assert c.seq == 1
    assert len(c.process.stdin.getvalue().splitlines()) == 1


def test_missing_response_times_out_without_duplicate_request():
    c = client()
    with pytest.raises(queue.Empty):
        c.rpc('tools/call', {}, timeout=.01)
    assert c.seq == 1
