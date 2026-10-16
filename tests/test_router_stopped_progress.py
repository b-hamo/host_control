"""Retired progress agrees with evidence, including old/partial snapshots."""
import asyncio
import json
from dataclasses import replace

import pytest

from host.router_mcp_service import RouterService, checksum
from router.ports import Receipt, State
from test_router_mcp import definitions, local_action


@pytest.mark.parametrize('capture', ['running', 'accepted', 'timeout', 'error'])
def test_stop_normalizes_progress_and_reopen_without_replay(tmp_path, monkeypatch, capture):
    async def run():
        class Host:
            submits = 0
            retiring = False
            async def submit(self, request):
                self.submits += 1
                self.request = request
                return Receipt(request.request_id, request.action.fingerprint, State.RUNNING, 'RUNNING')
            async def status(self, rid):
                if self.retiring and capture == 'timeout':
                    await asyncio.Future()
                if self.retiring and capture == 'error':
                    raise RuntimeError('unavailable')
                state = State.ACCEPTED if self.retiring and capture == 'accepted' else State.RUNNING
                return Receipt(rid, self.request.action.fingerprint, state, 'PENDING')
            async def stop_sandbox(self):
                pass
            async def close(self):
                pass
        monkeypatch.setattr('host.router_mcp_service.SNAPSHOT_WAIT_S', .01)
        host = Host()
        database = tmp_path / 'requests.sqlite'
        service = RouterService(host, 'PLAN-TEST', database)
        action = local_action(tmp_path)
        await service.call('router_plan', definitions([action]))
        await service.call('router_submit', {'action_id': action.action_id, 'request_id': 'one'})
        await asyncio.gather(*service.jobs.values())
        await service.call('router_submit', {'action_id': action.action_id, 'request_id': 'alias'})
        before = await service.call('router_status', {'request_id': 'one'})
        assert before['progress']['actions'][action.action_id]['state'] == 'RUNNING'
        host.retiring = True
        assert (await service.call('router_stop', {}))['stopped']
        for current in (service, None):
            if current is None:
                await service.close()
                current = RouterService(None, 'PLAN-TEST', database)
            for rid in ('one', 'alias'):
                status = await current.call('router_status', {'request_id': rid})
                assert status['stopped'] is True
                assert status['receipt']['state'] == 'UNKNOWN'
                assert all(a['state'] not in ('RUNNING', 'ACCEPTED') for a in status['progress']['actions'].values())
                assert not any(t['complete'] for t in status['progress']['tasks'].values())
                assert (await current.call('router_result', {'request_id': rid}))['error'] == 'RESULT_NOT_VERIFIED'
            assert (await current.call('router_submit', {'action_id': action.action_id, 'request_id': 'new'}))['error'] == 'PLAN_STOPPED'
            if current is not service:
                await current.close()
        assert host.submits == 1
    asyncio.run(run())


def test_legacy_multi_action_snapshots_use_all_retired_receipts(tmp_path):
    async def run():
        service = RouterService(None, 'PLAN-TEST', tmp_path / 'legacy.sqlite')
        action = local_action(tmp_path)
        second = replace(action, action_id='second')
        plan = definitions([action, second])
        plan['tasks'] = plan['tasks'][:1]
        await service.call('router_plan', plan)
        progress = service.router.snapshot()
        for a in progress['actions'].values():
            a['state'] = 'RUNNING'
        progress['tasks'][action.task_id]['complete'] = True
        with service.db:
            for aid, fp, state in ((action.action_id, action.fingerprint, 'UNKNOWN'), ('second', second.fingerprint, 'SUCCEEDED')):
                canonical = 'canonical-' + aid
                snapshot = {'receipt': {'state': state}, 'result': {}, 'task_id': action.task_id, 'progress': progress}
                service.db.execute('INSERT INTO submissions VALUES (?,?,?,?,?)', (checksum(aid), aid, fp, 'contract', canonical))
                service.db.execute('INSERT INTO retired_results VALUES (?,?)', (canonical, json.dumps(snapshot)))
            service.db.execute("INSERT INTO control VALUES ('stopped')")
            service.db.execute("INSERT INTO control VALUES ('cleaned')")
        service.stopped = True
        await service.close()
        service = RouterService(None, 'PLAN-TEST', tmp_path / 'legacy.sqlite')
        fixed = (await service.call('router_status', {'request_id': action.action_id}))['progress']
        assert fixed['actions'][action.action_id]['state'] == 'UNKNOWN'
        assert fixed['actions']['second']['state'] == 'SUCCEEDED'
        assert not fixed['tasks'][action.task_id]['complete']
        assert progress['actions']['second']['state'] == 'RUNNING'  # no mutation of legacy data
        await service.close()
    asyncio.run(run())
