import asyncio
import hashlib
from unittest.mock import patch

import pytest

from host.router_workflow_connection import WorkflowConnection
from router.ports import Receipt, State
from router.models import Artifact


class Runtime:
    def __init__(self, directory):
        self.directory = directory
        self.artifacts = {}
        self.receipts = {}
        self.submissions = []
        self.closed = False
        self.unavailable = asyncio.Event()

    async def submit(self, request):
        self.submissions.append(request)
        path = self.directory / (request.action.action_id + '.txt')
        path.write_bytes(b'harmless test output')
        art = Artifact('ART-' + request.action.action_id, 'EXPORTED', str(path),
                       hashlib.sha256(path.read_bytes()).hexdigest(),
                       output_name=request.action.outputs[0])
        self.artifacts[art.output_name] = art
        receipt = Receipt(request.request_id, request.action.fingerprint, State.SUCCEEDED,
                          'TEST_VERIFIED', 'EXEC-' + request.action.action_id, 'proof', (art,))
        self.receipts[request.request_id] = receipt
        return receipt

    async def status(self, rid):
        return self.receipts.get(rid, Receipt(rid, '', State.UNKNOWN, 'REQUEST_NOT_FOUND'))

    async def verify(self, receipt):
        return receipt == self.receipts.get(receipt.request_id)

    async def artifact(self, ref):
        return self.artifacts[ref]

    async def wait_unavailable(self):
        await self.unavailable.wait()

    async def stop_sandbox(self):
        self.closed = True

    async def close(self):
        self.closed = True


def connection(tmp_path):
    return WorkflowConnection(directory=tmp_path / 'connection', origins=['https://example.test'],
        runner_exe=tmp_path/'runner.exe', sandbox_root=tmp_path/'sandbox', allow_execution=True)


async def seed(c):
    # A scoped read creates the first workflow without launching a runtime.
    with patch('host.router_workflow.RouterWorkflow.read_sync', return_value=b'Write-Output harmless'):
        await c.call('router_read', {'request_id': 'source', 'uri': 'https://example.test'})
        await asyncio.gather(*c.workflows[-1].service.jobs.values())
    return (await c.call('router_result', {'request_id': 'source'}))['source']['source_id']


async def completed(c, rid):
    owner = c.owner(rid)
    await asyncio.gather(*owner.service.jobs.values(), return_exceptions=True)
    return await c.call('router_result', {'request_id': rid})


def test_two_commands_then_stop_new_session_and_old_id_no_replay(tmp_path):
    async def check():
        c = connection(tmp_path)
        runtimes = []
        async def open_runtime(w, action):
            w.execution = Runtime(w.private)
            runtimes.append(w.execution)
            w.runtime_ready.set()
        try:
            sid = await seed(c)
            def args(rid):
                return {'request_id': rid, 'source_id': sid, 'form': 'powershell-script'}
            with patch('host.router_workflow.RouterWorkflow.open_execution', open_runtime):
                for rid in ['first', 'second']:
                    assert (await c.call('router_execute', args(rid)))['ok']
                    assert (await completed(c, rid))['ok']
                assert len(runtimes) == 1 and len(runtimes[0].submissions) == 2
                assert len({r.action.outputs for r in runtimes[0].submissions}) == 2
                assert all(r.action.location.value == 'SANDBOX' for r in runtimes[0].submissions)
                assert (await c.call('router_stop', {}))['stopped']
                assert runtimes[0].closed
                assert (await c.call('router_result', {'request_id': 'first'}))['ok']
                assert (await c.call('router_execute', args('first')))['stopped']
                assert len(c.workflows) == 1
                conflict = await c.call('router_execute', {**args('first'), 'form': 'powershell-command'})
                assert conflict['error'] == 'IDEMPOTENCY_CONFLICT'
                assert (await c.call('router_execute', args('third')))['ok']
                assert (await completed(c, 'third'))['ok']
                assert len(c.workflows) == 2 and len(runtimes) == 2
                assert c.workflows[0].execution_identity != c.workflows[1].execution_identity
                assert (await c.call('router_result', {'request_id': 'second'}))['ok']
        finally:
            await c.close()
    asyncio.run(check())


def test_cleanup_failure_blocks_new_session(tmp_path):
    async def check():
        c = connection(tmp_path)
        try:
            await seed(c)
            current = c.workflows[0]
            with patch.object(current.service.host, 'stop_sandbox', side_effect=RuntimeError('cleanup failed')):
                assert not (await c.call('router_stop', {}))['ok']
                response = await c.call('router_read', {'request_id': 'new', 'uri': 'https://example.test'})
                assert response['error'] == 'CLEANUP_UNCONFIRMED'
                assert len(c.workflows) == 1
            # Reset only the test's injected cleanup failure for fixture teardown.
            current.service._retirement = None
        finally:
            await c.close()
    asyncio.run(check())


def test_source_tampering_after_stop_is_rejected(tmp_path):
    async def check():
        c = connection(tmp_path)
        try:
            sid = await seed(c)
            await c.call('router_stop', {})
            c.workflows[0].paths[sid].write_bytes(b'changed')
            with pytest.raises(ValueError, match='Source changed'):
                await c.call('router_execute', {'request_id':'new', 'source_id':sid, 'form':'powershell-script'})
            assert all(w.execution is None for w in c.workflows)
        finally:
            await c.close()
    asyncio.run(check())


def test_unknown_execution_blocks_followup_until_stop(tmp_path):
    async def check():
        c = connection(tmp_path)
        try:
            sid = await seed(c)
            with patch('host.router_workflow.RouterWorkflow.open_execution', side_effect=RuntimeError('startup unknown')):
                args = {'request_id':'first', 'source_id':sid, 'form':'powershell-script'}
                await c.call('router_execute', args)
                assert not (await completed(c, 'first'))['ok']
                with pytest.raises(ValueError, match='busy or unconfirmed'):
                    await c.call('router_execute', {**args, 'request_id':'second'})
                assert len(c.workflows) == 1
        finally:
            await c.close()
    asyncio.run(check())


def test_runtime_loss_retires_without_restart_until_new_work(tmp_path):
    async def check():
        c = connection(tmp_path)
        runtimes = []
        async def open_runtime(w, action):
            w.execution = Runtime(w.private)
            runtimes.append(w.execution)
            w.runtime_ready.set()
        try:
            sid = await seed(c)
            args = {'request_id':'first', 'source_id':sid, 'form':'powershell-script'}
            with patch('host.router_workflow.RouterWorkflow.open_execution', open_runtime):
                await c.call('router_execute', args)
                assert (await completed(c, 'first'))['ok']
                runtimes[0].unavailable.set()
                await asyncio.wait_for(c.workflows[0].service._watcher, 2)
                assert c.workflows[0].service.stopped and runtimes[0].closed
                assert (await c.call('router_execute', args))['stopped']
                assert (await c.call('router_result', {'request_id':'first'}))['ok']
                assert len(runtimes) == 1
                await c.call('router_execute', {**args, 'request_id':'new-work'})
                assert (await completed(c, 'new-work'))['ok']
                assert len(runtimes) == 2
        finally:
            await c.close()
    asyncio.run(check())
