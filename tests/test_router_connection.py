"""Sequential Router plans: real stdio/local Host plus isolated execution doubles."""
import asyncio
from dataclasses import asdict, replace
import json
from pathlib import Path
import sys

import pytest

from host.router_connection import RouterConnection, catalog
from host.router_mcp_server import tool_list
from host.router_command_bundle import CommandBundle, output_directory
from router.ports import Request
from test_mcp_server import Client, stop
from test_router_mcp import configuration, definitions, Port, SERVER, start as start_legacy
from test_router import setup, FakeSandbox  # noqa: F401


def configured(tmp_path):
    profile, config, action, execution = configuration(tmp_path)
    path = tmp_path / 'catalog.json'
    path.write_text(json.dumps({'version': 1, 'private_directory': str(tmp_path / 'connection'),
                                'profiles': {'work': str(profile)}}))
    return path, action, execution


async def start(path):
    proc = await asyncio.create_subprocess_exec(sys.executable, str(SERVER), '--catalog', str(path),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    client = Client(proc)
    await client.rpc('initialize')
    return proc, client


async def complete(client, pid, action):
    plan = definitions([action]); plan['plan_id'] = pid
    assert (await client.call('router_plan', plan))['ok']
    args = {'plan_id': pid, 'request_id': 'same-action-request', 'action_id': action.action_id}
    assert (await client.call('router_submit', args))['ok']
    for _ in range(100):
        result = await client.call('router_result', {'plan_id': pid, 'request_id': args['request_id']})
        if result['ok']:
            return result
        await asyncio.sleep(.02)
    raise AssertionError(result)


def test_same_stdio_stop_start_result_and_reconnect(tmp_path):
    async def run():
        path, action, _ = configured(tmp_path)
        proc, client = await start(path)
        try:
            names = {t['name'] for t in (await client.rpc('tools/list'))['result']['tools']}
            assert names == {t['name'] for t in tool_list(True)}
            assert not {'task_submit', 'computer_type', 'sandbox_run'} & names
            assert (await client.call('router_list')) == {'ok': True, 'profiles': ['work'], 'plans': []}
            for name in ('task_submit', 'computer_type', 'sandbox_run', 'exec_command'):
                assert (await client.call(name))['error'] == 'TOOL_NOT_EXPOSED'
            first = await client.call('router_start', {'profile': 'work', 'request_id': 'start-a'})
            assert first['ok']; a = first['plan_id']
            assert await client.call('router_start', {'profile': 'work', 'request_id': 'start-a'}) == first
            assert (await client.call('router_start', {'profile': 'work', 'request_id': 'start-b'}))['error'] == 'PLAN_ACTIVE'
            result = await complete(client, a, action)
            assert result['text'] == 'inert text'
            assert (await client.call('router_stop', {'plan_id': a}))['stopped']
            second = await client.call('router_start', {'profile': 'work', 'request_id': 'start-b'})
            assert second['ok']; b = second['plan_id']; assert a != b
            assert (await complete(client, b, action))['text'] == 'inert text'
            assert (await client.call('router_result', {'plan_id': a, 'request_id': 'same-action-request'}))['text'] == 'inert text'
            assert (await client.call('router_submit', {'plan_id': a, 'request_id': 'new', 'action_id': action.action_id}))['error'] == 'PLAN_STOPPED'
            # Stopping A again cannot stop B.
            assert (await client.call('router_stop', {'plan_id': a}))['stopped']
            assert not next(p for p in (await client.call('router_list'))['plans'] if p['plan_id'] == b)['stopped']
            assert (await client.call('router_stop', {'plan_id': b}))['stopped']
            assert proc.returncode is None
        finally:
            await stop(proc)
        proc, client = await start(path)
        try:
            recovered = await client.call('router_start', {'profile': 'work', 'request_id': 'start-a'})
            assert recovered['plan_id'] == a and recovered['stopped']
            assert (await client.call('router_result', {'plan_id': a, 'request_id': 'same-action-request'}))['text'] == 'inert text'
            third = await client.call('router_start', {'profile': 'work', 'request_id': 'start-c'})
            assert third['ok'] and third['plan_id'] not in {a,b}
            assert (await client.call('router_stop', {'plan_id': third['plan_id']}))['stopped']
        finally:
            await stop(proc)
    asyncio.run(run())


def test_concurrent_starts_and_execution_scope_rebinding(setup, tmp_path):
    async def run():
        path, action, _ = configured(tmp_path)
        root, profiles = catalog(path)
        opened = []
        async def factory(provision):
            opened.append(provision)
            return Port(setup((action,)))
        connection = RouterConnection(root, profiles, factory)
        try:
            replies = await asyncio.gather(*(connection.call('router_start', {'profile':'work', 'request_id':'a'}) for _ in range(8)))
            assert len(opened) == 1
            assert all(r == replies[0] for r in replies)
            a = replies[0]['plan_id']
            assert (await connection.call('router_start', {'profile':'different', 'request_id':'a'}))['error'] == 'IDEMPOTENCY_CONFLICT'
            assert (await connection.call('router_start', {'profile':'unknown', 'request_id':'b'}))['error'] == 'PROFILE_NOT_FOUND'
            assert (await connection.call('router_stop', {'plan_id':'missing'}))['error'] == 'PLAN_NOT_FOUND'
            assert (await connection.call('router_stop', {'plan_id':a}))['stopped']
            b = await connection.call('router_start', {'profile':'work', 'request_id':'b'})
            assert b['ok'] and len(opened) == 2
            assert opened[0]['args'].session != opened[1]['args'].session
            assert opened[0]['args'].runtime != opened[1]['args'].runtime
            assert opened[0]['private_directory'] != opened[1]['private_directory']
            assert opened[0]['args'].export_dir != opened[1]['args'].export_dir
        finally:
            await connection.close()
    asyncio.run(run())


def test_cleanup_failure_blocks_next_start(setup, tmp_path):
    async def run():
        path, action, _ = configured(tmp_path); root, profiles = catalog(path)
        class Failing(Port):
            async def stop_sandbox(self):
                raise TimeoutError('cleanup failed')
        async def factory(provision):
            return Failing(setup((action,)))
        connection = RouterConnection(root, profiles, factory)
        a = (await connection.call('router_start', {'profile':'work', 'request_id':'a'}))['plan_id']
        assert not (await connection.call('router_stop', {'plan_id':a}))['ok']
        assert (await connection.call('router_start', {'profile':'work', 'request_id':'b'}))['error'] == 'CLEANUP_UNCONFIRMED'
        with pytest.raises(RuntimeError):
            await connection.close()
        connection = RouterConnection(root, profiles, factory)
        assert (await connection.call('router_start', {'profile':'work', 'request_id':'b'}))['error'] == 'CLEANUP_UNCONFIRMED'
        with pytest.raises(RuntimeError):
            await connection.close()
    asyncio.run(run())


def test_start_failure_reservation_survives_restart(tmp_path):
    async def run():
        path, _, _ = configured(tmp_path); root, profiles = catalog(path)
        calls = []
        async def factory(provision):
            calls.append(provision)
            raise RuntimeError('private startup error')
        connection = RouterConnection(root, profiles, factory)
        args = {'profile':'work', 'request_id':'a'}
        failed = await connection.call('router_start', args)
        assert failed['error'] == 'START_UNCONFIRMED'
        assert (await connection.call('router_start', args))['plan_id'] == failed['plan_id']
        assert len(calls) == 1
        with pytest.raises(RuntimeError):
            await connection.close()
        connection = RouterConnection(root, profiles, factory)
        assert (await connection.call('router_start', args))['plan_id'] == failed['plan_id']
        assert (await connection.call('router_start', {'profile':'work', 'request_id':'b'}))['error'] == 'CLEANUP_UNCONFIRMED'
        assert len(calls) == 1
        with pytest.raises(RuntimeError):
            await connection.close()
    asyncio.run(run())


def test_existing_config_can_start_followup_without_reconnecting(tmp_path):
    async def run():
        profile, _, action, _ = configuration(tmp_path)
        proc, client = await start_legacy(profile)
        try:
            assert (await client.call('router_list'))['profiles'] == ['default']
            await complete(client, 'PLAN-TEST', action)
            assert (await client.call('router_stop'))['stopped']
            new = await client.call('router_start', {'profile':'default', 'request_id':'followup'})
            assert new['ok'] and new['plan_id'] != 'PLAN-TEST'
            assert (await complete(client, new['plan_id'], action))['ok']
            # Omitted plan_id NEVER silently targets the latest plan.
            assert (await client.call('router_submit', {'request_id':'again', 'action_id':action.action_id}))['error'] == 'PLAN_STOPPED'
            assert (await client.call('router_result', {'request_id':'same-action-request'}))['text'] == 'inert text'
            assert (await client.call('router_stop', {'plan_id':new['plan_id']}))['stopped']
        finally:
            await stop(proc)
        proc, client = await start_legacy(profile)
        try:
            assert (await client.call('router_result', {'request_id':'same-action-request'}))['text'] == 'inert text'
            assert (await client.call('router_result', {'plan_id':new['plan_id'],'request_id':'same-action-request'}))['text'] == 'inert text'
        finally:
            await stop(proc)
    asyncio.run(run())


def test_generated_execution_preserves_authority_and_uses_new_guest_output(tmp_path):
    from host.router_codec import action as decode_action
    from host.router_gateway import HostGateway
    from host.router_ledger import Ledger
    from host.router_local import LocalTools
    async def run():
        path, _, _ = configured(tmp_path)
        profile = tmp_path/'host.json'; config = json.loads(profile.read_text())
        original = decode_action(config['execution_action'])
        original = replace(original, scope=replace(original.scope,
            writes=(output_directory(('SES-MCP-TEST','RT-MCP-TEST',1)),),
            capabilities=('process.execute','gui.input','gui.observe','artifact.export.v1')))
        config['execution_action'] = asdict(original)
        grant = config['delegations'][0]
        grant.update(operations=['execute'], locations=['SANDBOX'], scope=asdict(original.scope),
                     execution_fingerprints=[original.fingerprint])
        profile.write_text(json.dumps(config))
        root, profiles = catalog(path); guests=[]; provisions=[]; ledgers=[]
        async def factory(provision):
            provisions.append(provision)
            guest=FakeSandbox(); guests.append(guest)
            ledger=Ledger(provision['private_directory']/'ledger.sqlite');ledgers.append(ledger)
            return Port(HostGateway(provision['authority'], ledger, LocalTools(provision['data_directory']), sandbox=guest))
        connection=RouterConnection(root,profiles,factory)
        try:
            for key in ('first','second'):
                started=await connection.call('router_start', {'profile':'work','request_id':key})
                pid=started['plan_id']; action=decode_action(started['execution_action']);provision=provisions[-1]
                assert action.command==original.command and action.sources==original.sources
                assert action.scope.reads==original.scope.reads
                assert action.scope.capabilities==original.scope.capabilities
                assert action.scope.writes!=original.scope.writes
                assert provision['authority'].check(action)=='ALLOW'
                assert provision['authority'].check(original)!='ALLOW'
                assert provision['authority'].check(replace(action, command=replace(action.command, argv=('unapproved',))))!='ALLOW'
                identity=(provision['args'].session, provision['args'].runtime,1)
                CommandBundle(Request('REQ-bundle',action),identity,provision['bindings'],provision['private_directory']/'bundle')
                plan=definitions([action]);plan['plan_id']=pid
                assert (await connection.call('router_plan',plan))['ok']
                assert (await connection.call('router_submit',{'plan_id':pid,'request_id':'run','action_id':action.action_id}))['ok']
                await asyncio.gather(*connection.services[pid].jobs.values())
                assert (await connection.call('router_result',{'plan_id':pid,'request_id':'run'}))['ok']
                assert guests[-1].calls==1
                assert (await connection.call('router_stop',{'plan_id':pid}))['stopped']
            assert len(guests)==2
        finally:
            await connection.close()
            for ledger in ledgers: ledger.close()
    asyncio.run(run())


def test_killed_connection_never_restarts_reserved_plan(tmp_path):
    async def run():
        path, action, _ = configured(tmp_path)
        proc,client=await start(path)
        original=await client.call('router_start',{'profile':'work','request_id':'a'})
        await complete(client, original['plan_id'], action)
        before=Path(action.locator).stat().st_mtime_ns
        proc.kill();await proc.wait()
        proc,client=await start(path)
        try:
            retry=await client.call('router_start',{'profile':'work','request_id':'a'})
            assert retry['error']=='CLEANUP_UNCONFIRMED' and retry['plan_id']==original['plan_id']
            assert (await client.call('router_start',{'profile':'work','request_id':'b'}))['error']=='CLEANUP_UNCONFIRMED'
            assert (await client.call('router_submit',{'plan_id':original['plan_id'],'request_id':'run','action_id':action.action_id}))['error']=='PLAN_STOPPED'
            assert Path(action.locator).stat().st_mtime_ns==before
        finally:
            await stop(proc)
    asyncio.run(run())


def test_connection_close_waits_for_inflight_start(setup, tmp_path):
    async def run():
        path, action, _ = configured(tmp_path);root,profiles=catalog(path)
        entered, release=asyncio.Event(),asyncio.Event();stops=[]
        class Tracked(Port):
            async def stop_sandbox(self): stops.append(True)
        async def factory(provision):
            entered.set();await release.wait()
            return Tracked(setup((action,)))
        connection=RouterConnection(root,profiles,factory)
        starting=asyncio.create_task(connection.call('router_start',{'profile':'work','request_id':'a'}))
        await entered.wait()
        closing=asyncio.create_task(connection.close())
        await asyncio.sleep(0)
        assert not closing.done()
        release.set()
        assert (await starting)['ok']
        await closing
        assert len(stops)==1
        assert (await connection.call('router_start',{'profile':'work','request_id':'b'}))['error']=='CONNECTION_CLOSED'
        await connection.close()
    asyncio.run(run())
