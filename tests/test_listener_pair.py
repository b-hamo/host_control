"""Real TCP conflicts, without creating or stopping a VM or another Host."""
import asyncio
from contextlib import asynccontextmanager
import errno

import pytest

from host.mcp_server import _listener_pair


@asynccontextmanager
async def control_server(factory):
    async with await factory() as server:
        yield server


@pytest.mark.parametrize('busy_channel', ['upload', 'control'])
def test_second_host_preserves_first_listener_and_uses_free_ports(busy_channel):
    async def run():
        async def echo(reader, writer):
            writer.write(b'original host still alive\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        first = await asyncio.start_server(echo, '127.0.0.1', 0)
        occupied_port = first.sockets[0].getsockname()[1]
        ports = {'upload': 0, 'control': 0}
        ports[busy_channel] = occupied_port
        created, replans = [], []

        async def create(channel):
            server = await asyncio.start_server(echo, '127.0.0.1', ports[channel])
            created.append(server)
            return server

        async def replan():
            assert all(not s.is_serving() for s in created), 'partial listener leaked'
            replans.append(True)
            ports.update(upload=0, control=0)

        async with first:
            async with _listener_pair(lambda: create('upload'),
                                      lambda: control_server(lambda: create('control')),
                                      on_address_in_use=replan) as (upload, control):
                actual = {s.sockets[0].getsockname()[1] for s in (upload, control)}
                assert len(actual) == 2 and occupied_port not in actual
                reader, writer = await asyncio.open_connection('127.0.0.1', occupied_port)
                assert await reader.readline() == b'original host still alive\n'
                writer.close()
                await writer.wait_closed()
            assert first.is_serving()
        assert replans == [True]
        assert all(not s.is_serving() for s in created)
    asyncio.run(run())


@pytest.mark.parametrize('code,enabled,attempts,replans', [
    (errno.EACCES, True, 1, 0), (errno.EADDRINUSE, False, 1, 0),
    (errno.EADDRINUSE, True, 2, 1), (10048, True, 2, 1),
])
def test_only_busy_auto_mode_replans_once(code, enabled, attempts, replans):
    async def run():
        seen, changed = [], []
        async def upload():
            seen.append(True)
            raise OSError(code, 'test bind error')
        def control():
            pytest.fail('control must not start after upload bind failed')
        async def replan():
            changed.append(True)
        with pytest.raises(OSError) as error:
            async with _listener_pair(upload, control, on_address_in_use=replan if enabled else None):
                pytest.fail('listeners were not created')
        assert error.value.errno == code
        assert len(seen) == attempts and len(changed) == replans
    asyncio.run(run())


def test_error_after_binding_never_replays_or_replans():
    async def run():
        closed, changed = [], []
        @asynccontextmanager
        async def listener():
            try:
                yield object()
            finally:
                closed.append(True)
        async def upload():
            return listener()
        async def replan():
            changed.append(True)
        with pytest.raises(OSError):
            async with _listener_pair(upload, listener, on_address_in_use=replan):
                raise OSError(errno.EADDRINUSE, 'later VM workload failure')
        assert not changed and len(closed) == 2
    asyncio.run(run())
