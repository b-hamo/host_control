"""WBS 4.4: periodic heartbeat, health states, reconnect and resync.

Server tests run the real Host server with short intervals (heartbeat every
0.2 s, ALIVE within 0.1 s) so the whole miss → DEGRADED → UNRESPONSIVE
sequence takes well under a second.
"""

import asyncio

import pytest
from websockets.exceptions import ConnectionClosed, InvalidStatus

from host import tls
from host.runtime_session import Health, HealthTracker, RuntimeSession, REPLACED_CLOSE_CODE
from host.sender import Sessions, start_server
from host.session_registry import AuthError, SessionRegistry
from mini_runner import MiniRunner
from scrp.validate import ProtocolError

SES = ("SES-001", "RT-SBX-001", 1)
FAST = dict(heartbeat_interval_s=0.2, alive_timeout_s=0.1)


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    cert, key = tls.ensure_dev_cert(tmp_path_factory.mktemp("certs"))
    return cert, key, cert.read_text()


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 20))


async def served(certs, body, *, run_demo=False, **session_kwargs):
    """Start a Host with one registered session; body(port, reg, sessions, rec)."""
    cert, key, _ = certs
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    sessions = Sessions(reg, **{**FAST, "reconnect_grace_s": 5.0, **session_kwargs})
    async with start_server(reg, cert, key, run_demo=run_demo, host="127.0.0.1", port=0,
                            sessions=sessions) as server:
        port = server.sockets[0].getsockname()[1]
        return await body(port, reg, sessions, rec)


async def until(pred, timeout=5.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not pred():
        if loop.time() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.02)


# --------------------------------------------------------------------- health, unit
def test_health_goes_degraded_then_unresponsive_then_recovers():
    changes = []
    h = HealthTracker(SES, lambda ident, old, new, why: changes.append((old, new)))
    h.missed()
    assert h.state is Health.OK                      # one miss is only a warning
    h.missed()
    assert h.state is Health.DEGRADED
    h.missed()
    assert h.state is Health.UNRESPONSIVE
    h.alive()
    assert h.state is Health.OK and h.misses == 0
    assert changes == [(Health.OK, Health.DEGRADED), (Health.DEGRADED, Health.UNRESPONSIVE),
                       (Health.UNRESPONSIVE, Health.OK)]


def test_alive_resets_the_miss_count():
    h = HealthTracker(SES)
    h.missed()
    h.alive()
    h.missed()
    assert h.state is Health.OK


# --------------------------------------------------------------------- registry, unit
def test_new_reconnect_token_revokes_the_previous_one():
    reg = SessionRegistry()
    first = reg.issue_reconnect(SES)
    second = reg.issue_reconnect(SES)
    with pytest.raises(AuthError, match="revoked"):
        reg.check(first.token)
    assert reg.check(second.token).kind == "reconnect"


def test_revoke_all_on_terminate():
    reg = SessionRegistry()
    boot = reg.issue(*SES)
    rc = reg.issue_reconnect(SES)
    other = reg.issue("SES-002", "RT-SBX-002", 1)
    reg.revoke(SES)
    for t in (boot.token, rc.token):
        with pytest.raises(AuthError, match="revoked"):
            reg.check(t)
    reg.check(other.token)                            # other sessions untouched


def test_actions_are_refused_while_disconnected():
    async def body():
        s = RuntimeSession(SES)
        with pytest.raises(ProtocolError) as e:
            await s.action("mouse.click", {"x": 1, "y": 1, "button": "left", "click_count": 1}, "OBS-1")
        assert e.value.code == "RUNTIME_UNAVAILABLE"
    asyncio.run(body())


# --------------------------------------------------------------------- heartbeat, server
def test_heartbeats_are_sent_periodically_and_answered(certs):
    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        await until(lambda: r.heartbeats >= 4)
        assert sessions.get(SES).health.state is Health.OK
        r.drop()
        await serving
    run(served(certs, body))


def test_missing_alive_degrades_then_unresponsive_then_recovers(certs):
    changes = []

    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES, answer_heartbeats=False)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        await until(lambda: session.health.state is Health.UNRESPONSIVE)
        with pytest.raises(ProtocolError, match="UNRESPONSIVE"):
            await session.observe()                   # no new work for an unresponsive runtime
        r.answer_heartbeats = True
        await until(lambda: session.health.state is Health.OK)
        r.drop()
        await serving

    run(served(certs, body, on_health=lambda ident, old, new, why: changes.append(new)))
    assert changes == [Health.DEGRADED, Health.UNRESPONSIVE, Health.OK]


# --------------------------------------------------------------------- reconnect, server
def test_reconnect_with_the_reconnect_token_continues_the_session(certs):
    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        first = await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        r.drop()
        await serving
        session = sessions.get(SES)
        await until(lambda: session.conn is None)

        second = await r.connect(r.reconnect_token)
        serving = asyncio.create_task(r.serve())
        await until(lambda: session.ready.is_set())
        assert second["connection_id"] != first["connection_id"]
        assert second["sequence_number"] == 1          # sequence starts over per connection
        assert session.connections == 2 and session.conn.id == second["connection_id"]
        r.drop()
        await serving
    run(served(certs, body))


def test_reconnect_token_is_single_use_and_superseded(certs):
    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        token1 = r.reconnect_token
        r.drop()
        await until(lambda: sessions.get(SES).conn is None)
        await r.connect(token1)                         # uses token1, gets token2
        r.drop()
        await until(lambda: sessions.get(SES).conn is None)
        with pytest.raises(InvalidStatus) as e:
            await MiniRunner(port, certs[2], SES).connect(token1)
        assert e.value.response.status_code == 401
    run(served(certs, body))


def test_a_new_connection_replaces_the_old_one(certs):
    async def body(port, reg, sessions, rec):
        old = MiniRunner(port, certs[2], SES)
        await old.connect(rec.token)
        old_serving = asyncio.create_task(old.serve())
        new = MiniRunner(port, certs[2], SES)
        await new.connect(old.reconnect_token)
        new_serving = asyncio.create_task(new.serve())
        await old_serving
        assert old.ws.close_code == REPLACED_CLOSE_CODE
        await until(lambda: sessions.get(SES).ready.is_set())
        assert sessions.get(SES).conn.id == new.me.connection_id
        new.drop()
        await new_serving
    run(served(certs, body))


def test_no_reconnect_within_grace_reports_unresponsive(certs):
    changes = []

    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        r.drop()
        await until(lambda: Health.UNRESPONSIVE in changes)

    run(served(certs, body, reconnect_grace_s=0.3, heartbeat_interval_s=5.0,
               on_health=lambda ident, old, new, why: changes.append(new)))


def test_cut_off_action_is_resolved_by_state_request_not_resent(certs):
    """The demo loses the click's result; after reconnect the Host asks, then carries on."""
    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES, drop_after_first_ack=True)
        await r.connect(rec.token)
        assert await r.serve() == "dropped"
        await asyncio.sleep(0.1)
        await r.connect(r.reconnect_token)
        assert await r.serve() == "terminated"
        session = sessions.get(SES)
        await session.demo_task
        return r, session

    r, session = run(served(certs, body, run_demo=True, heartbeat_interval_s=5.0))
    click, typed = r.executed                           # each action ran exactly once
    assert r.state_requests[0] == click                 # first thing after reconnect: what happened to it?
    assert session.actions == {click: "SUCCESS", typed: "SUCCESS"}
    assert session.terminated


def test_no_reconnect_after_terminate(certs):
    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        await until(lambda: sessions.get(SES).ready.is_set())
        await sessions.get(SES).terminate()
        assert await serving == "terminated"
        with pytest.raises(InvalidStatus) as e:
            await MiniRunner(port, certs[2], SES).connect(r.reconnect_token)
        assert e.value.response.status_code == 401
    run(served(certs, body, heartbeat_interval_s=5.0))


def test_sequence_stays_strict_with_heartbeats_running_during_actions(certs):
    """Heartbeat loop and actions share one connection; the Runner must see 1, 2, 3, ..."""
    async def body(port, reg, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        await until(lambda: session.ready.is_set())
        for _ in range(10):
            await session.observe()
            await session.action("mouse.click", {"x": 1, "y": 1, "button": "left", "click_count": 1})
        assert session.health.state is Health.OK
        r.drop()
        await serving
        return session

    session = run(served(certs, body, heartbeat_interval_s=0.2))
    assert all(v == "SUCCESS" for v in session.actions.values()) and len(session.actions) == 10
