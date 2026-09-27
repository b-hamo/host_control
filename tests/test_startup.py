"""WBS 4.5: the Host, not the Runner, decides when a Runtime is READY.

Server tests use a 0.5 s per-step timeout so a Runner that stays silent fails
quickly; production uses 5 s per step and 120 s overall.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from websockets.exceptions import ConnectionClosed, InvalidStatus

from host import tls
from host.sender import Sessions, start_server
from host.session_registry import SessionRegistry
from host.startup import StartupProfile, StartupReport, check_hello
from mini_runner import DEFAULT_COVERAGE, MiniRunner, hello_msg
from scrp.envelope import Endpoint
from scrp.validate import ProtocolError

SES = ("SES-001", "RT-SBX-001", 1)
QUICK = StartupProfile(step_timeout_s=0.5, timeout_s=5.0)


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    cert, key = tls.ensure_dev_cert(tmp_path_factory.mktemp("certs"))
    return cert, key, cert.read_text()


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 20))


async def served(certs, body, *, profile=QUICK, watchdog=False, run_demo=False):
    cert, key, _ = certs
    reg = SessionRegistry()
    rec = reg.issue(*SES)
    reports = []
    sessions = Sessions(reg, profile=profile, heartbeat_interval_s=5.0,
                        on_startup=lambda ident, report: reports.append(report))
    async with start_server(reg, cert, key, run_demo=run_demo, host="127.0.0.1", port=0,
                            sessions=sessions) as server:
        if watchdog:
            sessions.register(SES)
        port = server.sockets[0].getsockname()[1]
        result = await body(port, sessions, rec)
    return result, sessions.get(SES), reports


async def until(pred, timeout=5.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not pred():
        if loop.time() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.02)


# --------------------------------------------------------------------- HELLO checks, unit
def hello(**kw) -> dict:
    return hello_msg(Endpoint(*SES), kw.get("capabilities"), kw.get("coverage"))


def test_hello_that_meets_the_profile_passes():
    report = StartupReport()
    assert check_hello(hello(), StartupProfile(), report)
    assert [c.name for c in report.checks] == ["version", "capabilities", "monitoring", "clock"]
    assert all(c.ok for c in report.checks)


def test_missing_capability_is_reported():
    report = StartupReport()
    assert not check_hello(hello(capabilities=["gui.observe"]), StartupProfile(), report)
    assert report.reason == "capabilities: missing ['gui.input']"


def test_missing_required_monitor_is_reported():
    report = StartupReport()
    assert not check_hello(hello(coverage={**DEFAULT_COVERAGE, "file": False}), StartupProfile(), report)
    assert report.reason == "monitoring: missing ['file'] monitor"


def test_large_clock_skew_blocks_ready():
    h = hello()
    h["timestamp"] = (datetime.now(timezone.utc) - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    report = StartupReport()
    assert not check_hello(h, StartupProfile(), report)
    assert report.reason.startswith(("clock: skew 120s", "clock: skew 121s"))   # sub-second rounding


# --------------------------------------------------------------------- server
def test_healthy_runner_is_verified_then_ready(certs):
    async def body(port, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        assert session.runtime_state == "PREPARING" and not session.ready.is_set()   # HELLO alone is not READY
        await until(lambda: session.ready.is_set())
        status = session.status()
        r.drop()
        await serving
        return status

    status, session, reports = run(served(certs, body))
    assert status["state"] == "READY" and status["startup"]["ok"] is True
    assert [c["name"] for c in status["startup"]["checks"]] == [
        "version", "capabilities", "monitoring", "clock", "worker", "first_capture", "heartbeat"]
    assert len(reports) == 1 and reports[0].ok


def test_actions_wait_for_verification(certs):
    """Nothing but the Host's own checks is sent before READY."""
    async def body(port, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        session = sessions.get(SES)
        with pytest.raises(ProtocolError) as e:
            await session.action("mouse.click", {"x": 1, "y": 1, "button": "left", "click_count": 1}, "OBS-1")
        assert e.value.code == "RUNTIME_UNAVAILABLE"
        serving = asyncio.create_task(r.serve())
        await until(lambda: session.ready.is_set())
        r.drop()
        await serving
        return r.executed

    executed, _, _ = run(served(certs, body))
    assert executed == []


def expect_start_failure(certs, runner_kwargs, reason_prefix):
    async def body(port, sessions, rec):
        r = MiniRunner(port, certs[2], SES, **runner_kwargs)
        try:
            await r.connect(rec.token)
        except ConnectionClosed as e:                   # refused at HELLO
            return e.rcvd.code, r
        await r.serve()
        return r.ws.close_code, r

    (code, r), session, reports = run(served(certs, body))
    assert code == 1008
    assert session.runtime_state == "TERMINATED" and session.startup.ok is False
    assert session.startup.reason.startswith(reason_prefix), session.startup.reason
    assert session.end_reason.startswith("RUNTIME_START_FAILED")
    assert len(reports) == 1 and reports[0].ok is False
    return r


def test_dead_worker_is_not_promoted(certs):
    expect_start_failure(certs, {"worker_alive": False}, "worker: worker_alive=False")


def test_no_first_capture_is_not_promoted(certs):
    expect_start_failure(certs, {"answer_observe": False}, "first_capture: no OBSERVE_RESULT")


def test_no_alive_at_startup_is_not_promoted(certs):
    expect_start_failure(certs, {"answer_heartbeats": False}, "heartbeat: no ALIVE")


def test_missing_monitor_is_refused_before_credentials(certs):
    r = expect_start_failure(certs, {"coverage": {**DEFAULT_COVERAGE, "file": False}}, "monitoring:")
    assert r.reconnect_token is None                    # no HELLO_ACK, so no reconnect token handed out


def test_failed_startup_revokes_the_session(certs):
    async def body(port, sessions, rec):
        bad = MiniRunner(port, certs[2], SES, worker_alive=False)
        await bad.connect(rec.token)
        await bad.serve()
        with pytest.raises(InvalidStatus) as e:
            await MiniRunner(port, certs[2], SES).connect(bad.reconnect_token)
        return e.value.response.status_code

    code, session, _ = run(served(certs, body))
    assert code == 401 and session.terminated


def test_nobody_connecting_times_out(certs):
    async def body(port, sessions, rec):
        session = sessions.get(SES)
        await until(lambda: session.terminated, timeout=3)
        with pytest.raises(InvalidStatus) as e:          # the bootstrap token is dead too
            await MiniRunner(port, certs[2], SES).connect(rec.token)
        return e.value.response.status_code

    code, session, reports = run(served(certs, body, watchdog=True,
                                        profile=StartupProfile(step_timeout_s=0.5, timeout_s=0.3)))
    assert code == 401
    assert session.startup.reason == "timeout after 0s: runner never connected"
    assert reports[0].ok is False


def test_verified_session_is_not_timed_out_later(certs):
    async def body(port, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        await until(lambda: session.ready.is_set())
        await asyncio.sleep(1.2)                         # past the 1 s startup deadline
        state = session.runtime_state
        r.drop()
        await serving
        return state

    state, session, _ = run(served(certs, body, watchdog=True,
                                   profile=StartupProfile(step_timeout_s=0.5, timeout_s=1.0)))
    assert state == "READY" and session.startup.ok


def test_reconnect_with_fewer_capabilities_ends_the_session(certs):
    async def body(port, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        serving = asyncio.create_task(r.serve())
        session = sessions.get(SES)
        await until(lambda: session.ready.is_set())
        r.drop()
        await serving
        await until(lambda: session.conn is None)
        weaker = MiniRunner(port, certs[2], SES, capabilities=["gui.observe"])
        with pytest.raises(ConnectionClosed):
            await weaker.connect(r.reconnect_token)
        return session

    _, session, _ = run(served(certs, body))
    assert session.terminated and session.end_reason.startswith("RECONNECT_REJECTED: capabilities")


def test_demo_still_completes_after_verification(certs):
    async def body(port, sessions, rec):
        r = MiniRunner(port, certs[2], SES)
        await r.connect(rec.token)
        assert await r.serve() == "terminated"
        await sessions.get(SES).demo_task
        return r

    r, session, _ = run(served(certs, body, run_demo=True))
    assert len(r.executed) == 2 and session.terminated and session.startup.ok
