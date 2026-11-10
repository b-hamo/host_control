import asyncio
from types import SimpleNamespace

import pytest

from host.broker import Broker, BrokerError
from host.tool_catalog import ToolCatalog


def harness(prepare):
    session = SimpleNamespace(identity=("SES-apps", "RT-apps", 1), terminated=False,
                              ready=asyncio.Event())
    session.ready.set()
    broker = Broker(session, launcher=SimpleNamespace(prepare_apps=prepare), programs=True)
    broker.task_id = "TASK-1"
    return broker


def test_pending_polls_share_one_job_and_block_input():
    async def run():
        release, calls = asyncio.Event(), []
        async def prepare(apps):
            calls.append(apps)
            await release.wait()
            return {"prepared": True, "apps": [{"app": "notepad", "prepared": True}]}
        broker = harness(prepare)
        args = {"request_id": "prepare-1", "apps": ["notepad"], "wait_ms": 0}
        assert (await broker._prepare_apps(args))["status"] == "PREPARING"
        assert (await broker._prepare_apps(args))["status"] == "PREPARING"
        with pytest.raises(BrokerError, match="preparation is still running"):
            broker._check_session("computer_keypress")
        broker._check_session("computer_observe")
        with pytest.raises(BrokerError, match="different applications"):
            await broker._prepare_apps(dict(args, apps=["python"]))
        release.set()
        assert (await broker._prepare_apps(dict(args, wait_ms=1000)))["prepared"]
        broker._check_session("computer_keypress")
        assert calls == [["notepad"]]
    asyncio.run(run())


def test_generation_change_never_replays_or_returns_prepared():
    async def run():
        calls = []
        async def prepare(apps):
            calls.append(apps)
            return {"prepared": True, "apps": []}
        broker = harness(prepare)
        args = {"request_id": "prepare-1", "apps": ["powershell"], "wait_ms": 1000}
        assert (await broker._prepare_apps(args))["prepared"]
        broker.session.identity = ("SES-apps", "RT-apps", 2)
        assert (await broker._prepare_apps(args))["status"] == "UNKNOWN"
        assert len(calls) == 1
    asyncio.run(run())


def test_failed_preparation_cannot_become_success_on_poll():
    async def run():
        calls = []
        async def prepare(apps):
            calls.append(apps)
            raise RuntimeError("uncertain Guest reply")
        broker = harness(prepare)
        args = {"request_id": "prepare-1", "apps": ["python"], "wait_ms": 1000}
        assert (await broker._prepare_apps(args))["status"] == "UNKNOWN"
        assert (await broker._prepare_apps(args))["status"] == "UNKNOWN"
        assert len(calls) == 1
    asyncio.run(run())


def test_app_tool_schema_and_default_install_configuration(tmp_path):
    from host.solution import host_arguments
    args = ToolCatalog().validate("app_prepare", {"request_id": "prepare-1", "apps": ["notepad"]})
    assert args["wait_ms"] == 1000
    assert "--share-programs" in host_arguments(tmp_path / "runner.exe", tmp_path / "work", tmp_path / "state")


def test_manager_checkout_requires_explicit_dev_and_never_replaces_loaded_module(tmp_path, monkeypatch):
    import sys
    from host.solution_config import activate_manager_source
    package = tmp_path / "sandbox_manager"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "app_preparation.py").write_text("")
    profile = {"mode": "Dev", "manager_source": "checkout", "manager_repo": str(tmp_path)}
    with pytest.raises(ValueError, match="invalid Manager source"):
        activate_manager_source(dict(profile, mode="Deploy"))
    monkeypatch.setitem(sys.modules, "sandbox_manager", SimpleNamespace(__file__=str(tmp_path / "other/__init__.py")))
    with pytest.raises(ValueError, match="already been imported"):
        activate_manager_source(profile)
    monkeypatch.delitem(sys.modules, "sandbox_manager")
    monkeypatch.setattr(sys, "path", list(sys.path))
    activate_manager_source(profile)
    assert sys.path[0] == str(tmp_path.resolve())
