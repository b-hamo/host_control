"""Agent-selected Host builds, tested with fake build processes (no compiler launch)."""

import asyncio
import hashlib
import io
import zipfile
from types import SimpleNamespace

import pytest

from host import local_build
from host.audit import mask
from host.broker import Broker
from host.local_compile import CompileError
from host.tool_catalog import ToolCatalog, ToolError
from test_router_languages import runner_with_agent_capture
from test_sandbox_run import ID


def definition():
    return {"source_name": "src/main.c", "steps": [
        {"executable": "arbitrary-compiler", "arguments": ["--custom-option", "", "--custom-option"]}],
        "output": {"path": "dist", "entry": "app.exe", "arguments": ["", "two words"]}}


def arguments():
    return {"request_id": "BUILD-1", "source_id": "CAP-0001-AGENT", "form": "build-plan",
            "build_plan": definition()}


def test_arbitrary_commands_preserve_input_and_package_companion_files(tmp_path, monkeypatch):
    calls = []

    def step(spec, cwd, env, timeout, log, cancel):
        calls.append(spec)
        assert (cwd / "src/main.c").read_bytes() == b'#include "custom.h"\n'
        (cwd / "dist").mkdir()
        (cwd / "dist/app.exe").write_bytes(b"built executable")
        (cwd / "dist/helper.dll").write_bytes(b"dependency")
        return 0, "compiler output"

    monkeypatch.setattr(local_build, "_step", step)
    result = local_build.build(definition(), (local_build.BuildInput("src/main.c", b'#include "custom.h"\n'),))
    assert calls == definition()["steps"]
    assert result.arguments == ("", "two words")
    with zipfile.ZipFile(io.BytesIO(result.data)) as package:
        assert set(package.namelist()) == {"app.exe", "helper.dll"}
    assert result.steps == ({"name": "step-1", "exit_code": 0},)


def test_build_failure_stops_later_steps_and_returns_native_exit_code(monkeypatch):
    calls = []

    def fail(spec, *rest):
        calls.append(spec)
        return 7, "link failed"

    monkeypatch.setattr(local_build, "_step", fail)
    plan = definition()
    plan["steps"] *= 2
    with pytest.raises(CompileError) as error:
        local_build.build(plan, (local_build.BuildInput("src/main.c", b"source"),))
    assert len(calls) == 1
    assert error.value.exit_code == 7 and "link failed" in error.value.message


def test_zip_and_multiple_captures_are_not_limited_to_single_c_source(tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("project/build.xml", "<project />")
        z.writestr("project/Main.java", "class Main {}")
    local_build._stage(tmp_path, (local_build.BuildInput(".", archive.getvalue(), True),
                                 local_build.BuildInput("settings/config.txt", b"config")))
    assert (tmp_path / "project/Main.java").read_text() == "class Main {}"
    assert (tmp_path / "settings/config.txt").read_bytes() == b"config"
    with pytest.raises(CompileError):
        local_build._stage(tmp_path, (local_build.BuildInput("../outside.c", b"bad path"),))


def test_build_schema_keeps_legacy_forms_and_selects_one_input():
    catalog = ToolCatalog()
    assert catalog.validate("router_execute", arguments())["build_plan"] == definition()
    zip_args = arguments()
    del zip_args["source_id"]
    zip_args["file"] = "project.zip"
    zip_args["build_plan"]["archive"] = True
    assert catalog.validate("router_execute", zip_args)["file"] == "project.zip"
    for invalid in [dict(arguments(), file="duplicate.zip"),
                    dict(arguments(), form="c-source"),
                    {k: v for k, v in arguments().items() if k != "build_plan"}]:
        with pytest.raises(ToolError):
            catalog.validate("router_execute", invalid)
    assert catalog.validate("router_execute", {"request_id": "old", "source_id": "CAP-0001-AGENT",
                                                "form": "c-source"})["form"] == "c-source"


def test_bundle_runs_only_in_guest_and_runtime_is_passed_to_guest_helper(tmp_path):
    runner, _ = runner_with_agent_capture(tmp_path, text="original source")
    run, _ = runner.plan_capture(arguments(), ID)
    assert run.build_inputs[0].data == b"original source"
    assert run.origin["build_location"] == "HOST"
    bundle = local_build.BuiltBundle(b"package", "app.jar", ("-jar", "{entry}"), "java", "OK", ())
    runner.with_build(run, bundle)
    assert run.build is None and run.bundle
    assert run.origin["output_sha256"] == hashlib.sha256(bundle.data).hexdigest()
    assert run.action.command.executable.endswith("powershell.exe")
    runner.with_interpreter(run, {"exe": r"C:\Tools\java\bin\java.exe"})
    assert run.action.command.executable.endswith("powershell.exe")
    assert run.action.command.argv[-2:] == ("-Runtime", r"C:\Tools\java\bin\java.exe")
    assert run.program is None
    runner.runs[run.run_id] = run
    runner.bind_request(arguments(), run)
    assert runner.repeated(arguments()) is run


def test_plan_is_reserved_before_background_build_and_repeated_requests_do_not_build_twice(tmp_path):
    async def scenario():
        runner, _ = runner_with_agent_capture(tmp_path, text="source")
        run, _ = runner.plan_capture(arguments(), ID)
        entered = []
        release = asyncio.Event()

        async def start(plan):
            entered.append(plan.run_id)
            await release.wait()

        broker = SimpleNamespace(runner=runner, session=SimpleNamespace(), _start_build_plan=start)
        first = await Broker._dispatch(broker, "router_execute", arguments(), None, run)
        second = await Broker._dispatch(broker, "router_execute", arguments(), None, run)
        await asyncio.sleep(0)
        assert first["state"] == "ACCEPTED" and second["repeated"]
        assert entered == [run.run_id]
        release.set()
        await run.task

    asyncio.run(scenario())


def test_audit_keeps_plan_digest_without_environment_secrets():
    args = arguments()
    args["build_plan"]["environment"] = {"SECRET": "hidden-value"}
    masked = mask("router_execute", args)
    assert masked["build_plan"]["masked"] and "hidden-value" not in str(masked)
    assert args["build_plan"]["environment"]["SECRET"] == "hidden-value"


def test_compilation_failure_has_separate_status_and_never_starts_guest(tmp_path):
    async def scenario():
        runner, _ = runner_with_agent_capture(tmp_path, text="source")
        run, _ = runner.plan_capture(arguments(), ID)

        async def fail(plan):
            from host.broker import BrokerError
            plan.origin.update(build_status="FAILED", build_exit_code=2)
            raise BrokerError("INVALID_ARGUMENT", "compiler failed")

        async def no_guest(plan):
            raise AssertionError("Guest must not start after a failed build")

        broker = SimpleNamespace(session=SimpleNamespace(identity=ID, terminated=False),
                                 _compile_here=fail, _lend_interpreter=no_guest, runner=runner)
        await Broker._start_build_plan(broker, run)
        assert run.state == "FAILED" and not run.dispatched
        assert run.origin["build_exit_code"] == 2 and run.exit_code is None

    asyncio.run(scenario())
