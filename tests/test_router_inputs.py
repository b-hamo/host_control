"""Manager input contract tests; prepare/copy is real when the package is present.

These tests never start Windows Sandbox and never execute an input script.
"""

from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from host.router_authority import Authority, Delegation
from host.router_inputs import InputBinding, InputBoundManager
from router import Action, Command, Location, Operation, Scope, Source


def register(path, source):
    data = path.read_bytes()
    return SimpleNamespace(path=path, sha256=hashlib.sha256(data).hexdigest(),
                           size=len(data), source=source)


class ManagerDouble:
    def __init__(self, root):
        self.root = root
        self.prepares = self.starts = self.cleanups = 0

    def prepare(self, *args, input_files):
        self.prepares += 1
        self.root.mkdir()
        for item in input_files:
            shutil.copyfile(item.path, self.root / item.path.name)
        self.inputs = input_files
        return SimpleNamespace(input_dir=self.root,
            guest_input_paths=[rf"C:\UserFiles\{item.path.name}" for item in input_files])

    def start(self, session):
        self.starts += 1
        return "192.0.2.1"

    def cleanup(self, session):
        self.cleanups += 1


@pytest.fixture
def bound(tmp_path):
    path = tmp_path / "renamed.ps1"
    path.write_text("'inert test data; never run this file'", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    parent = Source("original", "https://example.invalid/task?token=PRIVATE", digest, "external")
    source = Source("renamed", "copy:renamed.ps1", digest, "local", (parent.source_id,))
    binding = InputBinding(source.source_id, path)
    scope = Scope(reads=(binding.guest_path,), capabilities=("process.execute",))
    action = Action("execute", "guest", Operation.EXECUTE, scope, "user-grant",
                    sources=(parent, source), command=Command("powershell.exe",
                        ("-NoProfile", "-File", binding.guest_path), r"C:\UserFiles", source.source_id))
    grant = Delegation("user-grant", frozenset({Operation.EXECUTE}), frozenset({Location.SANDBOX}),
                        scope, 100, frozenset({action.fingerprint}))
    authority = Authority(sources=action.sources, delegations=(grant,), clock=lambda: 0,
                          verify_source=lambda s: hashlib.sha256(path.read_bytes()).hexdigest() == s.sha256)
    manager = ManagerDouble(tmp_path / "copied")
    return SimpleNamespace(path=path, binding=binding, action=action, authority=authority, manager=manager)


def adapter(bound, **kwargs):
    return InputBoundManager(bound.manager, bound.authority, bound.action, (bound.binding,),
                             register_input=kwargs.pop("register_input", register), **kwargs)


def prepare(manager):
    return manager.prepare("SES-ROUTER", "RT-ROUTER", 1, Path("runner.exe"))


def test_prepare_binds_copy_and_preserves_lineage_without_starting(bound):
    manager = adapter(bound)
    session = prepare(manager)
    assert bound.manager.starts == 0
    assert (session.input_dir / bound.path.name).read_bytes() == bound.path.read_bytes()
    assert session.guest_input_paths == [bound.binding.guest_path]
    assert manager.action.sources[1].parents == ("original",)
    assert "PRIVATE" not in bound.manager.inputs[0].source
    assert bound.action.sources[1].sha256 in bound.manager.inputs[0].source
    assert manager.start(session) == "192.0.2.1"
    assert bound.manager.starts == 1


@pytest.mark.parametrize("when", ["before_prepare", "before_start"])
def test_changed_original_requires_reassessment(bound, when):
    manager = adapter(bound)
    session = prepare(manager) if when == "before_start" else None
    bound.path.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="reassessment"):
        manager.start(session) if session else prepare(manager)
    assert bound.manager.starts == 0


def test_source_omission_denies_before_manager(bound):
    del bound.authority.sources["original"]
    with pytest.raises(ValueError, match="reassessment"):
        prepare(adapter(bound))
    assert bound.manager.prepares == 0


def test_missing_delegation_denies_before_manager(bound):
    bound.authority.delegations.clear()
    with pytest.raises(ValueError, match="reassessment"):
        prepare(adapter(bound))
    assert bound.manager.prepares == 0


def test_hash_change_during_registration_is_not_authorized(bound):
    def changed(path, source):
        return SimpleNamespace(sha256="0" * 64)
    with pytest.raises(ValueError, match="content changed"):
        prepare(adapter(bound, register_input=changed))
    assert bound.manager.prepares == 0


def test_policy_failure_does_not_start_or_use_local_execution(bound):
    def unavailable(source):
        raise RuntimeError("policy service unavailable")
    bound.authority.verify_source = unavailable
    with pytest.raises(RuntimeError):
        prepare(adapter(bound))
    assert bound.manager.prepares == bound.manager.starts == 0


def test_guest_path_contract_mismatch_is_cleaned_before_start(bound):
    original = bound.manager.prepare
    def wrong(*args, **kwargs):
        session = original(*args, **kwargs)
        session.guest_input_paths = [r"C:\Wrong\renamed.ps1"]
        return session
    bound.manager.prepare = wrong
    with pytest.raises(ValueError, match="Guest input paths"):
        prepare(adapter(bound))
    assert bound.manager.cleanups == 1
    assert bound.manager.starts == 0


def test_copy_tampering_stops_before_start(bound):
    manager = adapter(bound)
    session = prepare(manager)
    (session.input_dir / bound.path.name).write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="prepared input changed"):
        manager.start(session)
    assert bound.manager.starts == 0


def test_unrelated_session_cannot_start(bound):
    manager = adapter(bound)
    prepare(manager)
    with pytest.raises(ValueError, match="not prepared"):
        manager.start(SimpleNamespace())
    assert bound.manager.starts == 0


def test_hardlinked_input_refused(bound, tmp_path):
    (tmp_path / "alias.ps1").hardlink_to(bound.path)
    with pytest.raises(ValueError, match="single-link"):
        prepare(adapter(bound))
    assert bound.manager.prepares == 0


@pytest.mark.parametrize("change", ["scope", "target", "duplicate"])
def test_mismatched_binding_contract_is_rejected(bound, change):
    action, bindings = bound.action, (bound.binding,)
    if change == "scope":
        action = replace(action, scope=replace(action.scope, reads=()))
    elif change == "target":
        action = replace(action, command=replace(action.command, argv=("-File", r"C:\Other\renamed.ps1")))
    else:
        bindings *= 2
    with pytest.raises(ValueError):
        InputBoundManager(bound.manager, bound.authority, action, bindings)


def test_real_manager_registered_copy_and_cleanup(bound, tmp_path):
    module = pytest.importorskip("sandbox_manager", reason="optional Manager package is not installed")
    # A package placeholder is copied as data, not launched. No WSB/Guest here.
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"inert package fixture")
    real = module.SandboxManager(tmp_path / "sessions-root")
    manager = InputBoundManager(real, bound.authority, bound.action, (bound.binding,))
    session = manager.prepare("SES-REAL-COPY", "RT-REAL-COPY", 1, runner)
    try:
        assert session.state == "PREPARED"
        assert session.guest_input_paths == [bound.binding.guest_path]
        assert (session.input_dir / bound.path.name).read_bytes() == bound.path.read_bytes()
        assert session.input_files[0]["sha256"] == bound.action.sources[1].sha256
        assert "PRIVATE" not in session.input_files[0]["source"]
    finally:
        manager.cleanup(session)
    assert not session.input_dir.exists()


def test_real_manager_refuses_change_between_registration_and_copy(bound, tmp_path, monkeypatch):
    module = pytest.importorskip("sandbox_manager", reason="optional Manager package is not installed")
    from sandbox_manager.errors import SandboxManagerError
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"inert package fixture")
    real = module.SandboxManager(tmp_path / "sessions-root")
    manager = InputBoundManager(real, bound.authority, bound.action, (bound.binding,))
    original = shutil.copyfile

    def change_at_copy(src, dst, **kwargs):
        if Path(src) == bound.path:
            bound.path.write_text("changed after registration", encoding="utf-8")
        return original(src, dst, **kwargs)

    monkeypatch.setattr(shutil, "copyfile", change_at_copy)
    with pytest.raises(SandboxManagerError, match="changed since it was registered"):
        manager.prepare("SES-CHANGED-COPY", "RT-CHANGED-COPY", 1, runner)
    assert not (real.root / "sessions" / "SES-CHANGED-COPY").exists()
