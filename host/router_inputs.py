"""Bind Host-verified Router sources to Sandbox Manager's read-only input API.

Construct this adapter in the trusted Host composition code, then pass it as the
manager to SandboxLauncher/HostBackend. The Agent cannot supply Host paths here.
No file is evaluated. The Manager still owns copying, hash revalidation, mappings,
launch and cleanup. A separate command driver must verify actual Guest execution.
"""

from dataclasses import dataclass
import hashlib
import ntpath
from pathlib import Path, PureWindowsPath

from host.router_authority import Authority
from router.models import Action, EXECUTION, identifier


@dataclass(frozen=True)
class InputBinding:
    source_id: str
    host_path: Path

    def __post_init__(self):
        identifier(self.source_id)
        if not isinstance(self.host_path, Path) or not self.host_path.is_absolute():
            raise ValueError("absolute Host input path required")
        name = self.host_path.name
        win = PureWindowsPath(name)
        if (not name or win.name != name or ":" in name or name.endswith((".", " "))
                or ntpath.isreserved(name)):
            raise ValueError("invalid Guest input filename")

    @property
    def guest_path(self) -> str:
        # sandbox_manager.config.GUEST_INPUT contract; no caller-selected mapping.
        return str(PureWindowsPath(r"C:\UserFiles") / self.host_path.name)


class InputBoundManager:
    """One immutable execution's input set; unrelated work needs another instance.

    ``register_input`` is injectable for contract tests. Production defaults to
    the installed Manager's registrar, whose InputFile freezes size/hash/source.
    """

    def __init__(self, manager, authority: Authority, action: Action,
                 bindings: tuple[InputBinding, ...], *, register_input=None):
        if (action.operation not in EXECUTION or type(bindings) is not tuple or not bindings
                or any(not isinstance(b, InputBinding) for b in bindings)):
            raise ValueError("execution and immutable input bindings required")
        sources = {s.source_id: s for s in action.sources}
        ids = [b.source_id for b in bindings]
        names = [b.host_path.name.casefold() for b in bindings]
        if len(set(ids)) != len(ids) or len(set(names)) != len(names):
            raise ValueError("duplicate input source or Guest filename")
        if action.command.target_source not in ids or not set(ids) <= sources.keys():
            raise ValueError("input source missing from execution provenance")
        if any(b.guest_path not in action.scope.reads for b in bindings):
            raise ValueError("input path missing from delegated read scope")
        target = next(b for b in bindings if b.source_id == action.command.target_source)
        if target.guest_path not in (action.command.executable, *action.command.argv):
            raise ValueError("exact command does not reference the bound execution target")
        self.manager, self.authority, self.action = manager, authority, action
        self.bindings = bindings
        self._register_input = register_input
        self._prepared = None

    def __getattr__(self, name):
        # Preserve the Manager lifecycle contract, including stop/cleanup/recovery.
        return getattr(self.manager, name)

    @staticmethod
    def _plain_file(path):
        # Check the whole chain, not just the leaf. Do not resolve away a link.
        for part in (path, *path.parents):
            st = part.lstat()
            if part.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked input path is not allowed")
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("input must be a single-link regular file")

    def _authorize(self):
        if self.authority.check(self.action) != "ALLOW":
            raise ValueError("input authorization requires reassessment")

    def prepare(self, session_id, runtime_id, generation, runner_exe):
        self._authorize()
        register = self._register_input
        if register is None:
            from sandbox_manager.inputs import register_input
            register = register_input
        sources = {s.source_id: s for s in self.action.sources}
        registered = []
        for binding in self.bindings:
            self._plain_file(binding.host_path)
            source = sources[binding.source_id]
            # Manager persists this field. Keep URL credentials/query secrets in
            # the private Authority registry, linked by source ID and content hash.
            entry = register(binding.host_path, source=f"router-source:{source.source_id}:{source.sha256}")
            if entry.sha256 != source.sha256:
                raise ValueError("input content changed since Host validation")
            registered.append(entry)
        self._authorize()
        session = self.manager.prepare(session_id, runtime_id, generation, runner_exe,
                                       input_files=registered)
        try:
            # Detect incompatible Manager versions rather than silently executing
            # against a different location or a writable/custom mapping.
            if list(session.guest_input_paths) != [b.guest_path for b in self.bindings]:
                raise ValueError("Manager Guest input paths do not match the approved command")
            self._authorize()
        except BaseException:
            # prepare has not started a Guest. Reuse Manager's own cleanup rules.
            self.manager.cleanup(session)
            raise
        self._prepared = session
        return session

    def start(self, session):
        if session is not self._prepared:
            raise ValueError("session was not prepared for this execution")
        self._authorize()
        sources = {s.source_id: s for s in self.action.sources}
        for binding in self.bindings:
            copied = session.input_dir / binding.host_path.name
            self._plain_file(copied)
            with copied.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual != sources[binding.source_id].sha256:
                raise ValueError("prepared input changed before Sandbox start")
        return self.manager.start(session)
