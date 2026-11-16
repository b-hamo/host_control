"""② project zips (배주한 2026-11-05): a downloaded project is installed, built and run inside the Sandbox.

- the Host reads only the zip's names; the recipe comes from the project's marker files, not the Agent
- unsafe names, unsupported projects and missing entries are refused before anything runs
- the Guest script waits for the zip (SHA-256), and becomes the run's input derived from the zip
"""

import asyncio
import hashlib
import zipfile
from types import SimpleNamespace

import pytest

from host.broker import Broker, BrokerError
from host.sandbox_project import ProjectError, inspect, script
from host.sandbox_run import POWERSHELL, SandboxRunner
from test_sandbox_run import ID

SHARED = {n: {"exe": rf"C:\Tools\{n}\{n}.exe", "guest_root": rf"C:\Tools\{n}", "path": [rf"C:\Tools\{n}"], "env": {}}
          for n in ("python", "node", "go", "dotnet", "gcc", "ruby", "java")}


def make_zip(tmp_path, files, name="proj-main.zip", top="proj-main/"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as z:
        for rel, text in files.items():
            z.writestr(top + rel, text)
    return path


@pytest.mark.parametrize("files, entry, kind, marker", [
    ({"go.mod": "", "main.go": ""}, None, "go", "go.mod"),
    ({"package.json": "{}", "index.js": ""}, None, "node", "package.json"),
    ({"App.csproj": "", "Program.cs": ""}, None, "dotnet", "App.csproj"),
    ({"CMakeLists.txt": "", "src/main.cpp": ""}, None, "cmake", "CMakeLists.txt"),
    ({"Gemfile": "", "bin/main.rb": ""}, "bin/main.rb", "ruby", "Gemfile"),
    ({"requirements.txt": "", "app/main.py": ""}, "app/main.py", "python", "requirements.txt"),
    ({"src/Main.java": ""}, "src/Main.java", "java", None),
    ({"Cargo.toml": "", "build.rs": "", "src/main.rs": ""}, None, "rust", "Cargo.toml")])
def test_the_recipe_comes_from_the_projects_marker_files(tmp_path, files, entry, kind, marker):
    p = inspect(make_zip(tmp_path, files), entry, [])
    assert (p.kind, p.marker, p.root) == (kind, marker, "proj-main")


@pytest.mark.parametrize("files, entry", [
    ({"Cargo.toml": "", "src/main.rs": ""}, "src/main.rs"),   # Rust: entry is a binary name, not a file
    ({"Makefile": "", "main.c": ""}, None),                   # make: not installed
    ({"README.md": ""}, None),                                # nothing known
    ({"requirements.txt": "", "main.py": ""}, None),          # python needs an entry
    ({"requirements.txt": "", "main.py": ""}, "other.py"),    # not in the project
    ({"requirements.txt": "", "main.py": ""}, "../main.py")])
def test_unsupported_projects_and_bad_entries_are_refused(tmp_path, files, entry):
    with pytest.raises(ProjectError) as e:
        inspect(make_zip(tmp_path, files), entry, [])
    assert e.value.code == "INVALID_ARGUMENT"


def test_a_go_entry_folder_with_its_own_module_becomes_the_root(tmp_path):
    p = inspect(make_zip(tmp_path, {"go.mod": "", "hello/go.mod": "", "hello/hello.go": ""}), "hello", [])
    assert (p.root, p.entry, p.marker) == ("proj-main/hello", None, "hello/go.mod")
    p = inspect(make_zip(tmp_path, {"go.mod": "", "cmd/app/main.go": ""}, name="b.zip"), "cmd/app", [])
    assert (p.root, p.entry) == ("proj-main", "cmd/app")


def test_an_unsafe_entry_name_in_the_zip_is_refused(tmp_path):
    with pytest.raises(ProjectError) as e:
        inspect(make_zip(tmp_path, {"../evil.txt": "", "go.mod": ""}, top=""), None, [])
    assert e.value.code == "POLICY_DENIED"


def test_the_script_waits_for_the_zip_and_runs_the_fixed_recipe(tmp_path):
    p = inspect(make_zip(tmp_path, {"requirements.txt": "x", "app/main.py": ""}), "app/main.py", ["a b", "it's"])
    text = script(p, "proj-main.zip", "ab" * 32, "n1", {"python": SHARED["python"]})
    assert "'" + "ab" * 32 + "'" in text and "tar.exe" in text and "Project-n1" in text
    steps = [ln for ln in text.splitlines() if ln.startswith("Invoke-Step ")]
    assert [s.split("'")[1] for s in steps] == ["make a venv", "pip install -r requirements.txt", "run python app/main.py"]
    assert steps[-1].endswith("""'app\\main.py "a b" it''s' $true""")       # one PowerShell string, quotes doubled


def test_the_project_script_becomes_the_runs_input(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    z = make_zip(inbox, {"package.json": "{}", "index.js": ""})
    runner = SandboxRunner(inbox)
    runner.register({"final_url": "https://github.com/x/proj/archive/main.zip",
                     "file": {"name": z.name, "size": z.stat().st_size, "sha256": hashlib.sha256(z.read_bytes()).hexdigest()}})
    run, shown = runner.plan(z.name, [], ID)
    assert shown["project"] == "node" and run.project is not None
    runner.with_project(run, {"node": SHARED["node"]})
    s, parent = run.action.sources
    assert s.source_id == "DL-0001-PROJECT" and s.parents == ("DL-0001",) and parent.source_id == "DL-0001"
    assert run.action.command.executable == POWERSHELL and run.action.command.argv[-1].endswith("proj-main-project.ps1")
    assert (inbox / "proj-main-project.ps1").is_file() and run.project is None


def test_the_broker_lends_every_tool_or_refuses(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    z = make_zip(inbox, {"go.mod": "", "main.go": ""})
    runner = SandboxRunner(inbox)
    runner.register({"final_url": "https://x/p.zip",
                     "file": {"name": z.name, "size": z.stat().st_size, "sha256": hashlib.sha256(z.read_bytes()).hexdigest()}})
    run, _ = runner.plan(z.name, [], ID)
    with pytest.raises(BrokerError) as e:
        asyncio.run(Broker._prepare_project(SimpleNamespace(programs=False, runner=runner), run))
    assert e.value.code == "POLICY_DENIED"

    class Launcher:
        asked = []

        async def share_program(self, name):
            self.asked.append(name)
            return SHARED[name]
    broker = SimpleNamespace(programs=True, runner=runner, launcher=Launcher())
    asyncio.run(Broker._prepare_project(broker, run))
    assert Launcher.asked == ["go"] and run.project is None


def test_a_rust_project_fetches_rust_inside_the_sandbox_and_lends_nothing(tmp_path):
    """배주한 2026-11-12 (가): this PC's Rust (MSVC) cannot be lent, so the Sandbox fetches rustup (GNU)
    with its .sha256 into its own TEMP, then cargo builds and runs there (build.rs runs only there)."""
    p = inspect(make_zip(tmp_path, {"Cargo.toml": "", "src/main.rs": ""}), "demo", ["a b"])
    assert (p.kind, p.programs, p.entry) == ("rust", (), "demo")
    text = script(p, "proj-main.zip", "ab" * 32, "n1", {})
    order = ["'download rustup'", "'download rustup checksum'", "'check rustup checksum' '#sha256'",
             "'install Rust (GNU, minimal)'", "'cargo build --release'", "'run cargo --bin demo'"]
    at = [text.index(o) for o in order]
    assert at == sorted(at)
    assert "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe" in text
    assert "--default-host x86_64-pc-windows-gnu" in text and "--profile minimal" in text
    assert "%TEMP%\\rustup" in text and "%TEMP%\\cargo" in text      # never this PC's ~/.rustup
    assert 'run --release --quiet --bin demo -- "a b"' in text
