"""Claude Code support: the integrated install registers the same Host with Claude Code, and the team Skill
installs into Claude Code's skills folder (installer/register_claude.ps1, codex/install_skill.ps1 -Agent)."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from host.solution_config import CLAUDE_NAME, register_claude, render_profile_claude, render_profile_mcp

ROOT = Path(__file__).resolve().parent.parent
windows = pytest.mark.skipif(sys.platform != "win32", reason="PowerShell installers")


def profile(tmp_path):
    return tmp_path / "state" / "solution.json", {"host_repo": str(ROOT)}


def test_claude_gets_the_same_stdio_host_as_codex(tmp_path):
    path, prof = profile(tmp_path)
    server = render_profile_claude(path, prof)
    assert server["type"] == "stdio" and server["command"] == "powershell.exe"
    assert server["args"][-3:] == ["-Stdio", "-State", str(path.parent)]
    assert str(ROOT / "scripts" / "start_solution.ps1") in server["args"]
    assert server["env"] == {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    assert json.dumps(server["args"], ensure_ascii=False) in render_profile_mcp(path, prof)   # Codex: same command


def test_registration_replaces_only_our_user_scope_entry(tmp_path):
    path, prof = profile(tmp_path)
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="Added", stderr="")
    exe = register_claude(render_profile_claude(path, prof), claude="claude.exe", run=run)
    assert exe == "claude.exe"
    assert calls[0] == ["claude.exe", "mcp", "remove", "--scope", "user", CLAUDE_NAME]
    assert calls[1][:5] == ["claude.exe", "mcp", "add-json", "--scope", "user"] and calls[1][5] == CLAUDE_NAME
    assert json.loads(calls[1][6]) == render_profile_claude(path, prof)


def test_registration_failures_are_reported(tmp_path, monkeypatch):
    path, prof = profile(tmp_path)
    bad = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="Invalid configuration")  # noqa: E731
    with pytest.raises(ValueError, match="Invalid configuration"):
        register_claude(render_profile_claude(path, prof), claude="claude.exe", run=bad)
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ValueError, match="Claude Code CLI"):
        register_claude(render_profile_claude(path, prof))


def test_the_installer_offers_claude_registration():
    install = (ROOT / "installer" / "install_solution.ps1").read_text(encoding="utf-8-sig")
    assert "[switch]$RegisterClaude" in install and "register_claude.ps1" in install
    script = (ROOT / "installer" / "register_claude.ps1").read_text(encoding="utf-8-sig")
    assert "'--register-claude'" in script


@windows
@pytest.mark.parametrize("agent, folders", [("Claude", [".claude"]), ("Both", [".codex", ".claude"]),
                                            ("Codex", [".codex"])])
def test_the_skill_installs_where_each_agent_reads_it(tmp_path, agent, folders):
    env = dict(os.environ, USERPROFILE=str(tmp_path))
    out = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                          str(ROOT / "codex" / "install_skill.ps1"), "-Agent", agent],
                         capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    src = (ROOT / "codex" / "skills" / "secure-sandbox-run" / "SKILL.md").read_bytes()
    for name in (".codex", ".claude"):
        dst = tmp_path / name / "skills" / "secure-sandbox-run" / "SKILL.md"
        assert dst.exists() == (name in folders)
        if dst.exists():
            assert dst.read_bytes() == src
