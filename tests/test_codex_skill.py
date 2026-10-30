"""The team Codex skill (codex/skills/secure-sandbox-run) only names tools and options this Host has."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "codex" / "skills" / "secure-sandbox-run" / "SKILL.md"
EXAMPLE = ROOT / "codex" / "config.example.toml"


def test_skill_has_codex_front_matter():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---\nname: \"secure-sandbox-run\"\ndescription: ")
    assert text.index("\n---\n", 4) > 0


def test_every_tool_the_skill_names_exists_in_the_host_schema():
    tools = {json.loads(p.read_text(encoding="utf-8"))["name"] for p in (ROOT / "schema" / "mcp-tools").glob("*.json")}
    named = set(re.findall(r"`([a-z]+_[a-z_]+)`", SKILL.read_text(encoding="utf-8")))
    not_tools = {"downloads_copy", "scrp_reconnect",          # a result field and an MCP server name
                 "source_url", "source_id", "after_mark"}     # router_capture arguments and result field
    assert named - not_tools <= tools, named - not_tools - tools


def test_config_example_uses_options_the_host_accepts():
    conf = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))["mcp_servers"]["scrp"]
    options = [a for a in conf["args"] if a.startswith("--")]
    assert options == ["--runner-exe", "--inbox", "--save-downloads", "--agent-guard", "--shared",
                       "--artifact-export", "--artifact-scanner", "--sandbox-run", "--router-capture"]
    source = (ROOT / "host" / "mcp_server.py").read_text(encoding="utf-8")
    for option in options:
        assert f'"{option}"' in source, option
