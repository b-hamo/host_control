"""Repository rules (AGENTS.md "규칙"): a fact kept in two places must say the same thing in both.

The MCP tool list, the error hints, the package boundaries, PowerShell encodings and the
module tables in the READMEs can each drift without any other test failing.
Every failure message names what to change.
"""

import ast
import json
import os
import re
from pathlib import Path

import pytest

from host.broker import COORDINATE_TOOLS, ERROR_HINTS, OPERATIONS, RUNTIME_TOOLS
from host.policy import DENIED_HOTKEYS
from host.tool_availability import NOT_YET_AVAILABLE, REQUIRED_CAPABILITY

ROOT = Path(__file__).resolve().parents[1]
TOOL_DIR = ROOT / "schema" / "mcp-tools"
TOOLS = {json.loads(p.read_text(encoding="utf-8"))["name"] for p in TOOL_DIR.glob("*.json")}
HOST_MODULES = sorted((ROOT / "host").glob("*.py"))

# Codes that reach the Agent without an ERROR_HINTS entry yet. Say why; delete the entry once fixed.
KNOWN_HINT_GAPS = {
    "SCANNER_UNAVAILABLE": "artifacts.py raises it with retryable=True, but BrokerError takes retryable "
                           "from ERROR_HINTS only, so the Agent is told retryable=false",
}

# package -> (top-level packages it must not import, modules allowed anyway, why)
BOUNDARIES = {
    "router": ({"host", "scanner_service"}, set(),
               "router/ is the Router core and knows nothing of the Host; its adapters are host/router_*.py"),
    "scrp": ({"host", "router", "scanner_service"}, set(),
             "scrp/ is the protocol library every other package shares"),
    "scanner_service": ({"host", "router"}, {"host.artifact_scan"},
                        "the scanner is its own Windows service and PyInstaller bundles whatever it imports"),
}
# Layer ④ of host/README.md, and the layers above it.
TRANSPORT = ["bootstrap", "connection", "observation_store", "session_registry", "tls", "upload_server"]
ABOVE_TRANSPORT = {"host.mcp_server", "host.mcp_runtime", "host.broker", "host.policy", "host.tool_catalog",
                   "host.tool_availability", "host.approval", "host.audit"}
SKIPPED_DIRS = {".git", ".venv", "__pycache__", "build", "dist", "node_modules"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _tool_literals(path: Path) -> list[tuple[str, int]]:
    """Strings a variable named `tool` is compared with: tool == "x", tool in ("x", "y")."""
    found = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "tool":
            for right in node.comparators:
                found += [(c.value, c.lineno) for c in ast.walk(right)
                          if isinstance(c, ast.Constant) and isinstance(c.value, str)]
    return found


def _imports(path: Path) -> set[str]:
    """Every module a file imports, lazy imports inside functions included."""
    found = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found |= {node.module} | {f"{node.module}.{alias.name}" for alias in node.names}
    return found


def _under(name: str, modules: set[str]) -> bool:
    return any(name == m or name.startswith(m + ".") for m in modules)


def test_host_code_names_only_real_tools():
    wrong = [f"{_rel(p)}:{line} {name!r}" for p in HOST_MODULES
             for name, line in _tool_literals(p) if name not in TOOLS]
    assert not wrong, f"compared with a tool name schema/mcp-tools/ does not define (typo or renamed tool): {wrong}"


def test_tool_tables_name_only_real_tools():
    tables = {"host/broker.py OPERATIONS": set(OPERATIONS), "host/broker.py COORDINATE_TOOLS": COORDINATE_TOOLS,
              "host/broker.py RUNTIME_TOOLS": RUNTIME_TOOLS,
              "host/tool_availability.py REQUIRED_CAPABILITY": set(REQUIRED_CAPABILITY),
              "host/tool_availability.py NOT_YET_AVAILABLE": set(NOT_YET_AVAILABLE)}
    wrong = {where: sorted(names - TOOLS) for where, names in tables.items() if names - TOOLS}
    assert not wrong, f"these tables name tools schema/mcp-tools/ does not define: {wrong}"


def test_every_tool_is_handled_by_the_broker():
    named = set(OPERATIONS) | {name for name, _ in _tool_literals(ROOT / "host" / "broker.py")}
    missing = sorted(TOOLS - named)
    assert not missing, (f"schema/mcp-tools/ defines {missing} but host/broker.py never handles them: add each "
                         "to OPERATIONS and translate(), or give it a branch in Broker._dispatch()")


def test_denied_hotkeys_use_keys_the_tool_accepts():
    schema = json.loads((TOOL_DIR / "computer_hotkey.json").read_text(encoding="utf-8"))
    accepted = set(schema["inputSchema"]["properties"]["keys"]["items"]["enum"])
    unknown = sorted({key for combo in DENIED_HOTKEYS for key in combo} - accepted)
    assert not unknown, (f"DENIED_HOTKEYS in host/policy.py uses {unknown}, which computer_hotkey cannot send, so "
                         "the rule never matches: use the key names in schema/mcp-tools/computer_hotkey.json")


def _passed_through() -> set[str]:
    """BrokerError, plus every exception Broker re-raises as BrokerError(e.code, ...)."""
    classes = {"BrokerError"}
    for handler in ast.walk(_tree(ROOT / "host" / "broker.py")):
        if isinstance(handler, ast.ExceptHandler) and handler.name and isinstance(handler.type, ast.Name):
            for node in ast.walk(handler):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "BrokerError"
                        and node.args and isinstance(code := node.args[0], ast.Attribute) and code.attr == "code"
                        and isinstance(code.value, ast.Name) and code.value.id == handler.name):
                    classes.add(handler.type.id)
    return classes


def _codes_raised(classes: set[str]) -> dict[str, list[str]]:
    """Literal error codes these exception classes are raised with anywhere in host/."""
    codes: dict[str, list[str]] = {}
    for path in HOST_MODULES:
        for node in ast.walk(_tree(path)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in classes
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                codes.setdefault(node.args[0].value, []).append(f"{_rel(path)}:{node.lineno}")
    return codes


def test_every_error_the_agent_sees_has_a_hint():
    codes = _codes_raised(_passed_through())
    missing = {code: where for code, where in codes.items() if code not in ERROR_HINTS and code not in KNOWN_HINT_GAPS}
    assert not missing, ("without an ERROR_HINTS entry in host/broker.py the Agent always gets retryable=false and "
                         f"no recommended_next_step unless the raise site gives one; add these codes: {missing}")
    stale = sorted(code for code in KNOWN_HINT_GAPS if code in ERROR_HINTS or code not in codes)
    assert not stale, f"{stale} is fixed or no longer raised: remove it from KNOWN_HINT_GAPS"


@pytest.mark.parametrize("package", sorted(BOUNDARIES))
def test_packages_import_in_one_direction(package):
    forbidden, allowed, why = BOUNDARIES[package]
    wrong = {}
    for path in sorted((ROOT / package).glob("*.py")):
        bad = sorted(n for n in _imports(path) if n.split(".")[0] in forbidden and not _under(n, allowed))
        if bad:
            wrong[_rel(path)] = bad
    assert not wrong, f"{why}; these imports cross that line: {wrong}"


def test_transport_layer_does_not_import_the_layers_above():
    wrong = {f"host/{m}.py": sorted(n for n in _imports(ROOT / "host" / f"{m}.py") if _under(n, ABOVE_TRANSPORT))
             for m in TRANSPORT}
    wrong = {path: names for path, names in wrong.items() if names}
    assert not wrong, ("layer 4 of host/README.md sits under the Broker and MCP layers; pass in what it needs "
                       f"instead of importing upward: {wrong}")


def _repo_files(suffix: str) -> list[Path]:
    found = []
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS and not d.startswith(".pytest")]
        found += [Path(folder, f) for f in files if f.endswith(suffix)]
    return sorted(found)


def test_powershell_scripts_with_non_ascii_text_have_a_bom():
    wrong = [_rel(p) for p in _repo_files(".ps1")
             if not (data := p.read_bytes()).startswith(b"\xef\xbb\xbf") and not data.isascii()]
    assert not wrong, ("Windows PowerShell 5.1, the PowerShell inside the Sandbox, reads a .ps1 without a BOM in "
                       f"the ANSI code page and garbles non-ASCII text; save these as UTF-8 with BOM: {wrong}")


@pytest.mark.parametrize("doc", ["README.md", "host/README.md"])
def test_tool_counts_in_docs_match_the_schema(doc):
    lines = (ROOT / doc).read_text(encoding="utf-8").splitlines()
    wrong = [f"{doc}:{n} {m.group(0)}" for n, line in enumerate(lines, 1)
             for m in re.finditer(r"도구 (\d+)개", line) if int(m.group(1)) != len(TOOLS)]
    assert not wrong, f"schema/mcp-tools/ has {len(TOOLS)} tools; update the count: {wrong}"


@pytest.mark.parametrize("package", ["host", "scanner_service"])
def test_every_module_has_a_row_in_its_readme(package):
    readme = (ROOT / package / "README.md").read_text(encoding="utf-8")
    missing = sorted(p.name for p in (ROOT / package).glob("*.py") if p.name != "__init__.py" and p.name not in readme)
    assert not missing, f"{package}/README.md says nothing about {missing}: add a row saying what each one does"


def test_agents_md_points_at_files_that_exist():
    text = re.sub(r"```.*?```", "", (ROOT / "AGENTS.md").read_text(encoding="utf-8"), flags=re.S)
    paths = [t for t in re.findall(r"`([^`\s]+)`", text) if "/" in t or re.search(r"\.(py|md|json|ps1|toml|txt)$", t)]
    missing = [t for t in paths if not (any(ROOT.glob(t)) if "*" in t else (ROOT / t).exists())]
    assert not missing, f"AGENTS.md points at paths that do not exist (moved or renamed?): {missing}"
