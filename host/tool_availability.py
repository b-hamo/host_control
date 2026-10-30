"""Which tools a session may see (spec B-11). Standard library only.

Kept apart from tool_catalog.py so the MCP Server can build its tool list
without importing jsonschema: Codex drops MCP servers that take longer than
about half a second to answer (ADR-002).
"""

from __future__ import annotations

# Which runtime capability (from HELLO, granted in HELLO_ACK) each tool needs.
REQUIRED_CAPABILITY = {
    "computer_observe": "gui.observe",
    "computer_move": "gui.input",
    "computer_click": "gui.input",
    "computer_scroll": "gui.input",
    "computer_type": "gui.input",
    "computer_keypress": "gui.input",
    "computer_hotkey": "gui.input",
    "computer_click_element": "ui.automation",
    # Only sessions that selected artifact-export-v1 are granted this (host/artifacts.py).
    "artifact_list": "artifact.export.v1",
    "artifact_export": "artifact.export.v1",
    # A Host feature, not a Runtime capability: only when the Host runs with --inbox.
    "inbox_download": "host.inbox",
    "inbox_import": "host.inbox",          # a file already in the user's Downloads
    "inbox_finish": "host.inbox",          # keep chosen files in Downloads, empty the inbox
    # Host feature too (--sandbox-run): runs inbox downloads inside the Sandbox, with approval.
    "sandbox_run": "host.sandbox_run",
    "sandbox_run_status": "host.sandbox_run",
    # Host feature (--router-capture, #94): web page commands as data, analyzed only in the Sandbox.
    "router_capture": "host.router",
    "router_execute": "host.router",
}
# Tools whose backend is not built yet. Hidden rather than failing late (B-11).
NOT_YET_AVAILABLE: dict[str, str] = {}


def unavailable_reason(name: str, granted: set[str]) -> str | None:
    if name in NOT_YET_AVAILABLE:
        return NOT_YET_AVAILABLE[name]
    need = REQUIRED_CAPABILITY.get(name)
    if need and need not in granted:
        return f"this runtime was not granted {need}"
    return None
