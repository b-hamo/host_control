"""One lazy, replaceable execution Host behind a long-lived stdio MCP connection.

Only a new explicit task can replace a retired session. Queries and GUI calls
never replay a task or reclaim another process's ports.
"""
from __future__ import annotations

import copy
import json
import threading
from uuid import uuid4


def success(**body):
    return {"content": [{"type": "text", "text": json.dumps({"ok": True, **body})}], "isError": False}


class McpRuntime:
    ident = None

    def __init__(self, args, factory):
        self.args, self.factory = args, factory
        self.backend = None
        self._lock = threading.RLock()
        self._serial = 0
        self._closed = False

    def is_alive(self):
        return False

    def start(self):
        """MCP initialize is discovery, not permission to claim ports."""

    def shutdown(self):
        with self._lock:
            self._closed = True
            if self.backend is not None:
                self.backend.shutdown()

    def call(self, tool, arguments):
        from host.mcp_server import _error_result
        from host.tool_catalog import ToolCatalog, ToolError

        try:
            args = ToolCatalog().validate(tool, arguments)
        except ToolError as exc:
            return _error_result(exc.code, exc.message, False, "fix_arguments")
        with self._lock:
            if self._closed:
                return _error_result("SESSION_TERMINATED", "MCP connection closed", False, None)
            backend = self.backend
            retired = backend is not None and (not backend.is_alive() or
                       (backend.session is not None and backend.session.terminated))
            if retired:
                # Wait for cleanup before reporting stop or allowing another start.
                try:
                    backend.shutdown()
                except TimeoutError:
                    return _error_result("CLEANUP_UNCONFIRMED", "Host cleanup is still pending", False,
                                         "runtime_get_state")
                if not backend.cleanup_confirmed:
                    return _error_result("CLEANUP_UNCONFIRMED", backend.error or "Sandbox cleanup failed", False,
                                         "runtime_get_state")
                if tool == "runtime_get_state":
                    return self._state(args)
                if tool == "session_stop":
                    return success(stopped=True, reason=args["reason"], host_released=True)
                if tool != "task_submit":
                    return _error_result("SESSION_TERMINATED", "Submit a new task before using this runtime",
                                         False, "task_submit")
                backend = None
            if backend is None:
                if tool == "runtime_get_state":
                    return self._state(args)
                if tool == "session_stop":
                    return success(stopped=True, reason=args["reason"], host_released=True)
                if tool.startswith("computer_"):
                    return _error_result("POLICY_DENIED", "Call task_submit first", False, "task_submit")
                self._serial += 1
                config = copy.copy(self.args)
                config.session = (self.args.session if self._serial == 1 and self.args.session else
                                  f"SES-{uuid4().hex}")
                # A competing start must not rewrite another session's certificate
                # or purge its in-flight artifact uploads before a bind fails.
                config.cert_dir = self.args.cert_dir / config.session
                if getattr(self.args, "artifact_dir", None) is not None:
                    config.artifact_dir = self.args.artifact_dir / config.session
                backend = self.backend = self.factory(config)
                backend.retire_on_end = True
                backend.start()
            result = backend.call(tool, args)
            if tool == "session_stop" and not result["isError"]:
                try:
                    backend.shutdown()
                except TimeoutError:
                    return _error_result("CLEANUP_UNCONFIRMED", "Host cleanup is still pending", False,
                                         "runtime_get_state")
                if not backend.cleanup_confirmed:
                    return _error_result("CLEANUP_UNCONFIRMED", backend.error or "Sandbox cleanup failed", False,
                                         "runtime_get_state")
                return success(stopped=True, reason=args["reason"], host_released=True)
            return result

    def _state(self, args):
        from host.mcp_server import _error_result
        status = (self.backend.final_status or {}) if self.backend else {}
        wanted = args["action_id"]
        actions = status.get("actions", {})
        if wanted is not None and wanted not in actions:
            return _error_result("INVALID_ARGUMENT", "Unknown action in this session", False, "fix_arguments")
        state = actions.get(wanted)
        if state in {"SENT", "PENDING", "ACCEPTED", "RUNNING"}:
            state = "UNKNOWN"
        return success(runtime_state=status.get("state", "START_FAILED" if self.backend else "NOT_STARTED"), connected=False,
                       health=status.get("health", "UNKNOWN"), source="host", host_released=True,
                       session_id=status.get("session_id"), end_reason=status.get("end_reason"),
                       host_error=self.backend.error if self.backend else None,
                       action={"action_id": wanted, "status": state} if wanted else None)
