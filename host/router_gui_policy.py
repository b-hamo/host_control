"""Opt-in Host policy for an exact, delegated Guest command launch sequence.

This does not alter the default Policy. Trusted Host composition must explicitly
select this policy and enable command launches. Ordinary MCP calls still follow
the base policy; a DENY from any other base rule remains a DENY. There is no
keyword/LLM risk classifier and no alternate path after a refused input.
"""

import asyncio
from contextlib import contextmanager
from copy import deepcopy

from host.policy import Decision, Policy
from host.router_authority import Authority
from router.models import Action, EXECUTION


class RouterGuiPolicy:
    def __init__(self, authority: Authority, *, base=None, command_launch_enabled=False):
        self.authority = authority
        self.base = base if base is not None else Policy()
        self.command_launch_enabled = command_launch_enabled
        # Runner binds ACTION_REQUEST to its fixed POL-0.1.0 wire profile.
        # The Router decision extension has its own revision; inventing another
        # wire version is not negotiation and is correctly rejected by Runner.
        self.version = self.base.version
        self.revision = "router-exact-launch-v1"
        self._owner = None
        self._action = None
        self._steps = ()
        self._next = 0

    @contextmanager
    def launch(self, action: Action, launch_line: str):
        """Host command driver only. ``launch_line`` must come from its renderer.

        The driver owns binding this transport line to action.command and verified
        Guest helper/input bytes. Never expose this method as an Agent/MCP tool.
        Consumption happens before dispatch; cancellation/timeout cannot replay a
        step within this lease. The driver/Host ledger also prevents a new lease
        for an already-dispatched request.
        """
        if self._owner is not None:
            raise ValueError("another command launch is in progress")
        if (not self.command_launch_enabled or action.operation not in EXECUTION
                or not {"gui.input", "gui.observe", "process.execute"} <= set(action.scope.capabilities)
                or self.authority.check(action) != "ALLOW"):
            raise ValueError("Guest command launch is not authorized")
        if not isinstance(launch_line, str) or not launch_line or any(c in launch_line for c in "\r\n\0"):
            raise ValueError("one exact launch line required")
        self._owner, self._action = asyncio.current_task(), action
        self._steps = (
            ("computer_hotkey", {"keys": ["win", "r"]}),
            ("computer_type", {"text": launch_line}),
            ("computer_keypress", {"key": "enter"}),
        )
        self._next = 0
        try:
            yield
        finally:
            self._owner = self._action = None
            self._steps, self._next = (), 0

    def decide(self, tool, args):
        if self._owner is None or not tool.startswith("computer_") or tool == "computer_observe":
            return self.base.decide(tool, args)
        deny = Decision("DENY", "P-ROUTER-LAUNCH-BOUNDARY", "input does not match the active command launch")
        if (asyncio.current_task() is not self._owner or self._next >= len(self._steps)
                or (tool, args) != self._steps[self._next]):
            return deny
        first, final = self._next == 0, self._next == 2
        self._next += 1
        # Revalidate immediately before Enter, which crosses the execution boundary.
        # This is content/delegation equality, not per-click risk classification.
        if final:
            try:
                if self.authority.check(self._action) != "ALLOW":
                    return deny
            except Exception:
                return deny
        base = self.base.decide(tool, deepcopy(args))
        if (first and type(self.base) is Policy and base.result == "DENY"
                and base.rule_id == "P-DENY-HOTKEY"):
            if tool in self.base.require_approval_for:
                return Decision("REQUIRE_APPROVAL", "P-APPROVE-SENSITIVE", "command launch needs user approval")
            return Decision("ALLOW", "P-ROUTER-EXACT-COMMAND", "Host delegated this exact Guest command launch")
        if base.result == "DENY":
            self._next = len(self._steps)
        return base
