"""Central policy for tool calls (spec B-5, B-8).

Every call gets a Decision before it runs: ALLOW, REQUIRE_APPROVAL or DENY,
with the id of the rule that decided it, so the audit log can say why.
The spec also lists ALLOW_WITH_MONITORING / FORCE_SANDBOX / FORCE_VM; those
choose *where* work runs and belong to the Translator's runtime routing
(WBS 7.x, 8.8), so they are not produced here yet.

These rules are an initial set, meant to be extended, not a finished policy.
"""

from __future__ import annotations

from dataclasses import dataclass

POLICY_VERSION = "POL-0.1.1"

# Key combinations that open admin or security surfaces.
# Win+R is allowed so tasks can open the Run dialog inside the Sandbox.
DENIED_HOTKEYS = {
    frozenset({"win", "x"}): "opens the admin power-user menu",
    frozenset({"ctrl", "alt", "delete"}): "opens the Windows security screen",
    frozenset({"ctrl", "shift", "escape"}): "opens Task Manager",
}


@dataclass(frozen=True)
class Decision:
    result: str          # ALLOW / REQUIRE_APPROVAL / DENY
    rule_id: str
    reason: str


class Policy:
    version = POLICY_VERSION

    def __init__(self, require_approval_for: tuple[str, ...] = ("artifact_export",)):
        # Spec B-6/B-8: sensitive tools need a separate, per-action approval.
        self.require_approval_for = set(require_approval_for)

    def decide(self, tool: str, args: dict) -> Decision:
        if tool == "computer_hotkey":
            combo = frozenset(args["keys"])
            for denied, why in DENIED_HOTKEYS.items():
                if denied <= combo:
                    return Decision("DENY", "P-DENY-HOTKEY", f"{'+'.join(args['keys'])} {why}")
        if tool in self.require_approval_for:
            return Decision("REQUIRE_APPROVAL", "P-APPROVE-SENSITIVE", f"{tool} needs user approval")
        return Decision("ALLOW", "P-ALLOW-DEFAULT", "no rule restricts this call")
