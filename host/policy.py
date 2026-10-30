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

# Sent in every ACTION_REQUEST. The Runner binds its input grant to exactly this value
# (sandbox_runner src/host_gui.cpp, POL-0.1.1 since sandbox_runner #32) and refuses any other,
# so both sides change together; RouterGuiPolicy reports this same version (router_gui_policy.py).
POLICY_VERSION = "POL-0.1.1"

# Key combinations that open an admin or security surface. Since POL-0.1.1 (team decision,
# 2026-10-13) Win+R is allowed: the Agent may open the Run dialog inside the Sandbox itself.
# A sandbox_run still types only its own approved line while it holds the launch.
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
        if tool == "inbox_finish":
            if args.get("keep"):
                return Decision("REQUIRE_APPROVAL", "P-INBOX-KEEP", "keeps files from the Sandbox inbox on this computer")
            return Decision("ALLOW", "P-INBOX-FINISH", "empties the Sandbox inbox; keeps nothing")
        if tool == "inbox_import":
            return Decision("ALLOW", "P-INBOX-IMPORT", "a file the user already has, copied into the Sandbox inbox; "
                            "never run on the Host")
        if tool == "inbox_download":
            # Team decision 2026-10-08: no approval. The file only ever runs inside the Sandbox;
            # every download is audited (URL, final URL, SHA-256).
            return Decision("ALLOW", "P-INBOX-DOWNLOAD", "into the Sandbox inbox; never run on the Host")
        if tool == "sandbox_run":
            # Team decision 2026-10-13: running inside the disposable Sandbox needs no approval.
            # People approve where a file crosses to this computer instead (artifact_export,
            # inbox_finish keep). The run is still bound to the Host's own download record and
            # exact command, and its source, command and receipt are recorded.
            return Decision("ALLOW", "P-SANDBOX-RUN", "runs a received file inside the Sandbox only; recorded")
        if tool == "router_capture":
            # #94: stores web page text as untrusted data; opens nothing, runs nothing.
            return Decision("ALLOW", "P-ROUTER-CAPTURE", "records web page text as untrusted data; runs nothing")
        if tool == "router_execute":
            # #94: same rule as sandbox_run. The script derived from a capture runs inside the
            # Sandbox only, bound to the SHA-256 of the capture and of the script.
            return Decision("ALLOW", "P-ROUTER-EXECUTE", "analyzes a captured command inside the Sandbox only; recorded")
        if tool in self.require_approval_for:
            return Decision("REQUIRE_APPROVAL", "P-APPROVE-SENSITIVE", f"{tool} needs user approval")
        return Decision("ALLOW", "P-ALLOW-DEFAULT", "no rule restricts this call")
