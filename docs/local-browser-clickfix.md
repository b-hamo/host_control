# Local browser → clipboard → Sandbox execution

The workflow server is an opt-in composition of RouterService, Authority and
HostGateway. It is separate from the existing general GUI MCP deployment. No
AGENTS.md or mail adapter is needed for this browser path.

## Contract

- `router_gui`: an owned local Edge tab, scoped HTTPS navigation, screenshots and
  pointer clicks against an observation ID. No keyboard, shell, arbitrary CDP,
  JavaScript evaluation, or desktop input tool is exposed.
- `router_clipboard_read`: actual Windows Unicode clipboard captured after a
  Router browser click changed its sequence. An unrelated or subsequently changed
  clipboard is rejected. Source text is stored with SHA-256 and external origin.
- `router_execute`: captured data is bound to a read-only Guest input, with exact
  source hashes, command, delegation and execution receipt. There is no Host
  execution location parameter. All execution operations are Sandbox operations.
- `auto_analyze_clipboard: true`: a successful Router click that changes the
  clipboard starts a Host-owned continuation after the click job completes. It
  registers a clipboard action, verifies its captured source, submits Sandbox
  analysis and polls through inspected completion. No client clipboard, execute,
  status or result call is required to start or finish analysis. The click result's
  `analysis.request_id` identifies the analysis; `analysis.state` may initially be
  PENDING. Explicit clipboard result reads also retain the earlier auto-analysis
  behavior. This is not a system-wide clipboard monitor.
- Unsupported command syntax is held. Plain `powershell[.exe] -Command "..."`
  with NoProfile/NoExit/NonInteractive switches and full `-EncodedCommand` UTF-16LE
  bodies are supported. NoExit is removed for batch completion. Command semantics
  are not guessed through Host evaluation. Other interpreters need separate
  adapters; benign-looking commands are never granted Host execution.
- Repeated request IDs return the existing execution; conflicting reuse is denied.
  Repeated clipboard capture auto-analysis is deduplicated by sequence and hash.

## Operator configuration

Run `python -m host.router_workflow_server --config <absolute JSON path>` with
Host and Manager installed, or the workspace's `scripts/launch_router_workflow.py`.

```json
{
  "directory": "C:/SCRP/runs/new-run",
  "origins": ["https://your-authorized-test-site.example"],
  "runner_exe": "C:/SCRP/sandbox_runner.exe",
  "sandbox_root": "C:/SCRP/sandbox",
  "allow_gui": true,
  "allow_execution": true,
  "auto_analyze_clipboard": true
}
```

The run directory must not exist. `mailbox` is optional. Origin scope is supplied
by the operator, never widened by page instructions. The browser profile and
captured files stay in the run directory. Call `router_stop` to close this owned
browser and Sandbox; preserved evidence remains on Host. The MCP connection stays
alive: a fresh work request ID creates a new workflow after confirmed cleanup.
Old request IDs always address their original workflow and never replay. Queries
alone never start a workflow or VM. A cleanup failure blocks replacement.

Within an active workflow, multiple commands run sequentially through
InteractiveRuntime, each with its own exact delegation, immutable input binding,
output name and receipt. An unfinished or UNKNOWN execution blocks the next
command until the session is stopped. Closing the Sandbox retires that workflow;
it does not automatically recreate it. A new explicit work request can then start
a fresh session. Previously captured external sources may be reused only after
hash validation; derived sources cannot be resubmitted as external input.

This retains the existing per-workflow request/resource limits. It is not unlimited
parallel execution. The upstream RouterConnection profile/catalog remains a
separate entrypoint. Installation state does not persist across VM termination.

## Desktop chat connection

The workspace `.codex/config.toml` adds the required `scrp_router` stdio server
using `scripts/launch_router_chat.py`. The launcher reads operator policy from
`config/router-chat.json` and creates a new directory under `runtime/router-chat`
per connection. The existing `scrp_sandbox` connection stays unchanged.

At the user's choice, the project disables the Browser plugin and the
unified-computer-use `cua_repl` MCP server. Legacy Node browser backends are empty;
general Node, native-app, shell, mail and development tooling are retained.
These are supported client configuration controls, not an AGENTS.md instruction
or a pattern-matching prompt hook. They take effect on a freshly resolved client
connection, not retroactively on the tool snapshot of an active turn.

Reconnect/restart the desktop app and reopen this workspace/chat. Verify Router
tools are present and direct browser tools are absent before declaring the chat
transition complete. A parser/effective-config check and a separate stdio test
do not establish that an existing chat has refreshed its tools. Existing shell
and native-desktop privileges remain outside this browser-MCP restriction.

Updating these Python modules requires one MCP server reload for an already
running old process. After that deployment reload, stopping and starting tasks
does not require MCP reconnects. No live code injection or process hot patching
is performed.

## Boundaries and remaining work

This is enforcement for tools owned by Router, not an OS policy on other Host
tools. It does not prevent unrelated shell/MCP clients, a malicious local process,
browser exploits, or the user manually pasting into Run. The browser runs webpage
JavaScript normally. CDP network interception checks HTTPS request origins and
redirects; browser downloads are denied and new pages are closed while paused.
Direct custom-protocol navigation is refused. Website-triggered OS protocol
handlers and browser-native dialogs need dedicated adversarial validation before
claiming all browser-mediated Host execution is prevented.

Clipboard sequence plus click timing is correlation, not cryptographic proof of
the writer; concurrent writes by another Host program remain a limitation.
Only an owned fresh Edge profile is controlled, not existing signed-in tabs.
Supported command conversion, capture tampering, unavailable Sandbox, and source
binding have automated tests. Live harmless CAPTCHA evidence is maintained in the
workspace runbook. This is not a malware detection-rate or network-containment
assessment. Sandbox network is not disabled by this change.
