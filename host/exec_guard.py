"""Agent hook (Codex and Claude Code PreToolUse): outside programs and code do not run on this PC.

The SCRP origin rule ("code from outside runs only in the Sandbox", team Skill secure-sandbox-run) lived
only in the prompt, so an Agent that was talked out of it by a page or a file could run anything here.
This hook sees every shell command and file edit the Agent is about to make, BEFORE it runs, and decides
by fixed rules, whatever the model was told. Standard library only, plus host/signature_check.py.

Blocked, each with a reason that names the SCRP tool to use instead:
  outside-file  running, copying or unpacking a program, script or archive that came from outside:
                it has the internet mark (Zone.Identifier ZoneId>=3) or sits in Downloads or the SCRP
                inbox. Exception: an .exe/.msi whose signature passes host/signature_check.py (the same
                rule as --signed-downloads). Read-only looks (hash, signature, listing, reading) pass.
  fetch-run     downloading and running in one command: iwr|iex, curl | sh, DownloadString, mshta http,
                regsvr32 /i:http, msiexec from a URL, powershell -EncodedCommand.
  guard         editing this hook, the Agent's hook/config/rules files, or turning Defender off or
                adding Defender exclusions.

Code the Agent writes itself and the user's own project are not judged (team origin rule).
Limits: this reads command text. Obfuscated commands can get past it, so it is one layer: files from
outside still land in the deny-execute inbox. Every block is appended to the log.

  hook:     <python> host/exec_guard.py [--inbox DIR]... [--log FILE]      (JSON on stdin)
  install:  <python> host/exec_guard.py install [--codex] [--claude] [--inbox DIR]...
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# The hook starts once per Agent command, so it imports only what every call needs (argparse, zipfile,
# shutil, datetime and dataclasses cost about 0.5 s on a PC whose antivirus scans each module file).

REPO = Path(__file__).resolve().parents[1]
HOME = Path(os.environ.get("USERPROFILE") or Path.home())
DOWNLOADS = HOME / "Downloads"
DEFAULT_LOG = Path(os.environ.get("LOCALAPPDATA") or HOME) / "SCRP" / "exec_guard.jsonl"

SHELL_TOOLS = {"bash", "powershell", "shell", "exec_command"}
EDIT_TOOLS = {"apply_patch", "edit", "write", "multiedit", "notebookedit"}
# Programs and scripts: running one of these from outside is what the Sandbox is for.
RUNNABLE = {".exe", ".msi", ".msix", ".appx", ".com", ".scr", ".pif", ".cpl", ".dll", ".sys", ".bat", ".cmd",
            ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url",
            ".reg", ".jar", ".py", ".pyw", ".rb", ".pl", ".php", ".sh", ".msp", ".appref-ms"}
ARCHIVES = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso", ".img", ".vhd", ".vhdx"}
SIGNED_OK = {".exe", ".msi"}
# Segments that only look at a file: a hash, a signature, a listing or its text.
READ_ONLY = {"get-filehash", "get-item", "gi", "get-itemproperty", "get-childitem", "gci", "dir", "ls", "test-path",
             "get-authenticodesignature", "get-content", "gc", "cat", "type", "more", "select-string", "sls",
             "findstr", "head", "tail", "wc", "file", "stat", "sha256sum", "sha1sum", "md5sum", "sigcheck",
             "sigcheck64", "format-hex", "get-acl", "write-output", "echo", "rg", "grep"}
SEGMENT_SPLIT = re.compile(r"\|\||&&|[;|\n]")

FETCH = re.compile(r"\b(iwr|irm|invoke-webrequest|invoke-restmethod|curl(\.exe)?|wget|start-bitstransfer|bitsadmin)\b"
                   r"|downloadstring|downloaddata|downloadfile|net\.webclient|certutil(\.exe)?\b[^\n]*-urlcache", re.I)
RUN_FETCHED = re.compile(
    r"\b(iex|invoke-expression)\b|scriptblock\]::create"
    r"|\|\s*(sudo\s+)?(ba|z|da)?sh\b"                              # | sh, | bash
    r"|\|\s*(python3?|py|node|ruby|perl|php|pwsh|powershell)(\.exe)?\s*(-\s*|-c\s*)?($|[;&|\n])", re.I)
ALONE = [
    ("encoded PowerShell command", re.compile(r"\b(powershell|pwsh)(\.exe)?\b[^\n]*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}", re.I)),
    ("mshta with a URL or script", re.compile(r"\bmshta(\.exe)?\s+[\"']?(https?|vbscript|javascript):", re.I)),
    ("regsvr32 loading a remote script", re.compile(r"\bregsvr32(\.exe)?\b[^\n]*/i:\s*[\"']?https?://", re.I)),
    ("rundll32 running script or a URL", re.compile(r"\brundll32(\.exe)?\b[^\n]*(javascript:|https?://)", re.I)),
    ("msiexec installing from a URL", re.compile(r"\bmsiexec(\.exe)?\b[^\n]*/(i|package|a)\s*[\"']?https?://", re.I)),
]
SINK = re.compile(r"\b(iex|invoke-expression)\b|scriptblock\]::create|\|\s*(sudo\s+)?(ba|z|da)?sh\b"
                  r"|\|\s*(python3?|py|node|ruby|perl|php|pwsh|powershell|cmd)(\.exe)?\b", re.I)
DEFENDER_OFF = re.compile(r"\b(set|add)-mppreference\b[^\n]*-(disable\w*|exclusion\w*)"
                          r"|\b(sc(\.exe)?|stop-service|set-service)\b[^\n]*\bwindefend\b", re.I)


def protected_files() -> list[Path]:
    return [Path(__file__).resolve(), HOME / ".codex" / "hooks.json", HOME / ".codex" / "config.toml",
            HOME / ".codex" / "rules", HOME / ".codex" / "requirements.toml", HOME / ".claude" / "settings.json",
            HOME / ".claude" / "settings.local.json"]


def _norm(p) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def _under(path: Path, root: Path) -> bool:
    a, b = _norm(path), _norm(root)
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


class Decision:
    __slots__ = ("allow", "rule", "reason", "detail")

    def __init__(self, allow: bool, rule: str = "", reason: str = "", detail: str = ""):
        self.allow, self.rule, self.reason, self.detail = allow, rule, reason, detail


ALLOW = Decision(True)


def deny(rule: str, reason: str, detail: str = "") -> Decision:
    return Decision(False, rule, reason, detail)


# --------------------------------------------------------------------- where a file came from
def zone_id(path: Path) -> int | None:
    try:
        with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="replace") as f:
            m = re.search(r"^ZoneId\s*=\s*(\d+)", f.read(), re.M)
        return int(m.group(1)) if m else None
    except OSError:
        return None


def outside_origin(path: Path, inboxes: list[Path]) -> str | None:
    """Why this file counts as from outside, or None."""
    for box in inboxes:
        if _under(path, box):
            return "it is in the SCRP inbox"
    z = zone_id(path)
    if z is not None and z >= 3:
        return "it carries the internet mark (Zone.Identifier)"
    if _under(path, DOWNLOADS):
        return "it is in the Downloads folder"
    return None


def _expand(token: str, cwd: Path) -> Path | None:
    t = token.strip().strip("\"'`").rstrip(",)")
    if not t or t.startswith("-") or "://" in t:
        return None
    t = re.sub(r"\$env:(\w+)", lambda m: os.environ.get(m.group(1), m.group(0)), t, flags=re.I)
    t = re.sub(r"\$(HOME|home)\b", str(HOME).replace("\\", "\\\\"), t)
    t = os.path.expandvars(t)
    if t.startswith("~"):
        t = str(HOME) + t[1:]
    m = re.match(r"^/([a-zA-Z])/(.*)$", t)                    # Git Bash /c/Users/...
    if m:
        t = f"{m.group(1)}:\\{m.group(2)}"
    p = Path(t)
    return p if p.is_absolute() else cwd / p


def _tokens(segment: str) -> list[str]:
    return re.findall(r'"[^"]*"|\'[^\']*\'|[^\s"\'<>(){}=]+', segment)


def files_in(segment: str, cwd: Path) -> list[Path]:
    found = []
    for tok in _tokens(segment):
        p = _expand(tok, cwd)
        if p is None:
            continue
        try:
            if p.is_file():
                found.append(p)
        except OSError:
            continue
    return found


def _head(segment: str) -> str:
    toks = _tokens(segment.strip())
    while toks and toks[0].lower() in {"&", ".", "call", "start", "sudo", "cmd", "/c", "cmd.exe"}:
        if toks[0].lower() in {"cmd", "cmd.exe"} and len(toks) > 1 and toks[1].lower() == "/c":
            toks = toks[2:]
            continue
        toks = toks[1:]
    return toks[0].strip("\"'").lower() if toks else ""


WRITES = re.compile(r">|\b(out-file|set-content|add-content|tee|tee-object|sc|ac)\b", re.I)


def _read_only(segment: str) -> bool:
    return _head(segment) in READ_ONLY and not WRITES.search(segment)


def _archive_runs_code(path: Path) -> bool:
    import zipfile
    if path.suffix.lower() != ".zip":
        return True                                          # cannot look inside: treat as code
    try:
        with zipfile.ZipFile(path) as z:
            return any(Path(n).suffix.lower() in RUNNABLE | ARCHIVES for n in z.namelist())
    except (OSError, zipfile.BadZipFile):
        return True


# --------------------------------------------------------------------- the rules
def judge_command(command: str, cwd: Path, inboxes: list[Path], signature=None) -> Decision:
    text = command or ""
    if FETCH.search(text) and RUN_FETCHED.search(text):
        return deny("fetch-run", "This command downloads code and runs it on this PC. Code from outside runs only "
                    "in the Sandbox: get the file with inbox_download, then sandbox_run (or router_capture / "
                    "router_execute for a command a web page gave).", text[:200])
    for what, pattern in ALONE:
        if pattern.search(text):
            return deny("fetch-run", f"Blocked: {what}. This is how web pages and attackers get code run on a PC "
                        "(MITRE ATT&CK T1204.004, T1218). Use router_capture / router_execute to run it in the Sandbox.",
                        text[:200])
    if DEFENDER_OFF.search(text):
        return deny("guard", "Turning Microsoft Defender off or adding exclusions is not allowed for the Agent.", text[:200])
    segments = [s for s in SEGMENT_SPLIT.split(text) if s.strip()]
    flat = text.lower().replace("/", "\\")
    for p in protected_files():
        # Written as a full path, through %USERPROFILE%/$env:USERPROFILE/~, or by the file name for the hook.
        tail = os.path.relpath(p, HOME).lower() if _under(p, HOME) and p.name != Path(__file__).name else p.name.lower()
        if (_norm(p) in _norm(text) or tail in flat) and not all(_read_only(s) for s in segments):
            return deny("guard", f"{p.name} keeps the Agent's safety settings (SCRP exec guard). The Agent "
                        "must not change it; ask the person at this computer.", str(p))
    # Reading a file is harmless unless the text goes on into something that runs it (Get-Content x | iex).
    sink = bool(SINK.search(text))
    for segment in segments:
        if _read_only(segment) and not sink:
            continue
        for path in files_in(segment, cwd):
            suffix = path.suffix.lower()
            if suffix not in RUNNABLE | ARCHIVES:
                continue
            origin = outside_origin(path, inboxes)
            if origin is None:
                continue
            if suffix in ARCHIVES and not _archive_runs_code(path):
                continue
            if suffix in SIGNED_OK:
                verdict = _signature(path, signature)
                if verdict.get("trusted"):
                    continue
                why = f"its signature did not pass ({verdict.get('reason')})"
            else:
                why = "only signed .exe/.msi programs from outside may run here"
            return deny("outside-file", f"{path.name} came from outside ({origin}) and {why}. Run it in the Sandbox: "
                        "inbox_import (a file already in Downloads) or inbox_download, then sandbox_run. Unpacking "
                        "or copying it does not change where it came from.", str(path))
    return ALLOW


def _signature(path: Path, signature) -> dict:
    try:
        if signature is None:
            sys.path.insert(0, str(REPO))
            from host.signature_check import check as signature
        return signature(path).to_dict()
    except Exception as e:  # noqa: BLE001 - no verdict means not trusted
        return {"trusted": False, "reason": f"signature check failed: {type(e).__name__}"}


def patch_targets(patch: str, cwd: Path) -> list[Path]:
    names = re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+?)\s*$|^\*\*\* Move to: (.+?)\s*$", patch or "", re.M)
    return [_expand(a or b, cwd) for a, b in names if (a or b)]


def judge_edit(paths: list[Path]) -> Decision:
    guarded = protected_files()
    for p in paths:
        if p is None:
            continue
        for g in guarded:
            if _under(p, g):
                return deny("guard", f"{g.name} keeps the Agent's safety settings (SCRP exec guard). The Agent must "
                            "not change it; ask the person at this computer.", str(p))
    return ALLOW


def judge(event: dict, inboxes: list[Path], signature=None) -> Decision:
    tool = str(event.get("tool_name") or "")
    args = event.get("tool_input") or {}
    cwd = Path(event.get("cwd") or os.getcwd())
    name = tool.lower()
    if name in SHELL_TOOLS:
        command = args.get("command") if isinstance(args, dict) else args
        if isinstance(command, list):
            command = " ".join(map(str, command))
        return judge_command(str(command or ""), cwd, inboxes, signature)
    if name in EDIT_TOOLS:
        if name == "apply_patch":
            return judge_edit(patch_targets(str(args.get("command") or args.get("input") or ""), cwd))
        target = args.get("file_path") or args.get("notebook_path") or args.get("path")
        return judge_edit([_expand(str(target), cwd)] if target else [])
    return ALLOW


def log(path: Path, event: dict, d: Decision) -> None:
    import datetime as _dt
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"time": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                                "session": event.get("session_id"), "tool": event.get("tool_name"),
                                "cwd": event.get("cwd"), "rule": d.rule, "detail": d.detail[:512]},
                               ensure_ascii=False) + "\n")
    except OSError:
        pass


def run_hook(argv: list[str], stdin=sys.stdin, stdout=sys.stdout, signature=None) -> int:
    inboxes, log_file, rest = [], DEFAULT_LOG, list(argv)
    while rest:
        flag, value = rest.pop(0), (rest.pop(0) if rest else "")
        if flag == "--inbox":
            inboxes.append(Path(value))
        elif flag == "--log":
            log_file = Path(value)
    try:
        event = json.loads(stdin.read() or "{}")
        d = judge(event, inboxes, signature)
    except Exception as e:  # noqa: BLE001 - a guard that cannot decide does not let the call through
        event, d = {}, deny("guard-error", f"SCRP exec guard could not check this call ({type(e).__name__}); "
                            "it was not run. Tell the person at this computer.", repr(e))
    if d.allow:
        return 0
    log(log_file, event, d)
    stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                    "permissionDecisionReason": d.reason}}, ensure_ascii=False))
    stdout.flush()
    return 0


# --------------------------------------------------------------------- install
def hook_command(python: Path, inboxes: list[Path]) -> str:
    # -S: no site-packages (the hook needs only the standard library), about 0.15 s less per command.
    parts = [f'"{python}"', "-S", f'"{Path(__file__).resolve()}"'] + [f'--inbox "{p}"' for p in inboxes]
    return " ".join(parts)


def _merge(path: Path, entry: dict, marker: str, root_key: str) -> Path | None:
    """Put `entry` into PreToolUse of a JSON settings file, replacing an older entry of ours. Returns the backup."""
    import datetime as _dt
    import shutil
    data, backup = {}, None
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
        backup = path.with_name(path.name + ".bak-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, backup)
    hooks = data.setdefault(root_key, {})
    pre = [e for e in hooks.get("PreToolUse", []) if marker not in json.dumps(e)]
    hooks["PreToolUse"] = pre + [entry]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return backup


def install(argv: list[str], home: Path = HOME) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="exec_guard install")
    ap.add_argument("--codex", action="store_true", help="~/.codex/hooks.json")
    ap.add_argument("--claude", action="store_true", help="~/.claude/settings.json")
    ap.add_argument("--inbox", type=Path, action="append", default=[], help="the SCRP inbox (repeatable)")
    # The real interpreter, not a venv's python.exe redirector (which starts a second process).
    ap.add_argument("--python", type=Path, default=Path(getattr(sys, "_base_executable", sys.executable)))
    a = ap.parse_args(argv)
    if not (a.codex or a.claude):
        ap.error("choose --codex and/or --claude")
    command = hook_command(a.python, a.inbox)
    handler = {"type": "command", "command": command, "timeout": 30}
    marker = "exec_guard.py"
    if a.codex:
        entry = {"matcher": "^(Bash|apply_patch)$", "hooks": [dict(handler, commandWindows=command)]}
        b = _merge(home / ".codex" / "hooks.json", entry, marker, "hooks")
        print(f"Codex: {home / '.codex' / 'hooks.json'}" + (f" (backup {b})" if b else ""))
        print("  Codex runs a new hook only after you trust it: CLI /hooks, or the app's Settings > Hooks.")
    if a.claude:
        entry = {"matcher": "Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit", "hooks": [handler]}
        b = _merge(home / ".claude" / "settings.json", entry, marker, "hooks")
        print(f"Claude Code: {home / '.claude' / 'settings.json'}" + (f" (backup {b})" if b else ""))
    print("Restart the Agent so it loads the hook.")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["install"]:
        return install(argv[1:])
    return run_hook(argv)


if __name__ == "__main__":
    sys.exit(main())
