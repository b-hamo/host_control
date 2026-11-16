"""Agent hook (Codex and Claude Code PreToolUse + PostToolUse): outside programs and code do not run on this PC.

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
  outside-project  building or running a project the Agent downloaded (git clone, gh repo clone): its folder
                carries an origin mark, and python/npm/make/dotnet/... there, or a script in it, is refused.
  ask           outside code of a kind the Sandbox cannot run yet (Maven, Gradle, Ant, make, PHP, VBScript,
                Visual Studio C++): the person at this computer decides. Claude Code: permissionDecision "ask"
                (its own prompt). Codex runs a call whose hook answered "ask" (not supported there yet), so with
                --agent codex the hook shows its own Windows dialog and waits: Yes runs it, No, closing it or
                no answer in ASK_SECONDS denies. No --agent: deny.
  guard         editing this hook, the Agent's hook/config/rules files, turning Defender off or adding Defender
                exclusions, or removing an origin mark (Unblock-File, Zone.Identifier, scrp-origin.json).

After each shell command (PostToolUse) the hook marks what that command downloaded, so the rules above see it:
`git clone` and `gh repo clone` leave no internet mark, and curl/wget/iwr -OutFile copies may not either.
  file      a download target (curl -o/-O, wget, iwr/irm -OutFile, Start-BitsTransfer, bitsadmin, certutil)
            gets the internet mark Zone.Identifier ZoneId=3 with its URL.
  project   a cloned folder gets .git/scrp-origin.json and .scrp-origin.json (source URL, time), and its
            programs, scripts and archives get ZoneId=3. The marks are what the rules check; this step never blocks.

Code the Agent writes itself and the user's own project are not judged (team origin rule).
The rules are logic in this file, not instructions: a model talked out of the team Skill still meets them.
Limits: this reads command text. Obfuscated commands can get past it, so it is one layer: files from
outside still land in the deny-execute inbox. Every block is appended to the log.

  hook:     <python> host/exec_guard.py [--agent codex|claude] [--inbox DIR]... [--log FILE]   (JSON on stdin)
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
# Builds or runs the project it is pointed at (or the current folder): inside a downloaded project that runs
# outside code (setup.py, package.json scripts, Makefiles, build.rs, MSBuild targets ...).
PROJECT_RUN = {"python", "python3", "py", "pythonw", "node", "npm", "npx", "yarn", "pnpm", "bun", "deno", "pip",
               "pip3", "uv", "uvx", "poetry", "pipenv", "pytest", "tox", "nox", "conda", "jupyter", "cargo", "rustc",
               "go", "dotnet", "msbuild", "make", "nmake", "mingw32-make", "cmake", "ninja", "meson", "mvn", "gradle",
               "gradlew", "ant", "ruby", "bundle", "rake", "gem", "java", "javac", "perl", "php", "composer", "gcc",
               "g++", "clang", "cl", "tsc", "ts-node", "start-process", "saps", "invoke-item", "ii", "wscript",
               "cscript", "rundll32", "regsvr32", "mshta"}
# Wrappers in front of the real command: powershell -NoProfile -File x.ps1, cmd /c build.bat, bash -c "...".
WRAPPERS = {"&", ".", "call", "start", "sudo", "cmd", "cmd.exe", "/c", "/k", "powershell", "powershell.exe", "pwsh",
            "pwsh.exe", "bash", "bash.exe", "sh", "-c", "-command", "-file", "-noprofile", "-nologo",
            "-noninteractive", "-executionpolicy", "bypass", "unrestricted", "remotesigned", "-windowstyle", "hidden"}
CD = {"cd", "chdir", "set-location", "sl", "pushd"}
ORIGIN_MARK = "scrp-origin.json"          # <clone>/.git/scrp-origin.json (git clean leaves .git alone) and
                                          # <clone>/.scrp-origin.json (deleting .git leaves this one)
MARK_TAMPER = re.compile(r"\bunblock-file\b|zone\.identifier|scrp-origin", re.I)
REMOTE = re.compile(r"^(https?://|git@[\w.-]+:|ssh://|git://)", re.I)
URL = re.compile(r"^(https?|ftp)://", re.I)
MARK_LIMIT = 20000
# Outside code the Sandbox cannot run yet (no recipe in host/sandbox_project.py, no engine in its Windows).
UNSUPPORTED = {"mvn": "Maven", "gradle": "Gradle", "gradlew": "Gradle", "ant": "Ant", "make": "make", "nmake": "make",
               "mingw32-make": "make", "php": "PHP", "composer": "PHP", "cscript": "VBScript", "wscript": "VBScript",
               "devenv": "Visual Studio C++"}
UNSUPPORTED_SUFFIX = {".vbs": "VBScript", ".vbe": "VBScript", ".php": "PHP"}                        # files looked at per clone; a huge clone still gets its folder mark
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
    __slots__ = ("allow", "rule", "reason", "detail", "ask")

    def __init__(self, allow: bool, rule: str = "", reason: str = "", detail: str = "", ask: str = ""):
        # reason: for the Agent (a deny). ask: for the person, when the Agent's app can ask them instead.
        self.allow, self.rule, self.reason, self.detail, self.ask = allow, rule, reason, detail, ask


ALLOW = Decision(True)


def deny(rule: str, reason: str, detail: str = "") -> Decision:
    return Decision(False, rule, reason, detail)


ASK_SECONDS = 90                          # under the Codex hook timeout (120 s): a hook killed there fails open


def ask_person(question: str, seconds: int = ASK_SECONDS) -> bool:
    """A Yes/No Windows dialog on this desktop, No by default. True only for a click on Yes."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes
    MB_YESNO, MB_ICONWARNING, MB_DEFBUTTON2, MB_SYSTEMMODAL, MB_SETFOREGROUND, MB_TOPMOST = (
        0x4, 0x30, 0x100, 0x1000, 0x10000, 0x40000)
    try:
        box = ctypes.WinDLL("user32", use_last_error=True).MessageBoxTimeoutW   # MessageBoxW with a time limit
        box.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT, wintypes.WORD,
                        wintypes.DWORD]
        box.restype = ctypes.c_int
        answer = box(None, question + f"\n\n({seconds}초 안에 답하지 않으면 실행하지 않습니다.)",
                     "minoBox - AI 에이전트 실행 확인",
                     MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST,
                     0, seconds * 1000)
    except (OSError, AttributeError):
        return False
    return answer == 6                                                           # IDYES


def unsupported(rule: str, name: str, source: str, kind: str, detail: str) -> Decision:
    """Outside code the Sandbox cannot run: the person decides (Claude Code), or is told to (Codex)."""
    reason = (f"{name} came from {source} and is {kind}, which the Sandbox cannot run yet, and outside code does "
              "not run on this PC. Tell the person at this computer: if they trust it, they can run it themselves "
              "in their own terminal. Do not try another route.")
    question = (f"[minoBox] {name}은(는) 밖({source})에서 온 {kind} 코드입니다. 격리 공간(Sandbox·micro VM)은 아직 "
                f"{kind}를 실행하지 못합니다. 허용하면 이 PC에서 내 권한으로 실행됩니다. 출처를 믿을 수 있을 때만 허용하세요.")
    return Decision(False, rule, reason, detail, question)


def _kind(stem: str, toks: list[str]) -> str | None:
    if stem in UNSUPPORTED:
        return UNSUPPORTED[stem]
    if stem == "msbuild" and any(t.lower().endswith((".vcxproj", ".sln")) for t in toks):
        return "Visual Studio C++"
    for t in toks[:2]:
        kind = UNSUPPORTED_SUFFIX.get(Path(t).suffix.lower())
        if kind:
            return kind
    return None


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


def origin_root(path: Path) -> Path | None:
    """The downloaded project (a folder with our origin mark) that `path` is in, or None."""
    try:
        start = path if path.is_dir() else path.parent
        for d in (start, *start.parents):
            if (d / ".git" / ORIGIN_MARK).is_file() or (d / ("." + ORIGIN_MARK)).is_file():
                return d
    except OSError:
        return None
    return None


def _source(project: Path) -> str:
    for mark in (project / ".git" / ORIGIN_MARK, project / ("." + ORIGIN_MARK)):
        try:
            return str(json.loads(mark.read_text(encoding="utf-8")).get("source") or "outside")
        except (OSError, ValueError, AttributeError):
            continue
    return "outside"


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


def _unq(token: str) -> str:
    return token.strip().strip("\"'`")


def _cd(segment: str, here: Path) -> Path | None:
    """The new folder when the segment is `cd X` (also inside powershell -c "cd X; ..."), else None."""
    toks = [_unq(t) for t in _tokens(segment)]
    while toks and toks[0].lower() in WRAPPERS:
        toks = toks[1:]
    if len(toks) >= 2 and toks[0].lower() in CD:
        args = [t for t in toks[1:] if not t.startswith("-")]
        return _expand(args[0], here) if args else None
    return None


def _project_run(segment: str, here: Path, pending: list) -> Decision | None:
    toks = [_unq(t) for t in _tokens(segment)]
    while toks and toks[0].lower() in WRAPPERS:
        toks = toks[1:]
    if not toks:
        return None

    def came_from(p: Path):
        for target, url in pending:                 # downloaded earlier in this same command
            if _under(p, target):
                return target, url
        project = origin_root(p)
        return (project, _source(project)) if project is not None else None

    name = Path(toks[0]).name.lower()
    stem = re.sub(r"\.(exe|cmd|bat|ps1)$", "", name)
    places = []
    if stem in PROJECT_RUN:
        places.append(here)
        places += [p for p in (_expand(t, here) for t in toks[1:]) if p is not None]
    else:
        p = _expand(toks[0], here)                 # ./configure, .\run.ps1, build.sh after bash
        if p is not None and (p.is_file() or any(_under(p, t) for t, _ in pending)):
            places.append(p)
    for p in places:
        found = came_from(p)
        if found is not None:
            project, source = found
            kind = _kind(stem, toks)
            if kind:
                return unsupported("outside-project", project.name, source, kind, f"{segment.strip()[:200]} @ {project}")
            return deny("outside-project", f"{project.name} was downloaded from {source}; building or running it "
                        "runs outside code on this PC. Run it in the Sandbox: get it as one file (inbox_download; for "
                        "a repository its archive zip, e.g. https://github.com/<owner>/<repo>/archive/refs/heads/"
                        "<branch>.zip) and sandbox_run it (`entry` for a project). Reading its files is fine.",
                        f"{segment.strip()[:200]} @ {project}")
    return None


def judge_project(text: str, cwd: Path, depth: int = 0, pending: list | None = None) -> Decision | None:
    here, pending = cwd, list(pending or [])
    for segment in SEGMENT_SPLIT.split(text or ""):
        if not segment.strip():
            continue
        moved = _cd(segment, here)
        if moved is not None:
            here = moved
            continue
        if _read_only(segment):
            continue
        if depth < 2:                               # powershell -c "python main.py", bash -c '...'
            for tok in _tokens(segment):
                if tok[:1] in "\"'" and re.search(r"\s", tok):
                    d = judge_project(tok[1:-1], here, depth + 1, pending)
                    if d is not None:
                        return d
        d = _project_run(segment, here, pending)
        if d is not None:
            return d
        pending += [(target, url) for target, url, _ in downloads(segment, here, depth=2)]
    return None


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
    if MARK_TAMPER.search(text) and not all(_read_only(s) for s in segments):
        return deny("guard", "The internet mark (Zone.Identifier) and the SCRP origin mark say a file or project "
                    "came from outside. The Agent must not remove or change them; ask the person at this computer.",
                    text[:200])
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
            if suffix in UNSUPPORTED_SUFFIX:
                return unsupported("outside-file", path.name, origin, UNSUPPORTED_SUFFIX[suffix], str(path))
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
    return judge_project(text, cwd) or ALLOW


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
        if MARK_TAMPER.search(str(p)):
            return deny("guard", "The SCRP origin mark says a project came from outside. The Agent must not change "
                        "it; ask the person at this computer.", str(p))
        for g in guarded:
            if _under(p, g):
                return deny("guard", f"{g.name} keeps the Agent's safety settings (SCRP exec guard). The Agent must "
                            "not change it; ask the person at this computer.", str(p))
    return ALLOW


def _command(args) -> str:
    command = args.get("command") if isinstance(args, dict) else args
    if isinstance(command, list):
        command = " ".join(map(str, command))
    return str(command or "")


# --------------------------------------------------------------------- after the command: mark downloads
GIT_VALUE = {"-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference", "--reference-if-able",
             "--separate-git-dir", "-j", "--jobs", "--filter", "-u", "--upload-pack", "--template", "--shallow-since",
             "--shallow-exclude", "--server-option", "--bundle-uri"}
FETCHERS = {"curl", "wget", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "start-bitstransfer", "bitsadmin",
            "certutil"}


def _positional(args: list[str], takes_value: set[str]) -> list[str]:
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a.startswith("-") and len(a) > 1:
            i += 2 if a.lower() in takes_value else 1
            continue
        out.append(a)
        i += 1
    return out


def _basename(url: str) -> str:
    return re.split(r"[?#]", url)[0].rstrip("/").rsplit("/", 1)[-1]


def _fetch_target(name: str, args: list[str], here: Path) -> tuple[Path | None, str]:
    """Where a curl/wget/iwr/BITS/certutil call saves its file, and the URL."""
    urls = [a for a in args if URL.match(a)]
    url = urls[0] if urls else ""
    out, folder, remote = None, here, False
    i = 0
    while i < len(args):
        a, low = args[i], args[i].lower()
        nxt = args[i + 1] if i + 1 < len(args) else None
        if low in ("-outfile", "-destination", "--output", "--output-document") or (a == "-o" and name == "curl"):
            out, i = nxt, i + 2
            continue
        if low in ("--output-dir", "--directory-prefix") or (a == "-P" and name == "wget"):
            folder, i = (_expand(nxt, here) if nxt else here) or here, i + 2
            continue
        if low in ("--remote-name", "-remotename"):
            remote = True
        elif name in ("curl", "wget") and re.match(r"^-[A-Za-z]+$", a):
            flag = "o" if name == "curl" else "O"                       # curl -o FILE, wget -O FILE
            if flag in a[1:]:
                rest = a[1:][a[1:].index(flag) + 1:]
                if rest:
                    out = rest
                else:
                    out, i = nxt, i + 1
            if name == "curl" and "O" in a[1:]:
                remote = True
        i += 1
    if name == "bitsadmin" and url:
        tail = args[args.index(url) + 1:]
        out = tail[0] if tail else None
    elif name == "certutil" and url:
        tail = [a for a in args[args.index(url) + 1:] if not a.startswith("-")]
        out = tail[0] if tail else _basename(url)
    elif name == "start-bitstransfer" and out is None and url:
        tail = _positional(args[args.index(url) + 1:], {"-source", "-description", "-displayname"})
        out = tail[0] if tail else _basename(url)
    elif name == "wget" and out is None and url:
        out = _basename(url)
    if out is None and remote and url:
        out = _basename(url)
    if not out or out == "-":
        return None, url
    target = _expand(out, folder)
    if target is not None and target.is_dir() and url:
        target = target / _basename(url)
    return target, url


def downloads(command: str, cwd: Path, depth: int = 0) -> list[tuple[Path, str, bool]]:
    """(where, source URL, is a project) for each download a shell command makes."""
    found, here = [], cwd
    for segment in SEGMENT_SPLIT.split(command or ""):
        if not segment.strip():
            continue
        moved = _cd(segment, here)
        if moved is not None:
            here = moved
            continue
        raw = _tokens(segment)
        if depth < 2:
            for tok in raw:
                if tok[:1] in "\"'" and re.search(r"\s", tok):
                    found += downloads(tok[1:-1], here, depth + 1)
        toks = [_unq(t) for t in raw]
        names = [re.sub(r"\.exe$", "", Path(t).name.lower()) for t in toks]
        for i, name in enumerate(names):
            args = toks[i + 1:]
            if name == "git" and "clone" in args:
                base = here
                pre = args[:args.index("clone")]
                if "-C" in pre and pre.index("-C") + 1 < len(pre):
                    base = _expand(pre[pre.index("-C") + 1], here) or here
                pos = _positional(args[args.index("clone") + 1:], GIT_VALUE)
                if pos and REMOTE.match(pos[0]):
                    folder = pos[1] if len(pos) > 1 else re.sub(r"\.git$", "", re.split(r"[/:]", pos[0].rstrip("/"))[-1])
                    target = _expand(folder, base)
                    if target is not None:
                        found.append((target, pos[0], True))
                break
            if name == "gh" and args[:2] == ["repo", "clone"]:
                pos = _positional(args[2:], set())
                if pos:
                    spec = pos[0]
                    url = spec if REMOTE.match(spec) else f"https://github.com/{spec}"
                    folder = pos[1] if len(pos) > 1 else re.sub(r"\.git$", "", spec.rstrip("/").rsplit("/", 1)[-1])
                    target = _expand(folder, here)
                    if target is not None:
                        found.append((target, url, True))
                break
            if name in FETCHERS:
                target, url = _fetch_target(name, args, here)
                if target is not None:
                    found.append((target, url or "unknown", False))
                break
    return found


def _stamp(path: Path, url: str) -> bool:
    """Give `path` the internet mark unless it already has one. NTFS only."""
    if os.name != "nt":
        return False
    z = zone_id(path)
    if z is not None and z >= 3:
        return False
    try:
        with open(f"{path}:Zone.Identifier", "w", encoding="utf-8", newline="") as f:
            f.write(f"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={url}\r\n")
        return True
    except OSError:
        return False


def mark_project(project: Path, url: str) -> None:
    import datetime as _dt
    body = json.dumps({"source": url, "marked": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                       "by": "SCRP exec guard: downloaded by the Agent; build and run it only in the Sandbox"},
                      ensure_ascii=False, indent=2) + "\n"
    git = project / ".git"
    for mark in ([git / ORIGIN_MARK] if git.is_dir() else []) + [project / ("." + ORIGIN_MARK)]:
        try:
            mark.write_text(body, encoding="utf-8")
        except OSError:
            pass
    exclude = git / "info" / "exclude"                    # keep git status clean in the user's view
    try:
        if git.is_dir() and "." + ORIGIN_MARK not in (exclude.read_text(encoding="utf-8") if exclude.exists() else ""):
            exclude.parent.mkdir(parents=True, exist_ok=True)
            with exclude.open("a", encoding="utf-8") as f:
                f.write("\n." + ORIGIN_MARK + "\n")
    except OSError:
        pass
    seen = 0
    for folder, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            seen += 1
            if seen > MARK_LIMIT:
                return
            if Path(name).suffix.lower() in RUNNABLE | ARCHIVES:
                _stamp(Path(folder) / name, url)


def mark_downloads(command: str, cwd: Path) -> list[Path]:
    """Mark what `command` downloaded. Returns the files and projects that now carry a mark."""
    marked = []
    for target, url, project in downloads(command, cwd):
        try:
            if project and target.is_dir():
                mark_project(target, url)
                marked.append(target)
            elif target.is_file():
                _stamp(target, url)
                marked.append(target)
        except OSError:
            continue
    return marked


def after_tool(event: dict, log_file: Path, stdout) -> int:
    """PostToolUse: never blocks (the command already ran); marks its downloads so the next call is judged."""
    try:
        if str(event.get("tool_name") or "").lower() not in SHELL_TOOLS:
            return 0
        marked = mark_downloads(_command(event.get("tool_input") or {}), Path(event.get("cwd") or os.getcwd()))
    except Exception as e:  # noqa: BLE001 - marking is best effort; the PreToolUse rules still apply
        log(log_file, event, Decision(True, "mark-error", "", repr(e)))
        return 0
    if marked:
        log(log_file, event, Decision(True, "marked", "", "; ".join(map(str, marked))))
        note = ("SCRP marked what this command downloaded as from outside: " + ", ".join(p.name for p in marked)
                + ". Do not build, install or run it on this PC; run it in the Sandbox (inbox_download of the "
                "file or the repository's archive zip, then sandbox_run). Reading it is fine.")
        stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": note}}))
        stdout.flush()
    return 0


def judge(event: dict, inboxes: list[Path], signature=None) -> Decision:
    tool = str(event.get("tool_name") or "")
    args = event.get("tool_input") or {}
    cwd = Path(event.get("cwd") or os.getcwd())
    name = tool.lower()
    if name in SHELL_TOOLS:
        return judge_command(_command(args), cwd, inboxes, signature)
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


def run_hook(argv: list[str], stdin=sys.stdin, stdout=sys.stdout, signature=None, asker=None) -> int:
    inboxes, log_file, agent, rest = [], DEFAULT_LOG, "", list(argv)
    while rest:
        flag, value = rest.pop(0), (rest.pop(0) if rest else "")
        if flag == "--inbox":
            inboxes.append(Path(value))
        elif flag == "--agent":
            agent = value.lower()
        elif flag == "--log":
            log_file = Path(value)
    try:
        event = json.loads(stdin.read() or "{}")
        if event.get("hook_event_name") == "PostToolUse":
            return after_tool(event, log_file, stdout)
        d = judge(event, inboxes, signature)
    except Exception as e:  # noqa: BLE001 - a guard that cannot decide does not let the call through
        event, d = {}, deny("guard-error", f"SCRP exec guard could not check this call ({type(e).__name__}); "
                            "it was not run. Tell the person at this computer.", repr(e))
    if d.allow:
        return 0
    if d.ask and agent == "codex":
        # Codex runs a call whose hook answered "ask", so this hook asks the person itself and waits.
        if (asker or ask_person)(d.ask):
            log(log_file, event, Decision(True, d.rule + "-allowed", "", d.detail))
            return 0
        d = Decision(False, d.rule, "The person at this computer said no (or did not answer) to running "
                     f"this here. Do not run it another way; tell them. {d.reason}", d.detail)
    asked = bool(d.ask) and agent == "claude"      # Claude Code shows its own prompt for "ask"
    log(log_file, event, Decision(False, d.rule + ("-ask" if asked else ""), d.reason, d.detail))
    stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                    "permissionDecision": "ask" if asked else "deny",
                                                    "permissionDecisionReason": d.ask if asked else d.reason}}))
    stdout.flush()
    return 0


# --------------------------------------------------------------------- install
def hook_command(python: Path, inboxes: list[Path], agent: str = "") -> str:
    # -S: no site-packages (the hook needs only the standard library), about 0.15 s less per command.
    parts = [f'"{python}"', "-S", f'"{Path(__file__).resolve()}"'] + ([f"--agent {agent}"] if agent else [])
    parts += [f'--inbox "{p}"' for p in inboxes]
    return " ".join(parts)


def _merge(path: Path, entries: dict, marker: str, root_key: str) -> Path | None:
    """Put each {event: entry} into a JSON settings file, replacing an older entry of ours. Returns the backup."""
    import datetime as _dt
    import shutil
    data, backup = {}, None
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
        backup = path.with_name(path.name + ".bak-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, backup)
    hooks = data.setdefault(root_key, {})
    for event, entry in entries.items():
        hooks[event] = [e for e in hooks.get(event, []) if marker not in json.dumps(e)] + [entry]
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
    marker = "exec_guard.py"
    if a.codex:
        command = hook_command(a.python, a.inbox, "codex")
        handler = {"type": "command", "command": command, "timeout": 120}  # the dialog waits up to ASK_SECONDS
        after = dict(handler, timeout=120)                # marking a large clone walks its files
        entries = {"PreToolUse": {"matcher": "^(Bash|apply_patch)$", "hooks": [dict(handler, commandWindows=command)]},
                   "PostToolUse": {"matcher": "^Bash$", "hooks": [dict(after, commandWindows=command)]}}
        b = _merge(home / ".codex" / "hooks.json", entries, marker, "hooks")
        print(f"Codex: {home / '.codex' / 'hooks.json'}" + (f" (backup {b})" if b else ""))
        print("  Codex runs a new hook only after you trust it: CLI /hooks, or the app's Settings > Hooks.")
    if a.claude:
        command = hook_command(a.python, a.inbox, "claude")
        handler = {"type": "command", "command": command, "timeout": 30}
        after = dict(handler, timeout=120)
        entries = {"PreToolUse": {"matcher": "Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit", "hooks": [handler]},
                   "PostToolUse": {"matcher": "Bash|PowerShell", "hooks": [after]}}
        b = _merge(home / ".claude" / "settings.json", entries, marker, "hooks")
        print(f"Claude Code: {home / '.claude' / 'settings.json'}" + (f" (backup {b})" if b else ""))
    print("Restart the Agent so it loads the hook.")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["install"]:
        return install(argv[1:])
    # The Agent apps write and read hook JSON as UTF-8; Windows would use the console code page (cp949 ...),
    # which garbles non-ASCII paths in the event. The answer is ASCII-only JSON (escaped) either way.
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    return run_hook(argv)


if __name__ == "__main__":
    sys.exit(main())
