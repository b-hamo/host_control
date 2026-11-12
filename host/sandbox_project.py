"""sandbox_project: a downloaded project (.zip, e.g. a GitHub archive) installed, built and run inside the Sandbox.

배주한 2026-11-05 (②): a project's build files and library installs run code (setup.py, npm scripts,
CMake, MSBuild), so none of it happens on this computer. The Host only reads the zip's list of names
(never unpacks or runs anything here), picks a fixed recipe from the project's marker files, lends
the tools with program_share, and writes one PowerShell script that the Sandbox runs:
wait for the zip (SHA-256) -> unpack with tar.exe -> install libraries -> build -> run.

The Agent chooses only the project file (inbox_download/inbox_import), the entry inside it and the
arguments; the commands come from the recipe, never from the Agent. The Sandbox has internet, so
libraries come from their usual registries (PyPI, npm, Go proxy, NuGet, RubyGems) there.

Recipes (by the first marker found at the project root):
  go.mod -> go build | package.json -> npm install, node <entry> or npm start | *.csproj -> dotnet run
  CMakeLists.txt -> cmake + ninja (gcc) | Gemfile -> bundle install, ruby <entry>
  requirements.txt / pyproject.toml / setup.py -> venv + pip install, python <entry>
  Cargo.toml -> Rust fetched inside the Sandbox (below), cargo build --release, cargo run
  none of them: by the entry's suffix (.py .js .rb .java .sh)
Not yet: Maven/Gradle, make (not installed), Zig projects.

Rust (배주한 2026-11-12, (가)): this PC's Rust is usually the default install, the MSVC toolchain, which
links with Visual Studio's link.exe. Visual Studio cannot be lent to the Sandbox (it is installed, not a
folder: MSVC is not supported, 2026-11-04). So nothing is lent: the Sandbox fetches the official rustup
(static.rust-lang.org, its .sha256 checked) and installs the GNU toolchain, which brings its own MinGW
linker, into its own TEMP. It costs a download on every run; nothing is fetched or kept on this PC.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from subprocess import list2cmdline

MAX_ENTRIES = 20000
STEP_TIMEOUT_S = 900
WAIT_ZIP_S = 120
TAIL_LINES = 40
GUEST_INPUT = PureWindowsPath(r"C:\Users\WDAGUtilityAccount\Desktop\Input")


class ProjectError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


@dataclass(frozen=True)
class Project:
    kind: str                      # python, node, go, dotnet, cmake, ruby, java, sh
    programs: tuple                # program_share names it needs
    root: str                      # top folder inside the zip ("" if none), posix
    entry: str | None              # posix path relative to root (cmake: the built exe's name)
    arguments: tuple
    marker: str | None             # the file that chose the recipe


UNSUPPORTED = {"pom.xml": "Maven projects", "build.gradle": "Gradle projects", "build.gradle.kts": "Gradle projects",
               "build.zig": "Zig projects", "Makefile": "make projects (make is not installed; CMake is)"}
RUSTUP_URL = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe"
RUST_HOST = "x86_64-pc-windows-gnu"
RUST_ENV = {"RUSTUP_HOME": r"%TEMP%\rustup", "CARGO_HOME": r"%TEMP%\cargo"}
CURL = r"%SystemRoot%\System32\curl.exe"
import re  # noqa: E402
RUST_BIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}")
BY_SUFFIX = {".py": ("python", ("python",)), ".js": ("node", ("node",)), ".mjs": ("node", ("node",)),
             ".rb": ("ruby", ("ruby",)), ".java": ("java", ("java",)), ".sh": ("sh", ("git",))}


def _names(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
    except (zipfile.BadZipFile, OSError) as e:
        raise ProjectError("INVALID_ARGUMENT", f"{path.name} is not a readable zip ({e.__class__.__name__})") from None
    if len(infos) > MAX_ENTRIES:
        raise ProjectError("INVALID_ARGUMENT", f"{path.name} has more than {MAX_ENTRIES} entries")
    names = []
    for i in infos:
        n = i.filename.replace("\\", "/")
        p = PurePosixPath(n)
        if p.is_absolute() or ".." in p.parts or ":" in n:
            raise ProjectError("POLICY_DENIED", f"{path.name} has an unsafe entry name: {n!r}")
        names.append(n)
    return names


def _root(names: list[str]) -> str:
    """A GitHub archive keeps everything in one folder (repo-main/): that folder is the project root."""
    tops = {n.split("/", 1)[0] for n in names if n}
    if len(tops) == 1:
        top = tops.pop()
        if any(n.startswith(top + "/") and n != top + "/" for n in names):
            return top
    return ""


def inspect(path: Path, entry: str | None, arguments: list[str]) -> Project:
    names = _names(path)
    root = _root(names)
    prefix = root + "/" if root else ""
    files = {n[len(prefix):] for n in names if n.startswith(prefix) and not n.endswith("/")}
    at_root = {f for f in files if "/" not in f}
    if entry is not None:
        e = PurePosixPath(entry.replace("\\", "/"))
        if e.is_absolute() or ".." in e.parts or ":" in entry or not entry.strip():
            raise ProjectError("INVALID_ARGUMENT", "entry is a relative path inside the project")
        entry = str(e)
    has = lambda name: name in at_root  # noqa: E731
    if has("go.mod"):
        kind, programs, marker = "go", ("go",), "go.mod"
    elif has("package.json"):
        kind, programs, marker = "node", ("node",), "package.json"
    elif csproj := sorted(f for f in at_root if f.endswith(".csproj")):
        if len(csproj) > 1:
            raise ProjectError("INVALID_ARGUMENT", f"more than one .csproj at the project root: {csproj}")
        kind, programs, marker = "dotnet", ("dotnet",), csproj[0]
    elif has("CMakeLists.txt"):
        kind, programs, marker = "cmake", ("gcc",), "CMakeLists.txt"
    elif has("Gemfile"):
        kind, programs, marker = "ruby", ("ruby",), "Gemfile"
    elif marker := next((m for m in ("requirements.txt", "pyproject.toml", "setup.py") if has(m)), None):
        kind, programs = "python", ("python",)
    elif has("Cargo.toml"):
        kind, programs, marker = "rust", (), "Cargo.toml"
    elif blocked := next((m for m in UNSUPPORTED if has(m)), None):
        raise ProjectError("INVALID_ARGUMENT", f"{UNSUPPORTED[blocked]} are not supported yet")
    elif entry is not None and PurePosixPath(entry).suffix.lower() in BY_SUFFIX:
        (kind, programs), marker = BY_SUFFIX[PurePosixPath(entry).suffix.lower()], None
    else:
        raise ProjectError("INVALID_ARGUMENT", "no known project file at the project root (go.mod, package.json, "
                                               "*.csproj, CMakeLists.txt, Gemfile, requirements.txt, pyproject.toml, "
                                               "setup.py); give entry (a .py/.js/.rb/.java/.sh file) to run one file")
    if kind in ("python", "ruby", "java", "sh") and entry is None:
        if kind == "python" and "__main__.py" in at_root:
            entry = "__main__.py"
        else:
            raise ProjectError("INVALID_ARGUMENT", f"a {kind} project needs entry: the file to run")
    if kind == "go" and entry is not None and f"{entry}/go.mod" in files:
        # Found 2026-11-05 (golang/example): a repo of several modules; the entry folder is its own module.
        root, entry, marker = f"{root}/{entry}" if root else entry, None, f"{entry}/go.mod"
    if kind == "rust" and entry is not None and not RUST_BIN.fullmatch(entry):
        raise ProjectError("INVALID_ARGUMENT", "for a Rust project, entry is the name of a binary (cargo run --bin)")
    if entry is not None and kind not in ("cmake", "go", "rust") and entry not in files:
        raise ProjectError("INVALID_ARGUMENT", f"{entry} is not in the project")
    return Project(kind, programs, root, entry, tuple(arguments), marker)


# -- the Guest script ----------------------------------------------------------
def _q(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _dir(exe: str) -> str:
    return str(PureWindowsPath(exe).parent)


def _steps(p: Project, shared: dict) -> list[tuple[str, str, list, bool]]:
    """(title, exe, argv, show its output) — fixed by the recipe."""
    args = list(p.arguments)
    entry = p.entry.replace("/", "\\") if p.entry else None
    if p.kind == "python":
        venv = r".venv\Scripts\python.exe"
        steps = [("make a venv", shared["python"]["exe"], ["-m", "venv", ".venv"], False)]
        if p.marker == "requirements.txt":
            steps.append(("pip install -r requirements.txt", venv,
                          ["-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements.txt"], False))
        elif p.marker in ("pyproject.toml", "setup.py"):
            steps.append(("pip install .", venv, ["-m", "pip", "install", "--disable-pip-version-check", "."], False))
        return steps + [("run python " + p.entry, venv, [entry, *args], True)]
    if p.kind == "node":
        npm = _dir(shared["node"]["exe"]) + r"\npm.cmd"
        steps = [("npm install", npm, ["install", "--no-audit", "--no-fund"], False)]
        if entry:
            return steps + [("run node " + p.entry, shared["node"]["exe"], [entry, *args], True)]
        return steps + [("run npm start", npm, ["start", "--", *args] if args else ["start"], True)]
    if p.kind == "go":
        pkg = "./" + p.entry if p.entry else "."
        return [("go build", shared["go"]["exe"], ["build", "-o", "app.exe", pkg], False),
                ("run app.exe", "app.exe", args, True)]
    if p.kind == "dotnet":
        return [("dotnet build", shared["dotnet"]["exe"], ["build", p.marker, "-c", "Release", "-nologo"], False),
                ("run dotnet", shared["dotnet"]["exe"], ["run", "--project", p.marker, "-c", "Release", "--no-build",
                                                         "--", *args], True)]
    if p.kind == "cmake":
        bin_ = _dir(shared["gcc"]["exe"])
        return [("cmake configure", bin_ + r"\cmake.exe", ["-S", ".", "-B", "build", "-G", "Ninja",
                                                          "-DCMAKE_BUILD_TYPE=Release"], False),
                ("cmake build", bin_ + r"\cmake.exe", ["--build", "build"], False),
                ("run " + (p.entry or "the built program"), "build\\" + (entry or "*.exe"), args, True)]
    if p.kind == "ruby":
        bundle = _dir(shared["ruby"]["exe"]) + r"\bundle.bat"
        return [("bundle install", bundle, ["install"], False),
                ("run ruby " + p.entry, bundle, ["exec", "ruby", entry, *args], True)]
    if p.kind == "rust":
        # rustup acts by its file name (found 2026-11-12: '.rustup-init' -> "unknown proxy name"), so it
        # keeps its name, in a folder of its own inside the project folder (arguments are not expanded)
        init = r".rustup-download\rustup-init.exe"
        cargo = r"%TEMP%\cargo\bin\cargo.exe"
        run = ["run", "--release", "--quiet", *(["--bin", p.entry] if p.entry else [])]
        return [("download rustup", CURL, ["-sSfL", "--retry", "2", "--create-dirs", "-o", init, RUSTUP_URL], False),
                ("download rustup checksum", CURL, ["-sSfL", "--retry", "2", "-o", init + ".sha256",
                                                    RUSTUP_URL + ".sha256"], False),
                ("check rustup checksum", "#sha256", [init], False),
                ("install Rust (GNU, minimal)", init, ["-y", "--no-modify-path", "--profile", "minimal",
                                                       "--default-host", RUST_HOST, "--default-toolchain",
                                                       "stable"], False),
                ("cargo build --release", cargo, ["build", "--release"], False),
                ("run cargo" + (" --bin " + p.entry if p.entry else ""), cargo,
                 run + (["--", *args] if args else []), True)]
    if p.kind == "java":
        return [("run java " + p.entry, shared["java"]["exe"], [entry, *args], True)]
    if p.kind == "sh":
        return [("run sh " + p.entry, shared["git"]["shell"], [p.entry, *args], True)]
    raise ProjectError("INVALID_ARGUMENT", f"unknown project kind {p.kind}")


def script(p: Project, zip_name: str, zip_sha256: str, nonce: str, shared: dict,
           guest_input: PureWindowsPath = GUEST_INPUT) -> str:
    """The PowerShell the Sandbox runs (data here). Everything it prints is the run's stdout."""
    paths = [d for s in shared.values() for d in s.get("path", [])]
    env = {k: v for s in shared.values() for k, v in s.get("env", {}).items()}
    if "ruby" in shared:
        env.setdefault("BUNDLE_PATH", r"%TEMP%\bundle")
    if p.kind == "rust":
        for k, v in RUST_ENV.items():
            env.setdefault(k, v)
    if "dotnet" in shared:
        env.setdefault("DOTNET_CLI_UI_LANGUAGE", "en")      # not the console code page (unreadable in the log)
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        f"$zip = {_q(guest_input / zip_name)}",
        f"$deadline = (Get-Date).AddSeconds({WAIT_ZIP_S})",
        "while ($true) {",
        "  $h = $null",
        "  if (Test-Path -LiteralPath $zip) { try { $h = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() } catch { $h = $null } }",
        f"  if ($h -eq {_q(zip_sha256)}) {{ break }}",
        "  if ((Get-Date) -gt $deadline) { Write-Output 'PROJECT: the zip did not arrive'; exit 3 }",
        "  Start-Sleep -Milliseconds 500",
        "}",
        f"$work = Join-Path $env:TEMP {_q('Project-' + nonce)}",
        "New-Item -ItemType Directory -Path $work -Force | Out-Null",
        "& (Join-Path $env:SystemRoot 'System32\\tar.exe') -xf $zip -C $work",
        "if ($LASTEXITCODE) { Write-Output 'PROJECT: unpack failed'; exit 3 }",
        f"$root = Join-Path $work {_q(p.root.replace('/', chr(92)))}" if p.root else "$root = $work",
        "Set-Location -LiteralPath $root",
        "$env:PATH = " + _q(";".join(paths) + ";") + " + $env:PATH",
        *[f"Set-Item -Path ('env:' + {_q(k)}) -Value ([Environment]::ExpandEnvironmentVariables({_q(v)}))"
          for k, v in env.items()],
        # UTF-8 when the bytes are valid UTF-8 (Node, Go, C), else the OEM code page (Python, Java, dotnet)
        "$strict = New-Object Text.UTF8Encoding($false, $true)",
        "$oem = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)",
        "function Convert-Text([byte[]]$b) { try { $strict.GetString($b) } catch { $oem.GetString($b) } }",
        "function Invoke-Step([string]$title, [string]$exe, [string]$line, [bool]$show) {",
        "  Write-Output ('== ' + $title)",
        "  $exe = [Environment]::ExpandEnvironmentVariables($exe)",
        # '#sha256 <file>': the file's SHA-256 must equal the first word of <file>.sha256 (rustup publishes it)
        "  if ($exe -eq '#sha256') { $f = $line.Trim('\"')",
        "    $want = ((Get-Content -LiteralPath ($f + '.sha256') -Raw) -split '\\s+')[0].ToLowerInvariant()",
        "    $got = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()",
        "    if ($want -ne $got) { Write-Output ('== ' + $title + ' FAILED (checksum)'); exit 5 }",
        "    Write-Output ('== ' + $title + ' OK'); return }",
        "  if ($exe -like '*`**') { $found = @(Get-ChildItem -Path (Join-Path $root (Split-Path $exe)) -Filter '*.exe' -File)",
        "    if ($found.Count -ne 1) { Write-Output ('PROJECT: ' + $found.Count + ' programs were built; give entry: ' + (($found | ForEach-Object Name) -join ', ')); exit 4 }",
        "    $exe = $found[0].FullName }",
        "  elseif (-not [IO.Path]::IsPathRooted($exe)) { $exe = Join-Path $root $exe }",
        "  $info = New-Object Diagnostics.ProcessStartInfo",
        "  $info.FileName = $exe; $info.Arguments = $line; $info.WorkingDirectory = $root",
        "  $info.UseShellExecute = $false; $info.CreateNoWindow = $true",
        "  $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true",
        "  $proc = [Diagnostics.Process]::Start($info)",
        "  $om = New-Object IO.MemoryStream; $em = New-Object IO.MemoryStream",
        "  $o = $proc.StandardOutput.BaseStream.CopyToAsync($om); $e = $proc.StandardError.BaseStream.CopyToAsync($em)",
        f"  if (-not $proc.WaitForExit({STEP_TIMEOUT_S * 1000})) {{ & taskkill.exe /T /F /PID $proc.Id | Out-Null; Write-Output ('== ' + $title + ' TIMED OUT'); exit 124 }}",
        "  $proc.WaitForExit(); $o.Wait(); $e.Wait()",
        "  $text = (Convert-Text $om.ToArray()) + (Convert-Text $em.ToArray())",
        "  if ($show) { Write-Output $text }",
        "  if ($proc.ExitCode -ne 0) {",
        f"    if (-not $show) {{ Write-Output (($text -split \"`r?`n\") | Select-Object -Last {TAIL_LINES}) }}",
        "    Write-Output ('== ' + $title + ' FAILED (exit ' + $proc.ExitCode + ')'); exit $proc.ExitCode }",
        "  if (-not $show) { Write-Output ('== ' + $title + ' OK') }",
        "}",
    ]
    for title, exe, argv, show in _steps(p, shared):
        lines.append(f"Invoke-Step {_q(title)} {_q(exe)} {_q(list2cmdline(argv))} ${'true' if show else 'false'}")
    lines.append("exit 0")
    return "\r\n".join(lines) + "\r\n"
