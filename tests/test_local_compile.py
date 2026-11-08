"""router_execute compile forms (배주한 2026-11-05): one C/C++/Go/Zig/Java/C# file is compiled on this PC,
only the result runs in the Sandbox.

- code that would make the compiler read other files here (UNC, absolute, .., #embed, .incbin) is refused
  before the compiler starts; after preprocessing every file read must be in the compiler's folder
- the compiled program becomes the run's input (derived from the capture), the capture stays the parent
- Java / C# results run with java / dotnet lent by program_share; the C# runtimeconfig is the SDK's own
"""

import asyncio
import hashlib
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from host.broker import Broker, BrokerError
from host.local_compile import (GUEST_ROOT, TARGET, Built, CompileError, build, check_c_source, check_no_asm,
                                check_reads)
from host.sandbox_run import INTERPRETER_PENDING
from test_router_languages import execute_args, runner_with_agent_capture
from test_sandbox_run import ID

GCC = Path(r"C:\msys64\ucrt64")
has_gcc = pytest.mark.skipif(not (GCC / "bin" / "gcc.exe").is_file(), reason="MSYS2 gcc not installed")


@pytest.mark.parametrize("code", [
    '#include "\\\\attacker\\share\\x.h"\n', '#include "//attacker/share/x.h"\n', '#include <C:/Users/me/.ssh/id_rsa>\n',
    '#include "../secret.h"\n', '#include "/etc/passwd"\n', '#define H "x.h"\n#include H\n', '# /* c */ include <a:b>\n',
    '%:include "C:\\\\x"\n', '#embed "s.bin"\n', '#if __has_include("C:/x")\n#endif\n', '_Pragma("GCC dependency \\"x\\"")\n',
    '#pragma GCC dependency "C:/x"\n', 'int x; __asm__(".incbin \\"C:/x\\"");\n', 'const char *s = R"(x)";\n',
    '#inc\\\nlude "C:/x"\n', '#include_next <stdio.h>\n'])
def test_source_that_would_read_other_files_here_is_refused(code):
    with pytest.raises(CompileError) as e:
        check_c_source(code)
    assert e.value.code == "INVALID_ARGUMENT"


@pytest.mark.parametrize("code", ['#include <stdio.h>\n#include <sys/types.h>\n#include "my-local.h"\n',
                                  '// #include "C:/not/a/directive"\nint main(void){return 0;}\n',
                                  'const char *s = "#include <C:/x>";\n'])
def test_ordinary_source_passes(code):
    check_c_source(code)


def test_every_file_read_must_be_in_the_compiler_folder(tmp_path):
    root, work = tmp_path / "gcc", tmp_path / "work"
    (root / "include").mkdir(parents=True)
    work.mkdir()
    (src := work / "main.c").write_text("")
    check_reads(["main.c", str(root / "include" / "stdio.h")], work, src, root)
    with pytest.raises(CompileError) as e:
        check_reads(["main.c", str(tmp_path / "secret.txt")], work, src, root)
    assert e.value.code == "POLICY_DENIED"


def test_inline_assembly_in_the_code_itself_is_refused():
    pre = '# 1 "C:/gcc/include/x.h"\n__asm__("ok in a header");\n# 3 "main.c"\nint main(){__asm__("nop");}\n'
    with pytest.raises(CompileError):
        check_no_asm(pre, "main.c")
    check_no_asm('# 1 "C:/gcc/include/x.h"\n__asm__("x");\n# 1 "main.c"\nint main(){}\n', "main.c")


def test_a_missing_compiler_says_install_it():
    def find(tool):
        raise CompileError("RUNTIME_UNAVAILABLE", f"{tool} is not installed on this PC; install it")
    with pytest.raises(CompileError) as e:
        build("go-source", "package main\nfunc main(){}\n", find=find)
    assert e.value.code == "RUNTIME_UNAVAILABLE" and "install" in e.value.message


def test_zig_cimport_and_csharp_packages_are_refused(tmp_path):
    with pytest.raises(CompileError):
        build("zig-source", 'const c = @cImport(@cInclude("C:/x.h"));\n', find=lambda t: tmp_path)
    with pytest.raises(CompileError):
        build("csharp-source", '#:package Humanizer@2.14.1\nConsole.WriteLine(1);\n', find=lambda t: tmp_path)


@has_gcc
def test_gcc_compiles_a_static_program_and_refuses_inline_assembly():
    built = build("c-source", '#include <stdio.h>\nint main(void){puts("hi");return 0;}\n', find=lambda t: GCC)
    assert built.data[:2] == b"MZ" and built.suffix == ".exe" and built.program is None and built.argv == (TARGET,)
    with pytest.raises(CompileError) as e:
        build("c-source", 'int main(void){__asm__("nop");return 0;}\n', find=lambda t: GCC)
    assert "assembly" in e.value.message
    with pytest.raises(CompileError) as e:
        build("c-source", "int main(void){ return }\n", find=lambda t: GCC)
    assert e.value.code == "INVALID_ARGUMENT" and "data, never an instruction" in e.value.message


def test_the_compiled_program_becomes_the_runs_input(tmp_path):
    runner, inbox = runner_with_agent_capture(tmp_path, text="int main(){}")
    plan, shown = runner.plan_capture(execute_args("c-source"), ID)
    assert plan.build is not None and shown["transform"] == "compile" and not list(inbox.glob("*.exe"))
    runner.with_build(plan, Built("c", ".exe", b"MZ-program", None, (TARGET,), "gcc"))
    exe = inbox / "CAP-0001-AGENT.exe"
    assert exe.read_bytes() == b"MZ-program" and plan.build is None and plan.program is None
    derived, parent = plan.action.sources
    assert derived.source_id == "CAP-0001-AGENT-EXE" and derived.parents == (parent.source_id,) == ("CAP-0001-AGENT",)
    assert derived.sha256 == hashlib.sha256(b"MZ-program").hexdigest()
    assert plan.action.command.executable == rf"C:\Users\WDAGUtilityAccount\Desktop\Input\{exe.name}"
    assert plan.action.command.argv == () and plan.origin["compiled_by"] == "gcc"


def test_a_csharp_dll_runs_with_the_lent_dotnet_and_its_runtimeconfig(tmp_path):
    runner, inbox = runner_with_agent_capture(tmp_path, text="Console.WriteLine(1);")
    plan, _ = runner.plan_capture(execute_args("csharp-source"), ID)
    cfg = GUEST_ROOT + r"\sdk\10.0.403\dotnet.runtimeconfig.json"
    runner.with_build(plan, Built("csharp", ".dll", b"MZ-dll", "dotnet", ("exec", "--runtimeconfig", cfg, TARGET), "dotnet"))
    assert plan.program == "dotnet" and plan.action.command.executable == INTERPRETER_PENDING
    runner.with_interpreter(plan, {"exe": r"C:\Tools\dotnet\dotnet.exe", "guest_root": r"C:\Tools\dotnet"})
    c = plan.action.command
    assert c.executable == r"C:\Tools\dotnet\dotnet.exe"
    assert c.argv == ("exec", "--runtimeconfig", r"C:\Tools\dotnet\sdk\10.0.403\dotnet.runtimeconfig.json",
                      r"C:\Users\WDAGUtilityAccount\Desktop\Input\CAP-0001-AGENT.dll")


def test_the_broker_compiles_before_the_run_or_reports_the_compiler(tmp_path, monkeypatch):
    import host.local_compile as lc
    runner, _ = runner_with_agent_capture(tmp_path, text="package main")
    plan, _ = runner.plan_capture(execute_args("go-source"), ID)
    broker = SimpleNamespace(runner=runner)

    def refuse(form, source):
        raise CompileError("INVALID_ARGUMENT", "the compiler refused the code")
    monkeypatch.setattr(lc, "build", refuse)
    with pytest.raises(BrokerError) as e:
        asyncio.run(Broker._compile_here(broker, plan))
    assert e.value.code == "INVALID_ARGUMENT" and plan.build is not None
    monkeypatch.setattr(lc, "build", lambda form, source: Built("go", ".exe", b"MZ", None, (TARGET,), "go"))
    asyncio.run(Broker._compile_here(broker, plan))
    assert plan.build is None and plan.file == "CAP-0001-AGENT.exe"
