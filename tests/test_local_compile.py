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
                                check_reads, check_rust_source, find_rust_toolchain, rust_dep_info)
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


# -- Rust (배주한 2026-11-12) ------------------------------------------------------------------------
def _rust_toolchain():
    try:
        return find_rust_toolchain()
    except CompileError:
        return None


has_rust = pytest.mark.skipif(_rust_toolchain() is None, reason="Rust (rustup) not installed")


@pytest.mark.parametrize("code", [
    r'fn main(){ println!("{}", include_str!("C:/Users/me/.ssh/id_rsa")); }',
    r'fn main(){ let b = include_bytes!("\\\\attacker\\share\\x"); }',
    'include!("C:/x.rs");\nfn main(){}',
    'macro_rules! m { ($x:ident) => { $x!("C:/x") } }\nfn main(){ m!(include_str); }',
    '#[doc = include_str!("C:/x")]\nfn main(){}',
    r'fn main(){ println!("{}", env!("USERNAME")); }',
    r'fn main(){ println!("{:?}", option_env ! ("PATH")); }',
    r'fn main(){ unsafe { core::arch::asm!(".incbin \"C:/x\""); } }',
    'core::arch::global_asm!("");\nfn main(){}',
    'extern crate serde;\nfn main(){}',
    'mod other;\nfn main(){}',
    '#[path = "C:/x.rs"] mod m { }\nfn main(){}',
    '#[cfg_attr(all(), path = "C:/x")] mod m { }\nfn main(){}',
    '#[link(name = "C:/x")] extern "C" {}\nfn main(){}',
    'fn main(){} /* unterminated',
])
def test_rust_source_that_would_read_this_pc_is_refused(code):
    with pytest.raises(CompileError) as e:
        check_rust_source(code)
    assert e.value.code == "INVALID_ARGUMENT"


@pytest.mark.parametrize("code", [
    'use std::env;\nfn main(){ println!("{} include env! asm", env::args().count()); }',
    '''fn main(){ let _r = r#"include_str!("C:/x")"#; let _b = b"asm"; let c = '"'; println!("{c}"); }''',
    "fn f<'a>(s: &'a str) -> &'a str { s }\nfn main(){ println!(\"{}\", f(\"x\")); }",
    '/* outer /* inner */ include_str!("x") */\nfn main(){}',
    'mod inline { pub fn f() {} }\nfn main(){ inline::f(); }',
])
def test_ordinary_rust_source_passes(code):
    check_rust_source(code)


def test_rust_dep_info_lists_files_and_environment_reads(tmp_path):
    (d := tmp_path / "deps.d").write_text("app.d: main.rs C:\\secret\\a\\ b.txt\n\nmain.rs:\n\n"
                                          "# env-dep:USERNAME=me\n", encoding="utf-8")
    files, envs = rust_dep_info(d)
    assert files[:2] == ["main.rs", "C:\\secret\\a b.txt"] and envs == ["USERNAME"]


def test_rust_is_refused_before_rustc_starts(tmp_path):
    with pytest.raises(CompileError):
        build("rust-source", 'fn main(){ include_str!("C:/x"); }', find=lambda t: tmp_path)


@has_rust
def test_rustc_compiles_a_static_program_and_refuses_hidden_environment_reads():
    built = build("rust-source", 'fn main(){ let s: i64 = (1..=10).sum(); println!("합계 {s}"); }')
    assert built.data[:2] == b"MZ" and built.suffix == ".exe" and built.program is None and built.argv == (TARGET,)
    assert built.compiler == "rustc" and b"VCRUNTIME140" not in built.data.upper()     # static: no VC++ runtime
    with pytest.raises(CompileError) as e:
        build("rust-source", 'macro_rules! m { ($x:ident) => { $x!("USERNAME") } }\n'
                             'fn main(){ println!("{:?}", m!(option_env)); }')
    assert e.value.code == "POLICY_DENIED" and "USERNAME" in e.value.message
    with pytest.raises(CompileError) as e:
        build("rust-source", 'fn main(){ let x: i32 = "a"; }')
    assert e.value.code == "INVALID_ARGUMENT" and "data, never an instruction" in e.value.message


def test_a_rust_program_becomes_the_runs_input(tmp_path):
    runner, inbox = runner_with_agent_capture(tmp_path, text="fn main(){}")
    plan, shown = runner.plan_capture(execute_args("rust-source"), ID)
    assert plan.build is not None and shown["transform"] == "compile"
    runner.with_build(plan, Built("rust", ".exe", b"MZ-rust", None, (TARGET,), "rustc"))
    assert (inbox / "CAP-0001-AGENT.exe").read_bytes() == b"MZ-rust" and plan.origin["compiled_by"] == "rustc"
