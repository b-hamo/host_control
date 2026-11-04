"""--signed-downloads: only a trusted publisher's validly signed program also goes to Downloads (2026-11-03 멘토링).

The decisions are tested with an injected WinVerifyTrust result; the real Windows checks use a program that
Microsoft signs and that stays installed (Edge), and are skipped where there is none.
"""

import shutil
import sys
import time
from pathlib import Path

import pytest

from host import signature_check as sc
from host.mcp_server import SIGNED_DOWNLOADS_RULE, load_tool_list, main, save_downloads_description
from host.signature_check import Signature, Verdict, check
from test_inbox_download import BODY, downloader, server  # noqa: F401 - server is a fixture

windows = pytest.mark.skipif(sys.platform != "win32", reason="Authenticode is Windows")
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application")
SIGNED = next((p for p in (EDGE / "pwahelper.exe", EDGE / "msedge_proxy.exe", EDGE / "msedge.exe") if p.is_file()), None)
needs_signed = pytest.mark.skipif(SIGNED is None, reason="no Microsoft-signed Edge program on this computer")


def fixed(status=0, signer="Microsoft Corporation", machine_root=True):
    return lambda path: Signature(status, signer, machine_root)


def msi(tmp_path, name="tool.msi"):
    p = tmp_path / name
    p.write_bytes(b"not judged by its bytes in these tests")
    return p


# --------------------------------------------------------------------- decisions
@pytest.mark.parametrize("name", ["setup.ps1", "run.bat", "page.hta", "tool.zip", "README"])
def test_only_programs_are_judged(tmp_path, name):
    v = check(msi(tmp_path, name), verify=fixed())
    assert not v.trusted and "only .exe and .msi" in v.reason


@pytest.mark.parametrize("name", ["powershell.exe", "python.exe", "msiexec.exe", "mshta.exe", "rundll32.exe"])
def test_a_program_that_runs_other_code_is_refused_even_signed(tmp_path, name):
    v = check(msi(tmp_path, name), verify=fixed())
    assert not v.trusted and "runs other code" in v.reason


@pytest.mark.parametrize("sig, reason", [
    (Signature(0x800B0100, None, False), "not signed"),
    (Signature(0x80096010, "Microsoft Corporation", True), "not valid"),
    (Signature(0x800B010C, "Microsoft Corporation", True), "revoked"),
    (Signature(0x800B010E, "Microsoft Corporation", True), "could not be checked"),
    (Signature(0, "Microsoft Corporation", False), "root this computer's user added"),
    (Signature(0, "Some Small Vendor Ltd", True), "not on the trusted publisher list"),
])
def test_only_a_valid_signature_of_a_listed_publisher_is_trusted(tmp_path, sig, reason):
    v = check(msi(tmp_path), verify=lambda p: sig)
    assert not v.trusted and reason in v.reason
    assert check(msi(tmp_path), verify=fixed()) == Verdict(True, "Microsoft Corporation",
                                                           "valid signature of Microsoft Corporation")


def test_the_publisher_list_can_be_replaced(tmp_path):
    assert check(msi(tmp_path), ["Contoso Ltd"], verify=fixed(signer="Contoso Ltd")).trusted
    assert not check(msi(tmp_path), ["Contoso Ltd"], verify=fixed()).trusted


def test_a_check_that_hangs_is_not_trusted(tmp_path):
    def slow(path):
        time.sleep(2)
        return Signature(0, "Microsoft Corporation", True)
    v = check(msi(tmp_path), verify=slow, timeout_s=0.2)
    assert not v.trusted and "within" in v.reason


# --------------------------------------------------------------------- real Windows checks
@windows
@needs_signed
def test_a_microsoft_signed_program_is_trusted(tmp_path):
    copy = tmp_path / "tool.exe"
    shutil.copyfile(SIGNED, copy)
    v = check(copy)
    assert v.trusted, v.reason
    assert v.signer == "Microsoft Corporation"


@windows
def test_a_renamed_interpreter_is_still_refused(tmp_path):
    real = Path(getattr(sys, "_base_executable", sys.executable))
    if sc.original_file_name(real) is None:
        pytest.skip("this python.exe has no version resource")
    copy = tmp_path / "setup.exe"
    shutil.copyfile(real, copy)
    v = check(copy)
    assert not v.trusted and "renamed" in v.reason


@windows
@needs_signed
def test_data_after_the_signature_is_refused(tmp_path):
    copy = tmp_path / "tool.exe"
    copy.write_bytes(SIGNED.read_bytes() + b"payload!")
    v = check(copy)
    assert not v.trusted and "follows the signature" in v.reason


@windows
@needs_signed
def test_bytes_hidden_inside_the_signature_table_are_refused(tmp_path):
    """CVE-2013-3900: grow the certificate table by 8 bytes. Windows still calls the signature valid by
    default; the check must not."""
    data = bytearray(SIGNED.read_bytes())
    pe = int.from_bytes(data[0x3C:0x40], "little")
    opt = pe + 24
    sec = opt + (96 if int.from_bytes(data[opt:opt + 2], "little") == 0x10B else 112) + 4 * 8
    offset, size = (int.from_bytes(data[sec + i:sec + i + 4], "little") for i in (0, 4))
    data[sec + 4:sec + 8] = (size + 8).to_bytes(4, "little")
    length = int.from_bytes(data[offset:offset + 4], "little")
    data[offset:offset + 4] = (length + 8).to_bytes(4, "little")
    data += b"payload!"
    copy = tmp_path / "tool.exe"
    copy.write_bytes(data)
    assert sc.certificate_table_problem(copy) == "bytes were added inside the signature table (CVE-2013-3900)"
    assert not check(copy).trusted


@windows
def test_an_unsigned_program_is_not_trusted(tmp_path):
    copy = tmp_path / "tool.exe"
    copy.write_bytes(BODY)
    assert not check(copy).trusted


# --------------------------------------------------------------------- inbox_download --signed-downloads
def test_a_trusted_download_also_goes_to_downloads(tmp_path, server):
    server.routes["/tool.exe"] = ("body", BODY)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    seen = []

    def trusted(path):
        seen.append(path.read_bytes())
        return Verdict(True, "Microsoft Corporation", "valid signature of Microsoft Corporation")
    d, _ = downloader(tmp_path, server, downloads=downloads, signed_to_downloads=True, signature_check=trusted)
    r = d.download(f"{server.base}/tool.exe")
    assert seen == [BODY]                                                # the checked bytes are the copied bytes
    assert r["signature"]["trusted"] and r["downloads_copy"] == {"path": "Downloads\\tool.exe", "new": True}
    assert (downloads / "tool.exe").read_bytes() == BODY
    assert (tmp_path / "inbox" / "tool.exe").read_bytes() == BODY      # the Sandbox still gets its copy


def test_an_untrusted_download_stays_in_the_inbox_only(tmp_path, server):
    server.routes["/tool.exe"] = ("body", BODY)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    d, _ = downloader(tmp_path, server, downloads=downloads, signed_to_downloads=True,
                      signature_check=lambda p: Verdict(False, None, "not signed"))
    r = d.download(f"{server.base}/tool.exe")
    assert r["signature"] == {"trusted": False, "signer": None, "reason": "not signed"}
    assert "downloads_copy" not in r and list(downloads.iterdir()) == []
    assert (tmp_path / "inbox" / "tool.exe").read_bytes() == BODY


def test_the_agent_is_told_and_the_option_is_checked(capsys):
    tools = load_tool_list({"host.inbox"})
    save_downloads_description(tools, SIGNED_DOWNLOADS_RULE)
    assert next(t for t in tools if t["name"] == "inbox_download")["description"].endswith(SIGNED_DOWNLOADS_RULE)
    with pytest.raises(SystemExit):
        main(["--signed-downloads"])
    assert "--signed-downloads needs --inbox" in capsys.readouterr().err
