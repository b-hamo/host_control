"""Removed Shared entry points fail instead of creating writable mappings."""
import asyncio

import pytest

from host.approval import DialogApprover, IDYES, IDCANCEL, describe_shared
from host.mcp_server import main


@pytest.mark.parametrize("args", [["--shared", "C:/old-share"], ["--unified-export"]])
def test_removed_shared_configuration_fails_with_migration_hint(args, capsys):
    with pytest.raises(SystemExit) as failure:
        main(args)
    assert failure.value.code == 2
    assert "--output-root" in capsys.readouterr().err


def test_output_final_dialog_lists_files_destination_and_choices():
    text = describe_shared({"files": [{"name": "note.pdf", "size": 20}],
                            "share": "C:/work/output/SES/ART-1", "output_only": True,
                            "unified_export": True, "planned_destination": "C:/Downloads/SandboxOutput/SES/ART-1"})
    assert "note.pdf" in text and "SandboxOutput" in text
    assert "아니요" in text and "무응답" in text


def test_review_paginates_names_and_cancel_stops_remaining_pages():
    human, seen = DialogApprover(), []
    def answer(text, title, buttons):
        seen.append(text)
        return IDYES if len(seen) == 1 else IDCANCEL
    human._ask_code = answer
    files = [{"name": f"file-{n}.txt", "size": n} for n in range(25)]
    assert asyncio.run(human.review_export({"files": files, "output_only": True})) == "hold"
    assert len(seen) == 2 and "file-19.txt" in seen[1]
    assert "file-20.txt" not in "".join(seen)
