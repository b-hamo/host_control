"""User approval for sensitive tool calls (spec B-8): a dialog on the Host's own screen.

The Broker asks before artifact_export (Policy REQUIRE_APPROVAL). The question
goes to the person at the Host, never to the Agent: the Agent cannot answer it,
and a missing answer is a "no".

    approver = DialogApprover()            # 45 s, inside the 60 s MCP call limit
    Broker(..., approver=approver)

The dialog shows what the Guest reported (the file's path inside the Sandbox)
and what the Agent wrote as its reason; both are untrusted and labelled as
such. One dialog at a time. Windows only; elsewhere every request is denied.

The wait is shorter than the MCP tool call limit (mcp_server.CALL_TIMEOUT_S,
60 s; Codex's own tool timeout is 60 s too), so the answer always reaches the
call that asked. If that call is cancelled anyway (timeout, Host exit), the
open dialog is answered "No" and closed; a late "Yes" can never count.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time

log = logging.getLogger("host-approval")

APPROVAL_TIMEOUT_S = 45.0          # < mcp_server.CALL_TIMEOUT_S (60 s)
TITLE = "SCRP 파일 반출 승인"
MB_YESNO, MB_ICONWARNING, MB_DEFBUTTON2 = 0x4, 0x30, 0x100
MB_SYSTEMMODAL, MB_SETFOREGROUND, MB_TOPMOST = 0x1000, 0x10000, 0x40000
IDYES, IDNO = 6, 7
WM_COMMAND = 0x0111
MAX_SHOWN = 200


def _clean(text: str) -> str:
    """Untrusted text in a dialog: one line, printable, bounded."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(text)).strip()
    return text if len(text) <= MAX_SHOWN else text[:MAX_SHOWN] + "…"


def describe(summary: dict, timeout_s: float = APPROVAL_TIMEOUT_S) -> str:
    lines = ["AI(Codex)가 Sandbox 안의 파일을 이 컴퓨터로 반출하려고 합니다.", ""]
    if summary.get("path"):
        lines.append(f"파일 (Sandbox가 보고한 경로): {_clean(summary['path'])}")
    lines.append(f"세션: {_clean(summary.get('session_id', ''))}")
    reason = _clean((summary.get("arguments") or {}).get("reason") or "") or "(없음)"
    lines += [f"AI가 적은 이유 (확인되지 않은 내용): {reason}", "",
              "허용하면 파일을 받아 형식·백신 검사를 하고, 통과한 경우에만 결과 폴더에 저장합니다.",
              f"허용할까요? ({timeout_s:.0f}초 안에 답하지 않으면 거부됩니다)"]
    return "\n".join(lines)


class DialogApprover:
    def __init__(self, timeout_s: float = APPROVAL_TIMEOUT_S):
        self.timeout_s = timeout_s
        self._lock = asyncio.Lock()
        self._seq = 0

    async def __call__(self, summary: dict) -> bool:
        async with self._lock:                      # one question at a time
            self._seq += 1
            title = f"{TITLE} #{self._seq}"         # unique, so this exact dialog can be closed
            try:
                approved = await asyncio.to_thread(self._ask, describe(summary, self.timeout_s), title)
            except asyncio.CancelledError:
                log.info("APPROVAL %s cancelled; closing its dialog as \"No\"", title)
                self._dismiss(title)
                raise
        log.info("APPROVAL %s %s: %s", summary.get("tool"), summary.get("session_id"),
                 "approved" if approved else "denied")
        return approved

    def _dismiss(self, title: str) -> None:
        """Press "No" on the dialog with this title (in the background; it may still be opening)."""
        if sys.platform != "win32":
            return

        def press_no() -> None:
            import ctypes
            user32 = ctypes.WinDLL("user32")
            for _ in range(40):                     # up to 2 s for the window to exist
                hwnd = user32.FindWindowW(None, ctypes.c_wchar_p(title))
                if hwnd:
                    user32.PostMessageW(hwnd, WM_COMMAND, IDNO, 0)
                    return
                time.sleep(0.05)
        threading.Thread(target=press_no, name="approval-dismiss", daemon=True).start()

    def _ask(self, text: str, title: str = TITLE) -> bool:
        if sys.platform != "win32":
            log.warning("approval dialog needs Windows; denying")
            return False
        import ctypes
        user32 = ctypes.WinDLL("user32")
        flags = MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST
        # MessageBoxTimeoutW: exported by user32 since Windows XP; returns 32000 on timeout.
        answer = user32.MessageBoxTimeoutW(None, ctypes.c_wchar_p(text), ctypes.c_wchar_p(title),
                                           flags, 0, int(self.timeout_s * 1000))
        return answer == IDYES


async def deny_all(summary: dict) -> bool:
    """--approval deny: nothing is approved."""
    log.info("APPROVAL %s denied (approval is set to deny)", summary.get("tool"))
    return False
