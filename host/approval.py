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
RUN_TITLE = "SCRP Sandbox 실행 승인"
KEEP_TITLE = "SCRP 파일 남기기 확인"
STOP_TITLE = "SCRP Sandbox 종료 확인"
DUPLICATE_TITLE = "SCRP 내려받기 확인"
SHARED_TITLE = "SCRP 공유 폴더 남기기"
MAX_COMMAND_SHOWN = 1500           # the whole command or no approval at all (never cut short)
MB_YESNO, MB_ICONWARNING, MB_DEFBUTTON2 = 0x4, 0x30, 0x100
MB_YESNOCANCEL, MB_DEFBUTTON3 = 0x3, 0x200
MB_SYSTEMMODAL, MB_SETFOREGROUND, MB_TOPMOST = 0x1000, 0x10000, 0x40000
IDYES, IDNO, IDCANCEL = 6, 7, 2
WM_COMMAND = 0x0111
MAX_SHOWN = 200


def _clean(text: str, limit: int = MAX_SHOWN) -> str:
    """Untrusted text in a dialog: one line, printable, bounded."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(text)).strip()
    return text if len(text) <= limit else text[:limit] + "…"


def describe_run(summary: dict, timeout_s: float = APPROVAL_TIMEOUT_S) -> str | None:
    """sandbox_run: the exact command, in full. None when it cannot be shown in full."""
    command = "".join(ch if ch.isprintable() else " " for ch in str(summary.get("command", "")))
    if not command or len(command) > MAX_COMMAND_SHOWN:
        return None
    reason = _clean((summary.get("arguments") or {}).get("reason") or "") or "(없음)"
    return "\n".join([
        "AI(Codex)가 인터넷에서 받은 파일을 Sandbox 안에서 실행하려고 합니다.",
        "이 컴퓨터에서는 실행되지 않습니다.", "",
        f"파일: {_clean(summary.get('file', ''))}",
        f"받은 주소: {_clean(summary.get('source', ''))}",
        f"SHA-256: {_clean(summary.get('sha256', ''))}",
        f"Sandbox 안에서 실행할 명령: {command}",
        f"AI가 적은 이유 (확인되지 않은 내용): {reason}", "",
        "허용하면 이 명령 하나만, 이번 한 번 실행합니다.",
        f"허용할까요? ({timeout_s:.0f}초 안에 답하지 않으면 거부됩니다)"])


def describe_keep(summary: dict, timeout_s: float = APPROVAL_TIMEOUT_S) -> str:
    """inbox_finish: files from the Sandbox inbox would stay on this computer (Downloads)."""
    keep = (summary.get("arguments") or {}).get("keep") or []
    lines = ["AI(Codex)가 Sandbox에 넣었던 파일을 이 컴퓨터의 다운로드 폴더에 남기려고 합니다.", ""]
    lines += [f"  {_clean(k)}" for k in keep[:20]]
    lines += ["", "남긴 파일은 인터넷에서 받은 파일로 표시되어, 실행할 때 Windows가 한 번 더 묻습니다.",
              "남기지 않은 파일과 받는 폴더의 나머지는 지워집니다.",
              f"남길까요? (아니요: 아무것도 남기거나 지우지 않음. {timeout_s:.0f}초 안에 답하지 않으면 아니요)"]
    return "\n".join(lines)


def describe_stop(summary: dict, timeout_s: float = APPROVAL_TIMEOUT_S) -> str:
    """session_stop with --agent-guard: the Agent wants to end the Sandbox."""
    return "\n".join([
        "AI(Codex)가 Sandbox를 끝내려고 합니다.",
        f"AI가 고른 이유: {_clean(summary.get('stop_reason', ''))}", "",
        "끝내면 Sandbox 안의 모든 것이 사라집니다.",
        f"끝낼까요? (아니요: Sandbox를 계속 열어 둠. {timeout_s:.0f}초 안에 답하지 않으면 아니요)"])


def describe_duplicate(summary: dict, timeout_s: float = APPROVAL_TIMEOUT_S) -> str:
    """inbox_download with --agent-guard while a similar file is already in Downloads."""
    lines = ["AI(Codex)가 인터넷에서 새 파일을 받으려고 합니다.", "",
             f"받을 주소: {_clean(summary.get('url', ''))}", "",
             "그런데 다운로드 폴더에 비슷한 파일이 이미 있습니다:"]
    lines += [f"  {_clean(n)}" for n in (summary.get("similar") or [])[:5]]
    lines += ["", f"그래도 인터넷에서 새로 받을까요? (아니요: 받지 않음. {timeout_s:.0f}초 안에 답하지 않으면 아니요)"]
    return "\n".join(lines)


def describe_shared(summary: dict, timeout_s: float = APPROVAL_TIMEOUT_S) -> str:
    """--shared at session end: what the Sandbox saved in its shared folder passed the scan; keep it?"""
    files = summary.get("files") or []
    total = sum(f.get("size", 0) for f in files)
    lines = ["Sandbox가 공유 폴더(바탕화면 Shared)에 저장한 파일이 있습니다. 백신 검사는 통과했습니다.", ""]
    lines += [f"  {_clean(f.get('name', ''))}  ({f.get('size', 0):,} bytes)" for f in files[:15]]
    if len(files) > 15:
        lines.append(f"  ... 외 {len(files) - 15}개")
    lines += [f"  합계 {len(files)}개, {total:,} bytes", "",
              "이 컴퓨터에 남길까요?",
              "  예: 다운로드\\SandboxShared 폴더로 복사 (인터넷에서 받은 파일로 표시, 실행할 때 Windows가 한 번 더 물음)",
              "  아니요: 지움",
              f"  취소 또는 {timeout_s:.0f}초 무응답: 지우지 않고 공유 폴더에 실행 금지 상태로 보관",
              f"  ({_clean(summary.get('share', ''))})"]
    return "\n".join(lines)


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
            base, text = self._question(summary)
            title = f"{base} #{self._seq}"         # unique, so this exact dialog can be closed
            if text is None:
                log.warning("APPROVAL %s denied: the command is too long to show in full", summary.get("tool"))
                return False
            try:
                approved = await asyncio.to_thread(self._ask, text, title)
            except asyncio.CancelledError:
                log.info("APPROVAL %s cancelled; closing its dialog as \"No\"", title)
                self._dismiss(title)
                raise
        log.info("APPROVAL %s %s: %s", summary.get("tool"), summary.get("session_id"),
                 "approved" if approved else "denied")
        return approved

    async def choose_shared(self, summary: dict) -> str:
        """--shared at session end: "keep" (Yes), "delete" (No), "hold" (Cancel, no answer, or no dialog)."""
        async with self._lock:
            self._seq += 1
            title = f"{SHARED_TITLE} #{self._seq}"
            try:
                answer = await asyncio.to_thread(self._ask_code, describe_shared(summary, self.timeout_s), title,
                                                 MB_YESNOCANCEL | MB_DEFBUTTON3)
            except asyncio.CancelledError:
                self._dismiss(title, IDCANCEL)
                raise
        choice = {IDYES: "keep", IDNO: "delete"}.get(answer, "hold")
        log.info("APPROVAL shared folder %s: %s", summary.get("share"), choice)
        return choice

    def _question(self, summary: dict) -> tuple[str, str | None]:
        """(dialog title, text) for this tool; text None = cannot be shown in full, so no."""
        tool = summary.get("tool")
        if tool == "sandbox_run":
            return RUN_TITLE, describe_run(summary, self.timeout_s)
        if tool == "inbox_finish":
            return KEEP_TITLE, describe_keep(summary, self.timeout_s)
        if tool == "session_stop":
            return STOP_TITLE, describe_stop(summary, self.timeout_s)
        if tool == "inbox_download":
            return DUPLICATE_TITLE, describe_duplicate(summary, self.timeout_s)
        return TITLE, describe(summary, self.timeout_s)

    def _dismiss(self, title: str, button: int = None) -> None:
        """Press "No" (or button) on the dialog with this title (in the background; it may still be opening)."""
        button = IDNO if button is None else button
        if sys.platform != "win32":
            return

        def press_no() -> None:
            import ctypes
            user32 = ctypes.WinDLL("user32")
            for _ in range(40):                     # up to 2 s for the window to exist
                hwnd = user32.FindWindowW(None, ctypes.c_wchar_p(title))
                if hwnd:
                    user32.PostMessageW(hwnd, WM_COMMAND, button, 0)
                    return
                time.sleep(0.05)
        threading.Thread(target=press_no, name="approval-dismiss", daemon=True).start()

    def _ask(self, text: str, title: str = TITLE) -> bool:
        return self._ask_code(text, title, MB_YESNO | MB_DEFBUTTON2) == IDYES

    def _ask_code(self, text: str, title: str, buttons: int) -> int:
        """The button pressed (IDYES, IDNO, IDCANCEL), or 0 without Windows, 32000 on timeout."""
        if sys.platform != "win32":
            log.warning("approval dialog needs Windows; no answer")
            return 0
        import ctypes
        user32 = ctypes.WinDLL("user32")
        flags = buttons | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST
        # MessageBoxTimeoutW: exported by user32 since Windows XP; returns 32000 on timeout.
        return user32.MessageBoxTimeoutW(None, ctypes.c_wchar_p(text), ctypes.c_wchar_p(title),
                                         flags, 0, int(self.timeout_s * 1000))


async def deny_all(summary: dict) -> bool:
    """--approval deny: nothing is approved."""
    log.info("APPROVAL %s denied (approval is set to deny)", summary.get("tool"))
    return False
