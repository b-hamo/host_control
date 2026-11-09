"""Windows Sandbox와 micro_VM을 한 PC에서 같이 띄우는 시험 (다른 PC 재현용).

Host A는 Windows Sandbox(기존 17443/17444), Host B는 micro_VM 앱 창 VM(loopback, 동적 포트)을 맡는다.
두 Host를 실제 MCP 서버로 띄우고 정해진 순서로 도구를 한 번씩 부른다. 입력은 재시도하지 않는다.

  1. 슬롯 순서대로 task_submit, READY까지 기다려 첫 스크린샷 저장 (READY까지 걸린 시간 기록)
  2. 모든 슬롯이 켜진 상태에서 각 슬롯의 화면을 다시 받아 둘 다 살아 있는지 확인
  3. 슬롯마다 Win+R을 눌러 자기 화면만 바뀌는지 확인 (다른 슬롯 화면은 사람이 PNG로 비교)
  4. 나중에 켠 슬롯부터 session_stop, 남은 슬롯이 계속 살아 있는지 확인
  5. 끝난 뒤 Windows Sandbox가 남아 있지 않은지 확인

절차와 준비물은 docs/mixed-vm-other-pc.md. micro_VM broker 때문에 관리자 PowerShell에서 실행한다.

  python tools/mixed_vm_smoke.py --runner EXE --manager DIR --vm-package DIR --vm-root DIR --relay EXE --work NEW_DIR
  --slots B        micro_VM만 켜고 끈다 (Sandbox를 닫은 상태에서 첫 준비용)
  --slots B,A      micro_VM을 먼저 켜고 Sandbox를 나중에 켠다 (반대 순서)
  --vgpu-off       Sandbox의 vGPU를 끈다 (AMD 드라이버가 Sandbox 시작 중 멈추는 PC용)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import queue
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

HOST = Path(__file__).resolve().parents[1]
READY_TRIES = 30                 # computer_observe(wait_ms=10000) 30번: READY까지 최대 약 5분
INPUT_CHANGE = 0.05              # Win+R 뒤 화면의 5% 이상 줄이 바뀌면 입력이 닿은 것으로 본다


def as_host(argv: list[str]) -> int:
    """이 파일을 Host 실행 래퍼로 쓴다: --vgpu-off면 Sandbox 설정에 VGpu=Disable을 넣고 MCP 서버를 띄운다."""
    if argv and argv[0] == "--vgpu-off":
        argv = argv[1:]
        import sandbox_manager.config as wsb_config
        build = wsb_config.build_wsb
        wsb_config.build_wsb = lambda *a, **k: build(*a, **k).replace(
            "<Configuration>", "<Configuration><VGpu>Disable</VGpu>", 1)
    sys.path.insert(0, str(HOST))
    from host.mcp_server import main
    return main(argv)


def wsb_running() -> list:
    try:
        out = subprocess.run(["wsb", "list", "--raw"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return [f"wsb list failed: {e}"]
    try:
        return json.loads(out).get("WindowsSandboxEnvironments") or []
    except ValueError:
        return [out.strip()] if out.strip() else []


class Host:
    """MCP Host 하나 (stdio). 응답은 별도 스레드가 읽어 큐에 넣는다."""

    def __init__(self, slot: str, a, work: Path):
        self.slot, self.root, self.n = slot, work / slot, 0
        self.root.mkdir(parents=True)
        self.replies: queue.Queue = queue.Queue()
        wss, upload, listen = ("17443", "17444", "0.0.0.0") if slot == "A" else ("0", "0", "127.0.0.1")
        cmd = [sys.executable, str(Path(__file__).resolve()), "--as-host"]
        if slot == "A" and a.vgpu_off:
            cmd.append("--vgpu-off")
        cmd += ["--host", listen, "--port", wss, "--upload-port", upload,
                "--session", "SES-" + uuid.uuid4().hex, "--startup-timeout", str(a.startup_timeout),
                "--runner-exe", str(a.runner), "--sandbox-root", str(self.root / "manager"),
                "--cert-dir", str(self.root / "certs"), "--audit-dir", str(self.root / "audit"),
                "--log-file", str(self.root / "host.log"), "--no-auto-restart"]
        if slot == "B":
            cmd += ["--micro-vm-package", str(a.vm_package), "--micro-vm-root", str(a.vm_root),
                    "--micro-vm-relay", str(a.relay)]
        env = os.environ | {"PYTHONPATH": str(HOST) + os.pathsep + str(a.manager), "PYTHONUTF8": "1",
                            "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        (self.root / "launch.json").write_text(json.dumps({"command": cmd}, ensure_ascii=False, indent=2),
                                               encoding="utf-8")
        self.stderr = (self.root / "stderr.log").open("w", encoding="utf-8")
        self.p = subprocess.Popen(cmd, cwd=HOST, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=self.stderr, text=True, encoding="utf-8")
        threading.Thread(target=self._read, daemon=True).start()
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "mixed_vm_smoke", "version": "1"}}, 60)

    def _read(self):
        for line in self.p.stdout:
            try:
                self.replies.put(json.loads(line))
            except ValueError:
                pass
        self.replies.put(None)

    def request(self, method: str, params: dict, timeout: float = 120) -> dict:
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params},
                                      ensure_ascii=False) + "\n")
        self.p.stdin.flush()
        end = time.monotonic() + timeout
        while True:
            try:
                reply = self.replies.get(timeout=max(0.1, end - time.monotonic()))
            except queue.Empty:
                raise RuntimeError(f"{self.slot}: no reply to {method} within {timeout:.0f} s") from None
            if reply is None:
                raise RuntimeError(f"{self.slot}: Host exited (see {self.root / 'stderr.log'})")
            if reply.get("id") == self.n:
                return reply

    def tool(self, name: str, args: dict, timeout: float = 120):
        """(성공 여부, 본문 JSON, PNG bytes 또는 None)"""
        res = self.request("tools/call", {"name": name, "arguments": args}, timeout).get("result", {})
        text = next((c["text"] for c in res.get("content", []) if c.get("type") == "text"), "{}")
        try:
            body = json.loads(text)
        except ValueError:
            body = {"text": text}
        img = next((c["data"] for c in res.get("content", []) if c.get("type") == "image"), None)
        return not res.get("isError", True), body, base64.b64decode(img) if img else None

    def observe(self, name: str, wait_ms: int = 0):
        ok, body, png = self.tool("computer_observe", {"wait_ms": wait_ms}, timeout=60)
        if png:
            (self.root / f"{name}.png").write_bytes(png)
        return png, body

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(180)
        except (OSError, subprocess.TimeoutExpired):
            self.p.kill()
        self.stderr.close()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--as-host":
        return as_host(argv[1:])
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runner", type=Path, required=True, help="sandbox_runner.exe (develop 빌드)")
    ap.add_argument("--manager", type=Path, required=True, help="sandbox_manager checkout (develop)")
    ap.add_argument("--vm-package", type=Path, help="micro_VM 묶음 폴더 (dbictl.exe가 있는 곳)")
    ap.add_argument("--vm-root", type=Path, help="micro_VM broker 상태 폴더")
    ap.add_argument("--relay", type=Path, help="ScrpRelay.exe")
    ap.add_argument("--work", type=Path, required=True, help="새 증거 폴더 (이미 있으면 거부)")
    ap.add_argument("--slots", default="A,B", help="켜는 순서. A=Windows Sandbox, B=micro_VM (기본 A,B)")
    ap.add_argument("--vgpu-off", action="store_true")
    ap.add_argument("--startup-timeout", type=int, default=240)
    a = ap.parse_args(argv)
    slots = a.slots.split(",")
    if not slots or len(set(slots)) != len(slots) or any(s not in ("A", "B") for s in slots):
        ap.error("--slots는 A와 B를 한 번씩만: A,B / B,A / A / B")
    if "B" in slots and not (a.vm_package and a.vm_root and a.relay):
        ap.error("B(micro_VM)에는 --vm-package, --vm-root, --relay가 필요함")
    if a.work.exists():
        ap.error(f"{a.work}가 이미 있음: 매번 새 폴더를 쓴다")
    for p in (a.runner, a.relay):
        if p and not p.is_file():
            ap.error(f"파일이 없음: {p}")
    if "A" in slots and wsb_running():
        ap.error("Windows Sandbox가 이미 켜져 있음: 닫고 다시 실행")
    sys.path.insert(0, str(HOST))
    from host.sandbox_run import screen_change

    a.work.mkdir(parents=True)
    steps, t0, hosts = [], time.monotonic(), {}

    def step(name, ok, detail=""):
        steps.append({"t": round(time.monotonic() - t0, 1), "step": name, "ok": bool(ok), "detail": detail})
        print(f"[{time.monotonic() - t0:6.1f}s] {'OK ' if ok else 'BAD'} {name} {detail}", flush=True)

    try:
        # 1. 순서대로 켜기
        for s in slots:
            started = time.monotonic()
            h = hosts[s] = Host(s, a, a.work)
            ok, body, _ = h.tool("task_submit", {"goal": f"mixed VM smoke: slot {s}"}, timeout=a.startup_timeout + 60)
            step(f"{s} task_submit", ok, json.dumps(body, ensure_ascii=False)[:200])
            png = None
            for i in range(READY_TRIES):
                png, body = h.observe("1-ready", wait_ms=0 if i == 0 else 10000)
                if png:
                    break
            step(f"{s} READY + screenshot", png, f"{time.monotonic() - started:.0f} s"
                 if png else str(body.get("error") or body)[:200])
            if not png:
                raise RuntimeError(f"{s} never became READY")
            if "A" in hosts and s != "A":
                left = wsb_running()
                step("Windows Sandbox still running after the other slot started", left, str(left)[:120])

        # 2. 모두 켜진 상태
        if len(hosts) > 1:
            for s, h in hosts.items():
                png, body = h.observe("2-together")
                step(f"{s} alive while every slot is up", png, "" if png else str(body)[:200])

        # 3. 입력이 자기 VM에만 닿는지
        for s, h in hosts.items():
            others = {o: hosts[o].observe(f"3-{o}-before-{s}-input")[0] for o in hosts if o != s}
            before, _ = h.observe(f"3-{s}-before-input")
            ok, body, _ = h.tool("computer_hotkey", {"keys": ["win", "r"]})
            after, _ = h.observe(f"3-{s}-after-win-r", wait_ms=1500)
            change = screen_change(before, after)
            step(f"{s} Win+R changed its own screen", ok and change is not None and change >= INPUT_CHANGE,
                 f"changed rows {change:.1%}" if change is not None else str(body)[:200])
            for o in others:
                other_after, _ = hosts[o].observe(f"3-{o}-after-{s}-input")
                c = screen_change(others[o], other_after)
                print(f"         {o} screen while {s} got input: changed rows "
                      f"{'?' if c is None else f'{c:.1%}'} (compare 3-{o}-*.png by eye)", flush=True)
            h.tool("computer_keypress", {"key": "escape"})

        # 4. 나중에 켠 것부터 끄기
        for s in reversed(slots):
            ok, body, _ = hosts[s].tool("session_stop", {"reason": "TASK_COMPLETE"}, timeout=180)
            step(f"{s} session_stop", ok, json.dumps(body, ensure_ascii=False)[:200])
            for o in slots[:slots.index(s)]:            # 아직 안 끈 슬롯
                png, body = hosts[o].observe(f"4-{o}-after-{s}-stop")
                step(f"{o} still alive after {s} stopped", png, "" if png else str(body)[:200])
    except Exception as e:  # noqa: BLE001 - every failure ends up in result.json
        step("driver", False, f"{type(e).__name__}: {e}")
    finally:
        for h in hosts.values():
            h.close()
        if "A" in slots:
            left = wsb_running()
            step("no Windows Sandbox left", not left, str(left)[:120])

    passed = all(x["ok"] for x in steps)
    (a.work / "result.json").write_text(json.dumps({"slots": slots, "vgpu_off": a.vgpu_off,
                                                    "passed": passed, "steps": steps},
                                                   ensure_ascii=False, indent=2), encoding="utf-8")
    print("RESULT", "PASS" if passed else "FAIL", "->", a.work / "result.json")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
