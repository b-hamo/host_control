"""SecureArtifactScanner performance measurement (a tool, not a test). Run elevated, service installed:

    python tests\\scanner_perf.py [--reps 3] [--out build\\perf-report.json]

Measures, against the installed service and the real Microsoft Defender:
  service start (SCM start → RUNNING → first HEALTH_CHECK), the EICAR self-test,
  per file size: pipe upload, Defender scan (SCAN → SCANNED), disposal (ABORT → job directory gone),
  Host end to end for a 1 MiB TXT (artifact_export → EXPORTED; HTTPS+pipe transfer inside it),
  4 concurrent 1 MiB jobs: wall time, service and MsMpEng CPU and memory.
Elevated because it restarts the service and reads the service's and Defender's process counters.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import statistics
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from host.artifact_scan import DefenderServiceScanner  # noqa: E402
from host.scanner_client import ScannerServiceClient, job_identity  # noqa: E402
from scanner_service.config import SERVICE_NAME, default_data_root  # noqa: E402
from scanner_service.ipc_client import service_pid  # noqa: E402

MIB = 1024 * 1024
SIZES = [1024, 64 * 1024, 256 * 1024, MIB]


def text_of(size: int) -> bytes:
    line = b"SecureArtifactScanner performance sample line 0123456789 abcdefghijklmnopqrstuvwxyz\n"
    return (line * (size // len(line) + 1))[:size]


def stats(xs: list[float]) -> dict:
    return {"min": round(min(xs), 3), "median": round(statistics.median(xs), 3), "max": round(max(xs), 3),
            "runs": len(xs)}


# ----------------------------------------------------------------------------- process counters
class Sampler:
    """CPU (kernel+user time delta) and working set of processes, every 100 ms."""

    def __init__(self, pids: dict[str, int]):
        import win32api
        import win32con
        self.handles, self.errors = {}, {}
        for name, pid in pids.items():
            if not pid:
                continue
            try:                                  # MsMpEng is a protected process: query rights only
                self.handles[name] = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            except Exception as e:  # noqa: BLE001
                self.errors[name] = str(e)
        self.samples: dict[str, list[tuple[float, float, int]]] = {n: [] for n in self.handles}
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _read(self, h):
        import win32process
        t = win32process.GetProcessTimes(h)
        cpu = (t["KernelTime"] + t["UserTime"]) / 1e7
        try:
            mem = win32process.GetProcessMemoryInfo(h)["WorkingSetSize"]
        except Exception:  # noqa: BLE001 - protected process: CPU only
            mem = 0
        return cpu, mem

    def _run(self):
        while not self._stop.is_set():
            now = time.monotonic()
            for n, h in self.handles.items():
                try:
                    cpu, mem = self._read(h)
                    self.samples[n].append((now, cpu, mem))
                except Exception:  # noqa: BLE001
                    pass
            self._stop.wait(0.1)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join()

    def report(self) -> dict:
        import os
        out = {n: {"unavailable": e} for n, e in self.errors.items()}
        cores = os.cpu_count() or 1
        for n, s in self.samples.items():
            if len(s) < 2:
                continue
            pct = [100 * (b[1] - a[1]) / max(1e-6, b[0] - a[0]) / cores for a, b in zip(s, s[1:])]
            out[n] = {"cpu_percent_of_machine_avg": round(statistics.mean(pct), 1),
                      "cpu_percent_of_machine_peak": round(max(pct), 1),
                      "cpu_seconds": round(s[-1][1] - s[0][1], 3),
                      "working_set_mib_peak": round(max(x[2] for x in s) / MIB, 1) or None,
                      "working_set_mib_start": round(s[0][2] / MIB, 1) or None}
        return out


def pid_of(image: str) -> int | None:
    import subprocess
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {image}", "/FO", "CSV", "/NH"], capture_output=True,
                         text=True).stdout
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) > 1 and parts[0].lower() == image.lower():
            return int(parts[1])
    return None


# ----------------------------------------------------------------------------- measurements
def measure_start(reps: int) -> dict:
    import win32service
    import win32serviceutil
    client = ScannerServiceClient()
    running, healthy = [], []
    for _ in range(reps):
        win32serviceutil.StopService(SERVICE_NAME)
        win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_STOPPED, 60)
        t0 = time.perf_counter()
        win32serviceutil.StartService(SERVICE_NAME)
        win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_RUNNING, 60)
        running.append(time.perf_counter() - t0)
        while True:
            try:
                asyncio.run(client.health())
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.02)
        healthy.append(time.perf_counter() - t0)
    t = time.perf_counter()
    h = asyncio.run(client.health())                       # plain health, before the self-test
    plain = time.perf_counter() - t
    t = time.perf_counter()
    _selftest()
    selftest = time.perf_counter() - t
    return {"scm_start_to_running_s": stats(running), "scm_start_to_first_health_s": stats(healthy),
            "health_check_s": round(plain, 4), "eicar_selftest_s": round(selftest, 3),
            "service_version": h.get("version")}


def _selftest():
    c = ScannerServiceClient(timeout_s=120)
    return c._once("HEALTH_CHECK", payload={"selftest": True})


async def one_job(c: ScannerServiceClient, size: int, tag: str) -> dict:
    data = text_of(size)
    ident = job_identity((f"SES-PERF-{tag}", "RT-PERF", 1), "ART-000001")
    t0 = time.perf_counter()
    up = c.upload(ident)
    job = await up.begin("perf.txt", size)
    for off in range(0, size, 64 * 1024):
        await up.write(data[off:off + 64 * 1024])
    await up.complete(hashlib.sha256(data).hexdigest())
    await up.close()
    t1 = time.perf_counter()
    v = await c.scan(ident, job)
    while v["state"] == "SCANNING":
        await asyncio.sleep(0.02)
        v = await c.status(ident, job)
    t2 = time.perf_counter()
    assert v["state"] == "SCANNED", v
    await c.abort(ident, job, "perf done")
    jobdir = default_data_root() / "Quarantine" / f"session-SES-PERF-{tag}" / job
    while jobdir.exists():
        await asyncio.sleep(0.005)
    t3 = time.perf_counter()
    return {"upload_s": t1 - t0, "scan_s": t2 - t1, "dispose_s": t3 - t2,
            "mpcmdrun_s": (v.get("scan") or {}).get("duration_s")}


def measure_sizes(reps: int) -> dict:
    c = ScannerServiceClient(timeout_s=120)
    asyncio.run(one_job(c, 1024, "WARM"))                  # the first scan after a start runs the self-test
    out = {}
    for size in SIZES:
        runs = [asyncio.run(one_job(c, size, f"S{size}-{i}")) for i in range(reps)]
        out[f"{size}"] = {k: stats([r[k] for r in runs if r[k] is not None]) for k in runs[0]}
    return out


def measure_concurrent(n: int = 4) -> dict:
    c = ScannerServiceClient(timeout_s=120)
    pids = {"SecureArtifactScanner": service_pid(), "MsMpEng": pid_of("MsMpEng.exe")}
    results = []
    with Sampler(pids) as s:
        t0 = time.perf_counter()

        def worker(i):
            results.append(asyncio.run(one_job(c, MIB, f"C{i}")))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = time.perf_counter() - t0
    return {"jobs": n, "size_bytes": MIB, "wall_s": round(wall, 3),
            "per_job_scan_s": stats([r["scan_s"] for r in results]),
            "per_job_upload_s": stats([r["upload_s"] for r in results]), "processes": s.report()}


def measure_host_e2e(reps: int, tmp: Path) -> dict:
    from test_artifact_export import Approver, Host
    scanner = DefenderServiceScanner()
    export_root = Path(asyncio.run(scanner.client.health())["publish"]["export_root"])
    data = text_of(MIB)
    out = []

    async def body(i):
        session = f"SES-PERF-E2E-{i}"
        host = Host(tmp / f"h{i}", approver=Approver(), scanner=scanner, export_dir=export_root, session=session)
        grants = host.backend.artifacts.grants
        real = grants.receive
        timing = {}

        async def timed(grant, reader, length):
            t = time.perf_counter()
            try:
                return await real(grant, reader, length)
            finally:
                timing["https_and_pipe_transfer_s"] = time.perf_counter() - t
        grants.receive = timed
        r, serving = await host.start()
        await r.report("perf.txt", data)
        lst = await host.call("artifact_list", {})
        aid = lst["artifacts"][0]["artifact_id"]
        t0 = time.perf_counter()
        await host.call("artifact_export", {"artifact_id": aid})
        final = await host.wait_artifact(aid, timeout=240)
        timing["export_call_to_exported_s"] = time.perf_counter() - t0
        assert final["status"] == "EXPORTED", final
        Path(final["export_path"]).unlink()
        for d in (export_root / session / aid, export_root / session):
            d.rmdir()
        await host.close(serving)
        return timing
    for i in range(reps):
        (tmp / f"h{i}").mkdir(parents=True, exist_ok=True)
        out.append(asyncio.run(body(i)))
    return {k: stats([o[k] for o in out]) for k in out[0]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "perf-report.json")
    a = ap.parse_args()
    import platform
    import tempfile
    report = {"machine": {"os": platform.platform(), "cpu_count": __import__("os").cpu_count(),
                          "processor": platform.processor()},
              "measured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    a.out.parent.mkdir(parents=True, exist_ok=True)

    def section(name, fn):
        try:
            report[name] = fn()
        except Exception as e:  # noqa: BLE001 - keep the other sections
            report[name] = {"error": f"{type(e).__name__}: {e}"}
        a.out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    section("service_start", lambda: measure_start(a.reps))
    section("per_size_service", lambda: measure_sizes(a.reps))
    with tempfile.TemporaryDirectory(prefix="sas-perf-") as tmp:
        section("host_end_to_end_1mib", lambda: measure_host_e2e(a.reps, Path(tmp)))
    section("concurrent_4x1mib", lambda: measure_concurrent(4))
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
