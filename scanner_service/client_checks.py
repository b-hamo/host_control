"""`SecureArtifactScanner.exe client ...`: end-to-end checks against the running service.

Used by installer/verify.ps1. Prints one JSON document and exits 0 only when the service
behaved as expected (benign → SCANNED [→ EXPORTED], eicar → BLOCKED MALWARE_DETECTED).
"""

from __future__ import annotations

import json
import secrets

from scanner_service.config import PIPE_NAME
from scanner_service.defender_scanner import eicar
from scanner_service.ipc_client import ScannerClient, service_pid
from scanner_service.models import Identity, ScannerError

BENIGN = "SecureArtifactScanner verify: benign text file.\n검사 서비스 확인용 텍스트.\n".encode("utf-8")


def _client(args) -> ScannerClient:
    pid = None if args.no_verify_server or args.pipe else service_pid()
    if pid is None and not (args.no_verify_server or args.pipe):
        raise ConnectionError("SecureArtifactScanner service is not running")
    return ScannerClient(args.pipe or PIPE_NAME, timeout_s=30.0, expected_server_pid=pid)


def run_client(args) -> int:
    out: dict = {}
    ok = False
    try:
        with _client(args) as c:
            if args.action == "health":
                out = c.health(selftest=args.selftest)
                t = out["token"]
                ok = (not t["is_admin"] and not t["administrators_group"] and not t["is_local_system"]
                      and out["defender"]["available"]
                      and (not args.selftest or bool((out["defender"].get("selftest") or {}).get("ok"))))
            else:
                ok, out = _roundtrip(c, args)
    except (ConnectionError, ScannerError, TimeoutError, OSError) as e:
        out = {"error": f"{type(e).__name__}: {e}"}
    out["check_passed"] = ok
    print(json.dumps(out, ensure_ascii=True, indent=2))      # ASCII: safe in any console code page
    return 0 if ok else 1


def _roundtrip(c: ScannerClient, args) -> tuple[bool, dict]:
    ident = Identity("SES-VERIFY-" + secrets.token_hex(3).upper(), "RT-VERIFY", 1, "ART-VERIFY-001")
    data = BENIGN if args.content == "benign" else eicar()
    try:
        job = c.upload(ident, "verify-result.txt", data)
    except ScannerError as e:
        # real-time protection may already remove the EICAR file when the upload completes
        detected = args.content == "eicar" and e.code == "MALWARE_DETECTED"
        return detected, {"steps": {"uploaded": f"refused {e.code}"}, "error": {"code": e.code, "message": e.message}}
    steps = {"uploaded": job["state"]}
    view = c.scan(ident, job["job_id"], args.timeout)
    steps["scanned"] = view["state"]
    result: dict = {"job_id": job["job_id"], "steps": steps, "scan": view.get("scan"), "error": view.get("error")}
    if args.content == "eicar":
        ok = view.get("outcome") == "BLOCKED" and (view.get("error") or {}).get("code") == "MALWARE_DETECTED"
        final = c.wait(ident, job["job_id"], ("DISPOSED",), 30)
        result["final_state"], result["cleanup_error"] = final["state"], final.get("cleanup_error")
        return ok and final["state"] == "DISPOSED", result
    if view["state"] != "SCANNED":
        return False, result
    if args.publish:
        pub = c.publish(ident, view)
        result["published"] = {"outcome": pub.get("outcome"), "export_path": pub.get("export_path"),
                               "state": pub["state"]}
        final = c.wait(ident, job["job_id"], ("DISPOSED",), 30)
        result["final_state"], result["cleanup_error"] = final["state"], final.get("cleanup_error")
        return pub.get("outcome") == "EXPORTED" and final["state"] == "DISPOSED", result
    if args.keep:
        result["final_state"] = view["state"]
        return True, result
    end = c.call("ABORT", ident, job["job_id"], {"reason": "verify finished"})
    result["final_state"], result["cleanup_error"] = end["state"], end.get("cleanup_error")
    return end["state"] == "DISPOSED", result

