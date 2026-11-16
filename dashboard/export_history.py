"""Read retained blocked Output receipts; never open the quarantined payload files."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

_CODE = re.compile(r"^([A-Z][A-Z0-9_]+)(?::|$)")
MAX_JOURNAL_BYTES = 4 * 1024 * 1024


def blocked_exports(roots):
    """Compatibility for Hosts without exports publishing. Caller explicitly selects trusted roots."""
    seen = set()
    for root in roots:
        root = Path(root).resolve()
        paths = [root / "output-state.json"]
        for pattern in ("SES-*/output-state.json", "output/SES-*/output-state.json",
                        "clients/*/output/SES-*/output-state.json"):
            paths.extend(root.glob(pattern))
        for path in paths:
            try:
                resolved = path.resolve()
                if resolved in seen or not resolved.is_relative_to(root):
                    continue
                seen.add(resolved)
                stat = path.stat()
                if stat.st_size > MAX_JOURNAL_BYTES:
                    continue
                record = json.loads(path.read_text(encoding="utf-8-sig"))
                rows = record.get("files", []) if isinstance(record, dict) else []
                if not isinstance(rows, list):
                    continue
                updated = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")
            except (OSError, ValueError):
                continue
            for row in rows:
                if not isinstance(row, dict) or row.get("stage") not in ("BLOCKED", "QUARANTINED", "FAILED"):
                    continue
                identity, aid = row.get("identity"), row.get("artifact_id")
                if (not isinstance(identity, list) or not identity or not isinstance(identity[0], str)
                        or not identity[0].startswith("SES-") or not isinstance(aid, str)):
                    continue
                if path.parent.name.startswith("SES-") and identity[0] != path.parent.name:
                    continue
                result = row.get("result") if isinstance(row.get("result"), dict) else {}
                detail, code = result.get("detail"), result.get("code")
                if isinstance(detail, dict):
                    error = detail.get("error")
                    scan = detail.get("code") or (error.get("code") if isinstance(error, dict) else None)
                else:
                    match = _CODE.match(detail.strip()) if isinstance(detail, str) else None
                    scan = match.group(1) if match else None
                    if isinstance(detail, str) and re.match(r"^SCAN_ERROR: \[WinError (?:225|226)\](?: |$)", detail.strip()):
                        scan = "WINDOWS_MALWARE_BLOCKED"
                name = str(row.get("path") or aid).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
                yield {"artifact_id": aid, "session_id": identity[0], "name": name, "stage": row["stage"],
                       "code": code if isinstance(code, str) else None,
                       "scan_code": scan if isinstance(scan, str) else None,
                       "observed_at": updated, "finished_at": updated, "export_path": None,
                       "time_source": "journal_updated_at"}
