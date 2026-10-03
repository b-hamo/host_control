"""Audit log of every tool call (spec B-9).

One JSON object per line, in call order: timestamp, session_id, task_id,
action_id, tool, arguments, policy result, runtime_id, result, latency.
Sensitive input is not stored as-is: typed text becomes its length and a
SHA-256, so the log proves what was sent without containing it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

MASKED_FIELDS = {"computer_type": ("text",)}


def mask(tool: str, args: dict) -> dict:
    out = dict(args)
    for field in MASKED_FIELDS.get(tool, ()):
        if isinstance(out.get(field), str):
            raw = out[field].encode("utf-8")
            out[field] = {"masked": True, "chars": len(out[field]), "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()}
    return out


class AuditLog:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.records: list[dict] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, **fields) -> dict:
        rec = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), **fields}
        self.records.append(rec)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec
