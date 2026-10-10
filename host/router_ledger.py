"""Host-private durable idempotency records: no commands, text or raw errors."""

import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from router.models import Artifact
from router.ports import Receipt, Request, State


class Ledger:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS requests "
                        "(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, receipt TEXT)")
        self.db.commit()

    @staticmethod
    def _key(request_id: str) -> str:
        return hashlib.sha256(request_id.encode()).hexdigest()

    def reserve(self, request: Request) -> bool:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            key, fp = self._key(request.request_id), request.action.fingerprint
            if self.db.execute("SELECT 1 FROM requests WHERE id=?", (key,)).fetchone():
                self.db.commit()
                return False
            same = self.db.execute("SELECT receipt FROM requests WHERE fingerprint=? LIMIT 1", (fp,)).fetchone()
            self.db.execute("INSERT INTO requests VALUES (?, ?, ?)", (key, fp, same[0] if same else None))
            self.db.commit()
            return same is None
        except BaseException:
            self.db.rollback()
            raise

    def get(self, request_id: str) -> Receipt:
        row = self.db.execute("SELECT fingerprint, receipt FROM requests WHERE id=?",
                              (self._key(request_id),)).fetchone()
        if row is None:
            return Receipt(request_id, "", State.UNKNOWN, "REQUEST_NOT_FOUND")
        if row[1] is None:
            return Receipt(request_id, row[0], State.UNKNOWN, "EXECUTION_UNCONFIRMED")
        data = json.loads(row[1])
        data["request_id"] = request_id
        data["state"] = State(data["state"])
        data["artifacts"] = tuple(Artifact(**{**a, "source_ids": tuple(a["source_ids"])})
                                  for a in data["artifacts"])
        return Receipt(**data)

    def put(self, receipt: Receipt) -> None:
        data = asdict(receipt)
        del data["request_id"]
        with self.db:
            cursor = self.db.execute("UPDATE requests SET receipt=? WHERE id=? AND fingerprint=?",
                                     (json.dumps(data), self._key(receipt.request_id), receipt.fingerprint))
            if cursor.rowcount != 1:
                raise ValueError("receipt does not match reservation")

    def close(self):
        self.db.close()
