"""Envelope construction for one side of an SCRP connection.

An Endpoint owns the identity fields (session/runtime/generation/connection)
and the outbound sequence counter, so every message it builds is consistent
with schema/envelope.schema.json. Used by the Host sender.
"""

from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone

VERSION = "1.0"

RESPONSE_TYPES = {
    "HELLO": "HELLO_ACK",
    "OBSERVE": "OBSERVE_RESULT",
    "ACTION_REQUEST": "ACTION_RESULT",
    "STATE_REQUEST": "STATE_RESULT",
    "HEARTBEAT": "ALIVE",
    "ARTIFACT_REQUEST": "ARTIFACT_RESULT",
    "TERMINATE": "TERMINATE_RESULT",
    "CHANNEL_HELLO": "CHANNEL_ACK",
    "SECURITY_EVENT": "EVENT_ACK",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def parse_utc(ts: str) -> datetime:
    return datetime.strptime(ts.rstrip("Z").split(".")[0], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def new_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")


def new_message_id() -> str:
    return str(uuid.uuid4())


class Endpoint:
    def __init__(self, session_id: str, runtime_id: str, generation: int, connection_id: str | None = None):
        self.session_id = session_id
        self.runtime_id = runtime_id
        self.generation = generation
        self.connection_id = connection_id
        self.sequence = 0

    def envelope(self, msg_type: str, payload: dict, *, task_id: str | None = None,
                 action_id: str | None = None, correlation_id: str | None = None,
                 status: str | None = None, error: dict | None = None) -> dict:
        self.sequence += 1
        return {
            "version": VERSION,
            "session_id": self.session_id,
            "runtime_id": self.runtime_id,
            "generation": self.generation,
            "connection_id": self.connection_id,
            "message_id": new_message_id(),
            "task_id": task_id,
            "action_id": action_id,
            "sequence_number": self.sequence,
            "timestamp": now_utc(),
            "nonce": new_nonce(),
            "type": msg_type,
            "correlation_id": correlation_id,
            "status": status,
            "error": error,
            "payload": payload,
        }

    def reply(self, request: dict, msg_type: str, payload: dict, *, status: str = "OK") -> dict:
        """Response envelope bound to `request` (same task/action, correlation_id = its message_id)."""
        return self.envelope(msg_type, payload, task_id=request["task_id"], action_id=request["action_id"],
                             correlation_id=request["message_id"], status=status)

    def error(self, code: str, message: str, *, correlation_id: str | None = None,
              retryable: bool = False, next_step: str | None = None) -> dict:
        return self.envelope("ERROR", {}, correlation_id=correlation_id, status="ERROR", error={
            "code": code, "message": message[:1024], "retryable": retryable, "recommended_next_step": next_step,
        })
