"""SCRP message validation.

Order of checks mirrors protocol doc section 5/7: byte size before parsing,
strict UTF-8, JSON with duplicate keys / NaN / Infinity rejected, nesting depth,
then the envelope schema, then the per-type payload schema. Any failure raises
ProtocolError with a code from the envelope's error.code enum so callers can
answer with a well-formed ERROR message.

The Host uses this module. The Runner is written in C++ and validates the same
schema/ JSON files with its own validator, so those files, not this code, are
the single source of truth for what a message may look like.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

# Frozen (PyInstaller) builds carry schema/ inside the bundle.
_BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
SCHEMA_DIR = _BASE / "schema"
MAX_MESSAGE_BYTES = 64 * 1024
MAX_DEPTH = 16


class ProtocolError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _load(path: Path) -> Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


_envelope = _load(SCHEMA_DIR / "envelope.schema.json")
_payloads: dict[str, Draft202012Validator] = {}
MESSAGE_TYPES: frozenset[str] = frozenset(_envelope.schema["$defs"]["message_type"]["enum"])


def _payload_validator(msg_type: str) -> Draft202012Validator:
    if msg_type not in _payloads:
        path = SCHEMA_DIR / "payload" / f"{msg_type}.schema.json"
        if not path.exists():
            raise ProtocolError("UNSUPPORTED_TYPE", f"no payload schema for {msg_type}")
        _payloads[msg_type] = _load(path)
    return _payloads[msg_type]


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ProtocolError("PROTOCOL_DENIED", f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_non_finite(token: str):
    raise ProtocolError("PROTOCOL_DENIED", f"non-finite number {token}")


def _depth(obj: object, level: int = 1) -> int:
    if isinstance(obj, dict):
        return max((_depth(v, level + 1) for v in obj.values()), default=level)
    if isinstance(obj, list):
        return max((_depth(v, level + 1) for v in obj), default=level)
    return level


def parse(raw: bytes | str) -> dict:
    """Bytes/str of one WebSocket text frame -> dict, or ProtocolError."""
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("MESSAGE_TOO_LARGE", f"{len(data)} bytes > {MAX_MESSAGE_BYTES}")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise ProtocolError("PROTOCOL_DENIED", f"invalid UTF-8 at byte {e.start}") from None
    try:
        obj = json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_non_finite)
    except json.JSONDecodeError as e:
        raise ProtocolError("PROTOCOL_DENIED", f"malformed JSON: {e.msg}") from None
    if not isinstance(obj, dict):
        raise ProtocolError("PROTOCOL_DENIED", "top-level JSON value must be an object")
    if _depth(obj) > MAX_DEPTH:
        raise ProtocolError("PROTOCOL_DENIED", f"nesting deeper than {MAX_DEPTH}")
    return obj


def validate(msg: dict) -> None:
    """Envelope schema, then the payload schema for msg['type']."""
    err = best_match(_envelope.iter_errors(msg))
    if err is not None:
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        raise ProtocolError("PROTOCOL_DENIED", f"envelope {where}: {err.message}")
    msg_type = msg["type"]
    err = best_match(_payload_validator(msg_type).iter_errors(msg["payload"]))
    if err is not None:
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        raise ProtocolError("INVALID_ARGUMENT", f"{msg_type} payload {where}: {err.message}")


def parse_and_validate(raw: bytes | str) -> dict:
    msg = parse(raw)
    validate(msg)
    return msg
