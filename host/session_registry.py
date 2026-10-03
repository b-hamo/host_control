"""Session registry: which Runner may connect, and with which one-time token.

Stands in for the Lifecycle Manager's session creation (protocol doc §4 step 1)
until that exists. Each record binds session_id, runtime_id and generation to a
256-bit bootstrap token that is valid for five minutes and can be used once; a
used token is never reactivated (§4). The Broker's session binding (spec B-3)
is meant to reuse these records.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

TOKEN_TTL_S = 300.0


class AuthError(Exception):
    """Why a connection was refused. The reason goes to the Host log only."""


@dataclass
class SessionRecord:
    session_id: str
    runtime_id: str
    generation: int
    token: str = field(repr=False)
    expires_at: float = field(repr=False)          # time.monotonic() deadline
    expires_utc: str = ""                          # same deadline, for the bootstrap file
    consumed: bool = False

    def identity(self) -> tuple[str, str, int]:
        return (self.session_id, self.runtime_id, self.generation)


class SessionRegistry:
    def __init__(self, ttl_s: float = TOKEN_TTL_S, clock=time.monotonic):
        self._ttl_s = ttl_s
        self._clock = clock
        self._by_token: dict[str, SessionRecord] = {}

    def issue(self, session_id: str, runtime_id: str, generation: int) -> SessionRecord:
        deadline_utc = datetime.now(timezone.utc) + timedelta(seconds=self._ttl_s)
        rec = SessionRecord(
            session_id, runtime_id, generation,
            token=secrets.token_urlsafe(32),
            expires_at=self._clock() + self._ttl_s,
            expires_utc=deadline_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self._by_token[rec.token] = rec
        return rec

    def check(self, token: str | None) -> SessionRecord:
        """Validate without using the token; for the pre-upgrade check."""
        if not token:
            raise AuthError("missing token")
        rec = self._by_token.get(token)
        if rec is None:
            raise AuthError("unknown token")
        if rec.consumed:
            raise AuthError(f"token for {rec.session_id} already used")
        if self._clock() >= rec.expires_at:
            raise AuthError(f"token for {rec.session_id} expired")
        return rec

    def consume(self, token: str | None) -> SessionRecord:
        """Validate and mark used. There is no await between the two, so on the
        event loop this is atomic: of two connections racing with one token,
        exactly one gets the record."""
        rec = self.check(token)
        rec.consumed = True
        return rec


def bearer_token(header_value: str | None) -> str | None:
    if not header_value:
        return None
    scheme, _, value = header_value.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()
