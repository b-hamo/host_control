"""Session registry: which Runner may connect, and with which one-time token.

Stands in for the Lifecycle Manager's session creation (protocol doc §4 step 1)
until that exists. Each record binds session_id, runtime_id and generation to a
256-bit bootstrap token that is valid for five minutes and can be used once; a
used token is never reactivated (§4). The Broker's session binding (spec B-3)
is meant to reuse these records.

Two kinds of token open the control channel: the bootstrap token from the
bootstrap file, and a reconnect token handed out in each HELLO_ACK (§4). Only
the newest reconnect token of a session is valid, and TERMINATE revokes all.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

TOKEN_TTL_S = 300.0
# A reconnect token has to outlive the connection it was issued on, and there
# is no message to refresh it mid-connection yet, so it lives longer than the
# bootstrap token. It is still single use and superseded on every reconnect.
RECONNECT_TTL_S = 3600.0


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
    kind: str = "bootstrap"                        # "bootstrap" or "reconnect"
    revoked: bool = False

    def identity(self) -> tuple[str, str, int]:
        return (self.session_id, self.runtime_id, self.generation)


class SessionRegistry:
    def __init__(self, ttl_s: float = TOKEN_TTL_S, clock=time.monotonic):
        self._ttl_s = ttl_s
        self._clock = clock
        self._by_token: dict[str, SessionRecord] = {}

    def issue(self, session_id: str, runtime_id: str, generation: int, *,
              kind: str = "bootstrap", ttl_s: float | None = None) -> SessionRecord:
        ttl_s = self._ttl_s if ttl_s is None else ttl_s
        deadline_utc = datetime.now(timezone.utc) + timedelta(seconds=ttl_s)
        rec = SessionRecord(
            session_id, runtime_id, generation,
            token=secrets.token_urlsafe(32),
            expires_at=self._clock() + ttl_s,
            expires_utc=deadline_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            kind=kind,
        )
        self._by_token[rec.token] = rec
        return rec

    def issue_reconnect(self, identity: tuple[str, str, int],
                        ttl_s: float = RECONNECT_TTL_S) -> SessionRecord:
        """New reconnect token for this session; any older one stops working."""
        self.revoke(identity, kind="reconnect")
        return self.issue(*identity, kind="reconnect", ttl_s=ttl_s)

    def revoke(self, identity: tuple[str, str, int], kind: str | None = None) -> None:
        for rec in self._by_token.values():
            if rec.identity() == identity and (kind is None or rec.kind == kind):
                rec.revoked = True

    def check(self, token: str | None) -> SessionRecord:
        """Validate without using the token; for the pre-upgrade check."""
        if not token:
            raise AuthError("missing token")
        rec = self._by_token.get(token)
        if rec is None:
            raise AuthError("unknown token")
        if rec.consumed:
            raise AuthError(f"{rec.kind} token for {rec.session_id} already used")
        if rec.revoked:
            raise AuthError(f"{rec.kind} token for {rec.session_id} revoked")
        if self._clock() >= rec.expires_at:
            raise AuthError(f"{rec.kind} token for {rec.session_id} expired")
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
