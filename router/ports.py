"""The complete Router/Host boundary; concrete Host code lives outside this package."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from router.models import Action, Artifact


class State(StrEnum):
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"
    HELD = "HELD"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Request:
    request_id: str
    action: Action


@dataclass(frozen=True)
class Receipt:
    request_id: str
    fingerprint: str
    state: State
    reason: str  # fixed rule code, not exception/command text
    execution_id: str = ""
    evidence_ref: str = ""
    artifacts: tuple[Artifact, ...] = ()
    runtime_id: str = ""
    generation: int = 0


class HostPort(Protocol):
    async def submit(self, request: Request) -> Receipt: ...
    async def status(self, request_id: str) -> Receipt: ...
    async def verify(self, receipt: Receipt) -> bool: ...
    async def artifact(self, artifact_id: str) -> Artifact: ...
