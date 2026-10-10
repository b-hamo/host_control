"""Immutable boundary values. Agent claims are evidence to check, never authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum


class Location(StrEnum):
    LOCAL = "LOCAL"
    SANDBOX = "SANDBOX"


class Operation(StrEnum):
    READ_TEXT = "read_text"
    WRITE_TEXT = "write_text"
    SEARCH = "search"
    BROWSE = "browse"
    EXECUTE = "execute"
    BUILD = "build"
    TEST = "test"


EXECUTION = frozenset({Operation.EXECUTE, Operation.BUILD, Operation.TEST})


def identifier(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", value):
        raise ValueError("invalid identifier")


def strings(values: tuple[str, ...]) -> None:
    if type(values) is not tuple or any(not isinstance(v, str) or not v or "\0" in v for v in values):
        raise ValueError("expected immutable nonempty strings")
    if len(values) != len(set(values)):
        raise ValueError("duplicate values")


def digest(value) -> str:
    return hashlib.sha256(json.dumps(asdict(value), sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Source:
    source_id: str
    reference: str
    sha256: str
    origin: str  # external / local / generated / unknown, checked by Host
    parents: tuple[str, ...] = ()

    def __post_init__(self):
        identifier(self.source_id)
        strings((self.reference,))
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("source requires a content digest")
        if self.origin not in {"external", "local", "generated", "unknown"}:
            raise ValueError("invalid origin")
        strings(self.parents)
        for parent in self.parents:
            identifier(parent)


@dataclass(frozen=True)
class Scope:
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    network: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    def __post_init__(self):
        for values in (self.reads, self.writes, self.network, self.capabilities):
            strings(values)


@dataclass(frozen=True)
class Command:
    executable: str
    argv: tuple[str, ...]
    cwd: str
    target_source: str

    def __post_init__(self):
        strings((self.executable,))
        strings((self.cwd,))
        identifier(self.target_source)
        # Repeated/empty arguments are meaningful; do not normalize shell syntax.
        if type(self.argv) is not tuple or any(not isinstance(a, str) or "\0" in a for a in self.argv):
            raise ValueError("invalid argv")


@dataclass(frozen=True)
class Action:
    action_id: str
    task_id: str
    operation: Operation
    scope: Scope
    delegation_ref: str
    sources: tuple[Source, ...] = ()
    command: Command | None = None
    locator: str = ""
    text: str = ""
    inputs: tuple[str, ...] = ()  # output names; final artifact IDs/paths come only from Host
    outputs: tuple[str, ...] = ()  # unique names within this plan/Host gateway
    depends_on: tuple[str, ...] = ()

    def __post_init__(self):
        for item in (self.action_id, self.task_id, self.delegation_ref):
            identifier(item)
        if not isinstance(self.operation, Operation) or not isinstance(self.scope, Scope):
            raise ValueError("typed operation and scope required")
        if type(self.sources) is not tuple or any(not isinstance(s, Source) for s in self.sources):
            raise ValueError("immutable sources required")
        if len({s.source_id for s in self.sources}) != len(self.sources):
            raise ValueError("duplicate source")
        for values in (self.inputs, self.outputs, self.depends_on):
            strings(values)
            for item in values:
                identifier(item)
        if not isinstance(self.text, str) or not isinstance(self.locator, str):
            raise ValueError("text and locator must be strings")
        if self.operation in EXECUTION:
            if not isinstance(self.command, Command) or self.locator or self.text:
                raise ValueError("execution requires exact command, not free-form tool text")
            if self.command.target_source not in {s.source_id for s in self.sources}:
                raise ValueError("execution source missing")
            if "process.execute" not in self.scope.capabilities:
                raise ValueError("execution capability missing")
        elif self.command is not None or "process.execute" in self.scope.capabilities:
            raise ValueError("non-execution tools cannot carry commands")
        if self.operation in {Operation.READ_TEXT, Operation.WRITE_TEXT, Operation.SEARCH, Operation.BROWSE}:
            if not self.locator and not (self.operation == Operation.READ_TEXT and len(self.inputs) == 1):
                raise ValueError("locator required")
        if self.operation != Operation.WRITE_TEXT and self.text:
            raise ValueError("unexpected text")

    @property
    def location(self) -> Location:
        # Structured operation, never keywords, filename suffixes or Agent trust labels.
        return Location.SANDBOX if self.operation in EXECUTION else Location.LOCAL

    @property
    def access(self) -> str:
        return "X" if self.operation in EXECUTION else "W" if self.operation == Operation.WRITE_TEXT else "R"

    @property
    def fingerprint(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class Task:
    task_id: str
    location: Location
    depends_on: tuple[str, ...] = ()

    def __post_init__(self):
        identifier(self.task_id)
        if not isinstance(self.location, Location):
            raise ValueError("typed location required")
        strings(self.depends_on)
        for item in self.depends_on:
            identifier(item)


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    status: str
    final_ref: str
    sha256: str
    source_ids: tuple[str, ...] = ()
    output_name: str = ""  # plan slot; artifact_id remains the Host's actual ID

    def __post_init__(self):
        identifier(self.artifact_id)
        if self.output_name:
            identifier(self.output_name)
        strings(self.source_ids)
        if self.status != "EXPORTED" or not self.final_ref or not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("only EXPORTED artifacts with final references are consumable")
