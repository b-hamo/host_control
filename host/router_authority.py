"""Host-owned provenance and delegation records, separate from Agent claims.

Populate these records through a trusted application setup path, never from an
Agent tool's request. Verification callbacks must check current bytes/resources.
This API does not install an OS policy or intercept unrelated Agent tools.
"""

from dataclasses import dataclass
import time
from typing import Callable

from router.models import Action, Location, Operation, Scope, Source, EXECUTION


@dataclass(frozen=True)
class Delegation:
    reference: str
    operations: frozenset[Operation]
    locations: frozenset[Location]
    scope: Scope
    expires_at: float
    execution_fingerprints: frozenset[str] = frozenset()
    approval_required: bool = False


class Authority:
    def __init__(self, *, sources: tuple[Source, ...] = (), delegations: tuple[Delegation, ...] = (),
                 verify_source: Callable[[Source], bool] | None = None, clock=time.time):
        self.sources = {s.source_id: s for s in sources}
        self.delegations = {d.reference: d for d in delegations}
        self.verify_source = verify_source
        self.clock = clock

    def check(self, action: Action) -> str:
        grant = self.delegations.get(action.delegation_ref)
        if grant is None or grant.expires_at <= self.clock():
            return "DELEGATION_MISSING_OR_EXPIRED"
        if action.operation not in grant.operations or action.location not in grant.locations:
            return "DELEGATION_OPERATION"
        for name in ("reads", "writes", "network", "capabilities"):
            if not set(getattr(action.scope, name)) <= set(getattr(grant.scope, name)):
                return "DELEGATION_SCOPE"
        if action.operation in EXECUTION and action.fingerprint not in grant.execution_fingerprints:
            return "EXECUTION_NOT_DELEGATED"
        supplied = {s.source_id: s for s in action.sources}
        visited, active = set(), set()

        def check_source(source_id):
            if source_id in active:
                return False
            if source_id in visited:
                return True
            source = supplied.get(source_id)
            if source is None or self.sources.get(source_id) != source or self.verify_source is None:
                return False
            active.add(source_id)
            if not self.verify_source(source) or not all(check_source(p) for p in source.parents):
                return False
            active.remove(source_id)
            visited.add(source_id)
            return True

        if any(not check_source(s) for s in supplied):
            return "PROVENANCE_UNVERIFIED"
        if action.operation in EXECUTION and not supplied:
            return "PROVENANCE_MISSING"
        return "ALLOW"
