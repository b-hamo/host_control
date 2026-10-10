"""Host final decision and execution boundary for Router-managed requests only."""

import asyncio
from dataclasses import replace
import hashlib
from pathlib import Path
from uuid import uuid4

from host.router_authority import Authority
from host.router_ledger import Ledger
from host.router_local import LocalTools
from router.models import Artifact, Location, identifier
from router.ports import Receipt, Request, State


class HostGateway:
    def __init__(self, authority: Authority, ledger: Ledger, local: LocalTools, *, sandbox=None, approver=None):
        self.authority, self.ledger, self.local = authority, ledger, local
        self.sandbox, self.approver = sandbox, approver
        self._lock = asyncio.Lock()
        self._requests: dict[str, Request] = {}
        self._artifacts: dict[str, Artifact] = {}
        self._verified: dict[str, Receipt] = {}

    async def submit(self, request: Request) -> Receipt:
        identifier(request.request_id)
        async with self._lock:
            if not self.ledger.reserve(request):
                previous = self.ledger.get(request.request_id)
                if previous.fingerprint != request.action.fingerprint:
                    return self._receipt(request, State.DENIED, "IDEMPOTENCY_CONFLICT")
                return await self.status(request.request_id)
            self._requests[request.request_id] = request
            try:
                receipt = await self._execute(request)
            except asyncio.CancelledError:
                self.ledger.put(self._receipt(request, State.UNKNOWN, "EXECUTION_UNCONFIRMED"))
                raise
            except Exception:
                # May have crossed execution boundary. No fallback and no replay.
                receipt = self._receipt(request, State.UNKNOWN, "EXECUTION_UNCONFIRMED")
            self.ledger.put(receipt)
            return receipt

    @staticmethod
    def _receipt(request, state, reason, **kwargs):
        return Receipt(request.request_id, request.action.fingerprint, state, reason, **kwargs)

    async def _execute(self, request):
        action = request.action
        try:
            reason = self.authority.check(action)
        except Exception:
            return self._receipt(request, State.HELD, "POLICY_UNAVAILABLE")
        if reason != "ALLOW":
            return self._receipt(request, State.DENIED, reason)
        grant = self.authority.delegations[action.delegation_ref]
        if grant.approval_required:
            if self.approver is None or not await self.approver(request):
                return self._receipt(request, State.DENIED, "APPROVAL_REQUIRED")
            # Files, policy and scope may have changed while the user was approving.
            try:
                if self.authority.check(action) != "ALLOW":
                    return self._receipt(request, State.DENIED, "REASSESSMENT_REQUIRED")
            except Exception:
                return self._receipt(request, State.HELD, "POLICY_UNAVAILABLE")
        if action.location == Location.LOCAL:
            try:
                final_ref = ""
                if action.inputs:
                    if len(action.inputs) != 1 or action.locator:
                        raise ValueError("use exactly one final artifact reference")
                    final_ref = (await self.artifact(action.inputs[0])).final_ref
                self.local.validate(action, final_ref)
            except Exception:
                return self._receipt(request, State.DENIED, "LOCAL_SCOPE_INVALID")
            result_id, _ = await self.local.run(action, final_ref)
            receipt = self._receipt(request, State.SUCCEEDED, "LOCAL_DATA_VERIFIED",
                                    execution_id="LOCAL-" + uuid4().hex, evidence_ref=result_id)
            self._verified[request.request_id] = receipt
            return receipt
        if self.sandbox is None or not self.sandbox.supports(request):
            return self._receipt(request, State.HELD, "SANDBOX_COMMAND_CONTRACT_UNAVAILABLE")
        self.ledger.put(self._receipt(request, State.ACCEPTED, "HOST_VALIDATED"))
        return await self._validate_receipt(request, await self.sandbox.submit(request))

    async def _validate_receipt(self, request, receipt):
        if receipt.request_id != request.request_id or receipt.fingerprint != request.action.fingerprint:
            return self._receipt(request, State.UNKNOWN, "RECEIPT_MISMATCH")
        if receipt.state == State.SUCCEEDED:
            try:
                # Opaque references only: credentials/URLs/command text are not journal fields.
                for ref in (receipt.execution_id, receipt.evidence_ref, receipt.runtime_id):
                    identifier(ref)
                valid_identity = type(receipt.generation) is int and receipt.generation > 0
            except ValueError:
                valid_identity = False
            if not valid_identity or not await self.sandbox.verify(receipt):
                return self._receipt(request, State.UNKNOWN, "EXECUTION_EVIDENCE_MISSING")
            if {a.artifact_id for a in receipt.artifacts} != set(request.action.outputs):
                return self._receipt(request, State.UNKNOWN, "OUTPUTS_UNCONFIRMED")
            checked_artifacts = []
            for artifact in receipt.artifacts:
                checked = self.sandbox.artifact(artifact.artifact_id)
                if (checked.final_ref, checked.sha256) != (artifact.final_ref, artifact.sha256):
                    return self._receipt(request, State.UNKNOWN, "EXPORT_UNCONFIRMED")
                checked_artifacts.append(replace(checked,
                    source_ids=tuple(s.source_id for s in request.action.sources)))
            receipt = replace(receipt, artifacts=tuple(checked_artifacts))
            for artifact in checked_artifacts:
                self._artifacts[artifact.artifact_id] = artifact
            self._verified[request.request_id] = receipt
        if receipt.state != State.SUCCEEDED:
            return self._receipt(request, receipt.state, "SANDBOX_" + receipt.state.value)
        return replace(receipt, reason="SANDBOX_" + receipt.state.value)

    async def status(self, request_id: str) -> Receipt:
        receipt = self.ledger.get(request_id)
        if receipt.state in {State.ACCEPTED, State.RUNNING, State.UNKNOWN} and self.sandbox is not None:
            try:
                candidate = await self.sandbox.status(request_id)
                if candidate.request_id == request_id and candidate.fingerprint == receipt.fingerprint:
                    if request_id in self._requests:
                        receipt = await self._validate_receipt(self._requests[request_id], candidate)
                        self.ledger.put(receipt)
                    elif candidate.state != State.SUCCEEDED:
                        # After restart the original output contract needs reconciliation.
                        receipt = Receipt(request_id, receipt.fingerprint, candidate.state,
                                          "SANDBOX_" + candidate.state.value)
                        self.ledger.put(receipt)
            except Exception:
                pass
        return receipt

    async def verify(self, receipt: Receipt) -> bool:
        trusted = self._verified.get(receipt.request_id)
        return trusted is not None and replace(trusted, reason=receipt.reason) == receipt

    async def read_result(self, receipt: Receipt) -> bytes:
        """Return a verified Local data result; never evaluate returned code/page text."""
        if not await self.verify(receipt) or not receipt.execution_id.startswith("LOCAL-"):
            raise ValueError("not a verified Local result")
        return self.local.results[receipt.evidence_ref]

    async def artifact(self, artifact_id: str) -> Artifact:
        artifact = self._artifacts[artifact_id]
        current = self.sandbox.artifact(artifact_id)
        if (artifact.final_ref, artifact.sha256) != (current.final_ref, current.sha256):
            raise ValueError("artifact changed")
        if hashlib.sha256(Path(current.final_ref).read_bytes()).hexdigest() != artifact.sha256:
            raise ValueError("exported bytes changed")
        return artifact
