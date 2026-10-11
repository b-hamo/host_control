"""Reuse Broker lifecycle/artifacts; never mistake keyboard ACK for command exit.

A Host-configured driver must bind exact commands, resources and evidence to
requests. GuiCommandDriver supplies that binding over existing SCRP GUI tools
and inspected artifacts. No driver means HELD before Sandbox startup.
"""

from typing import Protocol

from router.ports import Receipt, Request


class CommandDriver(Protocol):
    def supports(self, request: Request) -> bool: ...
    async def submit(self, broker, request: Request) -> Receipt: ...
    async def status(self, broker, request_id: str) -> Receipt: ...
    async def verify(self, broker, receipt: Receipt) -> bool: ...


class BrokerSandbox:
    def __init__(self, broker, driver: CommandDriver | None = None):
        self.broker, self.driver = broker, driver
        self._started = False
        self._scope = None

    def supports(self, request: Request) -> bool:
        return self.driver is not None and self.driver.supports(request)

    async def submit(self, request: Request) -> Receipt:
        if not self.supports(request):
            raise ValueError("command driver unavailable")
        # Unrelated code or resource scopes need a separately provisioned session.
        scope = (request.action.scope, request.action.sources)
        if self._started and scope != self._scope:
            raise ValueError("separate Sandbox session required")
        if not self._started:
            prepare = getattr(self.driver, "prepare", None)
            if prepare is not None:
                await prepare(self.broker, request)
            result = await self.broker.call("task_submit", {
                "goal": "Run the Host-validated Router request in Windows Sandbox",
                "required_capabilities": ["gui.observe", "gui.input", "process.execute"],
                "network_required": bool(request.action.scope.network),
                "artifact_expected": bool(request.action.outputs),
                "constraints": "Only the separately validated exact command and access scope",
            })
            if not result.ok:
                raise RuntimeError("sandbox task refused")
            self._started, self._scope = True, scope
        return await self.driver.submit(self.broker, request)

    async def status(self, request_id: str) -> Receipt:
        if self.driver is None:
            raise ValueError("command driver unavailable")
        return await self.driver.status(self.broker, request_id)

    async def verify(self, receipt: Receipt) -> bool:
        identity = self.broker.session.identity
        return self.driver is not None and (receipt.runtime_id, receipt.generation) == identity[1:] \
            and await self.driver.verify(self.broker, receipt)

    def artifact(self, artifact_id: str):
        from router.models import Artifact
        artifacts = self.broker.artifacts
        if artifacts is None:
            raise ValueError("artifact broker unavailable")
        art = artifacts.precheck(self.broker.session, artifact_id)
        view = artifacts.view(art)
        if view["status"] != "EXPORTED":
            raise ValueError("artifact not exported")
        return Artifact(artifact_id, "EXPORTED", view["export_path"], view["sha256"])
