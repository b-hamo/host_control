"""Agent/Host composition for a Router plan with one isolated execution scope.

The caller supplies Host-owned Authority records and file bindings, not Agent
claims. The Agent receives this HostPort; it cannot replace the policy, approve
exports or send raw GUI inputs through this interface. Existing MCP/global shell
tools are outside this boundary. Each different execution scope needs a separate
instance after the preceding instance has closed its Sandbox.
"""

import asyncio
from pathlib import Path

from host.mcp_server import HostBackend
from host.router_gateway import HostGateway
from host.router_gui_driver import GuiCommandDriver
from host.router_gui_policy import RouterGuiPolicy
from host.router_inputs import InputBoundManager
from host.router_ledger import Ledger
from host.router_local import LocalTools
from host.router_sandbox import BrokerSandbox


class RouterRuntime:
    def __init__(self, backend):
        self.backend = backend
        self.gateway = self.driver = self.ledger = None
        self._closed = False

    @classmethod
    async def open(cls, args, manager, authority, execution_action, bindings,
                   data_directory: Path, private_directory: Path, *, command_launch_enabled=False,
                   execution_approver=None):
        inputs = InputBoundManager(manager, authority, execution_action, bindings)
        backend = HostBackend(args, sandbox_manager=inputs)
        runtime = cls(backend)
        backend.start()
        try:
            if not await asyncio.to_thread(backend.ready.wait, 20) or backend.error:
                raise RuntimeError("Router Host could not start")

            async def configure():
                private_directory.mkdir(parents=True, exist_ok=True)
                policy = RouterGuiPolicy(authority, command_launch_enabled=command_launch_enabled)
                runtime.driver = GuiCommandDriver(inputs, policy, private_directory / "commands",
                                                   startup_timeout=args.startup_timeout)
                # Trusted composition, before this HostPort is returned to any Agent.
                backend.broker.policy = policy
                backend.broker.approver = runtime.driver.approve_export
                runtime.ledger = Ledger(private_directory / "requests.sqlite")
                runtime.gateway = HostGateway(authority, runtime.ledger, LocalTools(data_directory),
                                               sandbox=BrokerSandbox(backend.broker, runtime.driver),
                                               approver=execution_approver)
            await runtime._on_host(configure())
            return runtime
        except BaseException:
            await runtime.close()
            raise

    async def _on_host(self, coroutine):
        if self.backend.loop is None or not self.backend.loop.is_running():
            coroutine.close()
            raise RuntimeError("Router Host is closed")
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, self.backend.loop)
        except RuntimeError:
            coroutine.close()
            raise
        return await asyncio.wrap_future(future)

    async def submit(self, request):
        return await self._on_host(self.gateway.submit(request))

    async def status(self, request_id):
        return await self._on_host(self.gateway.status(request_id))

    async def verify(self, receipt):
        return await self._on_host(self.gateway.verify(receipt))

    async def artifact(self, output_ref):
        return await self._on_host(self.gateway.artifact(output_ref))

    async def read_result(self, receipt):
        return await self._on_host(self.gateway.read_result(receipt))

    async def stop_sandbox(self):
        """Retire Guest AND execution Host; the service has already saved its results."""
        # HostBackend owns the one shutdown deadline and closes both listeners
        # even when Guest cleanup raises. Do not spend that deadline twice.
        await self.close()
        launcher = self.backend.launcher
        if self.backend.error:
            raise RuntimeError("Host cleanup unconfirmed")
        if launcher is not None and launcher.sandbox is not None:
            if launcher.cleanup_result is None or launcher.cleanup_result.get("failed"):
                raise RuntimeError("Sandbox cleanup unconfirmed")
            async with asyncio.timeout(5):
                running = await asyncio.to_thread(launcher.manager.is_running, launcher.sandbox)
            if running:
                raise RuntimeError("Sandbox cleanup unconfirmed")

    async def wait_unavailable(self):
        """Only observe this runtime's Guest. Never restart it or kill a port owner."""
        while not self._closed:
            if not self.backend.is_alive():
                return

            async def probe():
                launcher = self.backend.launcher
                if self.backend.session.terminated:
                    return True
                if (launcher.sandbox is not None and launcher.state in {"READY", "PUBLISHED"}
                        and launcher._launch is not None and launcher._launch.done()
                        and launcher._finish is None):
                    if not await asyncio.to_thread(launcher.manager.is_running, launcher.sandbox):
                        await self.backend.session._end("RUNTIME_GONE: owned Sandbox closed")
                        return True
                return False
            try:
                if await self._on_host(probe()):
                    return
            except Exception:
                # Observation failure is not permission to restart or replay.
                if not self.backend.is_alive():
                    return
            await asyncio.sleep(2)

    async def close(self):
        if self._closed:
            return
        try:
            if self.backend.loop is not None and self.backend.loop.is_running():
                async def finish():
                    try:
                        if self.driver is not None:
                            await self.driver.close()
                    finally:
                        if self.ledger is not None:
                            self.ledger.close()
                            self.ledger = None
                await self._on_host(finish())
        finally:
            await asyncio.to_thread(self.backend.shutdown)
            self._closed = True
