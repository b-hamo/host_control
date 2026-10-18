"""Opt-in, serialized Router GUI and command session. No public raw Broker handle."""
import asyncio
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path

from host.mcp_server import HostBackend
from host.policy import Decision
from host.router_gateway import HostGateway
from host.router_gui_driver import GuiCommandDriver
from host.router_gui_policy import RouterGuiPolicy
from host.router_inputs import InputBoundManager
from host.router_ledger import Ledger
from host.router_local import LocalTools
from host.router_runtime import RouterRuntime
from host.router_sandbox import BrokerSandbox
from router.models import Operation, EXECUTION
from router.ports import Receipt, State


class SessionInputs:
    def __init__(self, manager, seed):
        self.manager, self.seed, self.session = manager, seed, None
        self.children = []

    def __getattr__(self, name):
        return getattr(self.manager, name)

    def owns(self, manager):
        return any(child is manager for child in self.children)

    def prepare(self, *args):
        from sandbox_manager.inputs import register_input
        if self.session is not None:
            raise ValueError('interactive session cannot restart')
        self.session = self.manager.prepare(*args, input_files=[register_input(self.seed, source='router-session-seed')])
        return self.session


class LiveInputs(InputBoundManager):
    def configure_transport(self, inputs):
        super().configure_transport(inputs)
        from sandbox_manager.inputs import register_input
        self._authorize()
        entries = []
        sources = {s.source_id: s for s in self.action.sources}
        files = [(b.host_path, sources[b.source_id].sha256) for b in self.bindings]
        files += [(i.path, i.sha256) for i in inputs]
        for path, sha in files:
            self._plain_file(path)
            entry = register_input(path, source='router-bound:' + sha)
            if entry.sha256 != sha:
                raise ValueError('input changed')
            entries.append(entry)
        self.manager.add_inputs(self.manager.session, entries)
        self._prepared = self.manager.session
        self.validate_prepared(self._prepared)


class InteractionPolicy(RouterGuiPolicy):
    """GUI input requires an exact Router lease, including ordinary clicks."""
    @contextmanager
    def interaction(self, action, steps):
        if self._owner is not None or self.authority.check(action) != 'ALLOW':
            raise ValueError('GUI authorization unavailable')
        self._owner, self._action = asyncio.current_task(), action
        self._steps, self._next = tuple(steps), 0
        try:
            yield
        finally:
            self._owner = self._action = None
            self._steps, self._next = (), 0

    def decide(self, tool, args):
        if tool.startswith('computer_') and tool != 'computer_observe':
            if self._owner is None or self.authority.check(self._action) != 'ALLOW':
                return Decision('DENY', 'P-ROUTER-GUI-BOUNDARY', 'Router input lease required')
        return super().decide(tool, args)


class InteractiveSandbox(BrokerSandbox):
    def __init__(self, broker, manager, authority, policy, directory, bindings):
        super().__init__(broker)
        self.manager, self.authority, self.policy = manager, authority, policy
        self.directory, self.bindings = directory, bindings
        self.drivers, self.receipts, self.results, self.jobs = {}, {}, {}, {}
        self.lock = asyncio.Lock()
        self.last_observation = None

    def supports(self, request):
        return request.action.operation == Operation.GUI or request.action.action_id in self.bindings

    def receipt(self, request, state, reason, data=None):
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True).encode() if data is not None else b''
        ref = 'DATA-' + hashlib.sha256(raw).hexdigest() if raw else ''
        r = Receipt(request.request_id, request.action.fingerprint, state, reason,
                    'GUI-' + request.action.action_id, ref, (), *self.broker.session.identity[1:])
        self.receipts[request.request_id] = r
        if raw:
            self.results[ref] = raw
        return r

    async def submit(self, request):
        self.receipt(request, State.ACCEPTED, 'GUI_QUEUED')
        self.jobs[request.request_id] = asyncio.create_task(self.run(request))
        return self.receipts[request.request_id]

    async def ready(self):
        if self.broker.session.terminated:
            raise ValueError('Sandbox stopped')
        if not self._started:
            result = await self.broker.call('task_submit', {
                'goal': 'Router-scoped browser and clipboard analysis in one Sandbox',
                'required_capabilities': ['gui.observe', 'gui.input', 'process.execute'],
                'network_required': True, 'artifact_expected': True,
                'constraints': 'Only exact Host-authorized Router actions; no Host execution'})
            if not result.ok:
                raise ValueError('Sandbox start refused')
            self._started = True
        await asyncio.wait_for(self.broker.session.ready.wait(), 180)
        if self.broker.session.terminated:
            raise ValueError('Sandbox stopped')

    async def observed(self, wait=500):
        r = await self.broker.call('computer_observe', {'wait_ms': wait})
        if not r.ok or not r.image:
            raise ValueError('validated screenshot unavailable')
        self.last_observation = r.data['observation_id']
        path = self.directory / (self.last_observation + '.png')
        path.write_bytes(r.image)
        return {**r.data, 'screenshot_path': str(path), 'screenshot_sha256': hashlib.sha256(r.image).hexdigest()}

    async def run(self, request):
        async with self.lock:
            try:
                if self.authority.check(request.action) != 'ALLOW':
                    raise ValueError('authority changed')
                await self.ready()
                action = request.action
                if action.operation in EXECUTION:
                    inputs = LiveInputs(self.manager, self.authority, action, self.bindings[action.action_id])
                    self.manager.children.append(inputs)
                    driver = GuiCommandDriver(inputs, self.policy, self.directory / 'commands')
                    self.drivers[request.request_id] = driver
                    await driver.prepare(self.broker, request)
                    await driver.submit(self.broker, request)
                    # Hold the session lease through completion, never overlap a payload with GUI input.
                    deadline = asyncio.get_running_loop().time() + 240
                    while asyncio.get_running_loop().time() < deadline:
                        receipt = await driver.status(self.broker, request.request_id)
                        self.receipts[request.request_id] = receipt
                        if receipt.state in {State.SUCCEEDED, State.FAILED, State.DENIED, State.HELD}:
                            return
                        await asyncio.sleep(1)
                    # Unknown process state poisons the session; no follow-up input or replay.
                    await self.broker.session._end('ROUTER_EXECUTION_TIMEOUT')
                    return
                spec = json.loads(action.locator)
                op = spec['operation']
                if op == 'observe':
                    data = await self.observed()
                else:
                    if op == 'navigate':
                        steps = [('computer_hotkey', {'keys': ['win', 'r']}),
                                 ('computer_type', {'text': spec['url']}),
                                 ('computer_keypress', {'key': 'enter'})]
                        await self.observed()
                    elif op == 'click':
                        if spec['observation_id'] != self.last_observation:
                            raise ValueError('observation changed')
                        steps = [('computer_click', {'x': spec['x'], 'y': spec['y'], 'button': 'left', 'click_count': 1})]
                    else:
                        raise ValueError('unsupported GUI operation')
                    with self.policy.interaction(action, steps):
                        for index, (tool, args) in enumerate(steps):
                            r = await self.broker.call(tool, args)
                            if not r.ok or r.data.get('status') != 'SUCCESS' or r.data.get('result', {}).get('input_delivered') is not True:
                                raise ValueError('GUI input unconfirmed: ' + str(r.error or r.data))
                            if tool == 'computer_hotkey':
                                await self.observed()
                    data = await self.observed(1000)
                self.receipt(request, State.SUCCEEDED, 'GUI_VERIFIED', data)
            except asyncio.CancelledError:
                self.receipt(request, State.UNKNOWN, 'INTERRUPTED')
                raise
            except Exception as exc:
                self.receipt(request, State.UNKNOWN, 'GUI_UNCONFIRMED')
                (self.directory / (request.request_id + '-error.txt')).write_text(repr(exc), encoding='utf-8')

    async def status(self, request_id):
        return self.receipts.get(request_id, Receipt(request_id, '', State.UNKNOWN, 'REQUEST_NOT_FOUND'))

    async def verify(self, receipt):
        stored = self.receipts.get(receipt.request_id)
        if (stored != receipt or receipt.state != State.SUCCEEDED
                or (receipt.runtime_id, receipt.generation) != self.broker.session.identity[1:]):
            return False
        if receipt.request_id in self.drivers:
            return await self.drivers[receipt.request_id].verify(self.broker, receipt)
        raw = self.results.get(receipt.evidence_ref, b'')
        if 'DATA-' + hashlib.sha256(raw).hexdigest() != receipt.evidence_ref:
            return False
        doc = json.loads(raw)
        return hashlib.sha256(Path(doc['screenshot_path']).read_bytes()).hexdigest() == doc['screenshot_sha256']

    async def read_result(self, receipt):
        original = self.receipts[receipt.request_id]
        if not await self.verify(original) or replace(original, reason=receipt.reason) != receipt:
            raise ValueError('GUI evidence changed')
        return self.results[receipt.evidence_ref]

    async def approve_export(self, summary):
        for driver in self.drivers.values():
            if await driver.approve_export(summary):
                return True
        return False

    async def close(self):
        for job in self.jobs.values():
            if not job.done():
                job.cancel()
        await asyncio.gather(*self.jobs.values(), return_exceptions=True)
        for driver in self.drivers.values():
            await driver.close()


class InteractiveRuntime(RouterRuntime):
    @classmethod
    async def open(cls, *, args, manager, authority, data_directory, private_directory, bindings, **unused):
        private_directory.mkdir(parents=True, exist_ok=True)
        seed = private_directory / 'router-session.txt'
        seed.write_text('Router interactive input mapping', encoding='utf-8')
        inputs = SessionInputs(manager, seed)
        backend = HostBackend(args, sandbox_manager=inputs)
        runtime = cls(backend)
        backend.start()
        try:
            if not await asyncio.to_thread(backend.ready.wait, 20) or backend.error:
                raise RuntimeError('Interactive Host startup failed')
            async def configure():
                policy = InteractionPolicy(authority, command_launch_enabled=True)
                runtime.driver = InteractiveSandbox(backend.broker, inputs, authority, policy, private_directory, bindings)
                backend.broker.policy = policy
                backend.broker.approver = runtime.driver.approve_export
                runtime.ledger = Ledger(private_directory / 'requests.sqlite')
                runtime.gateway = HostGateway(authority, runtime.ledger, LocalTools(data_directory), sandbox=runtime.driver)
            await runtime._on_host(configure())
            return runtime
        except BaseException:
            await runtime.close()
            raise
