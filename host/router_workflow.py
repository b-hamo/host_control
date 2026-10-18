"""Router-only external-content workflow. Operator config owns scope.

Every read, GUI interaction and execution is submitted through RouterService -> Router -> HostGateway.
The GUI Broker exists only inside RouterRuntime. No raw shell or Broker tool is exposed.
This is a tool boundary, not an OS restriction on unrelated clients/processes.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from email import policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import time
from urllib.request import build_opener, HTTPRedirectHandler
from uuid import uuid4

from host.router_authority import Authority, Delegation
from host.router_command_bundle import output_directory
from host.router_gateway import HostGateway
from host.router_inputs import InputBinding
from host.router_ledger import Ledger
from host.router_local import LocalTools
from host.router_mcp_service import RouterService
from host.router_interactive import InteractiveRuntime
from router.models import Action, Command, Location, Operation, Scope, Source, Task, identifier
from host.router_web_policy import WebPolicy

LIMIT = 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def __init__(self, policy=None):
        self.policy = policy

    def redirect_request(self, *args, **kwargs):
        if self.policy is None:
            raise ValueError('Redirect outside operator scope')
        self.policy.require(args[5], 'redirect')
        return super().redirect_request(*args, **kwargs)


def script_from_source(text, form, start=None, end=None):
    """Decode data only. Never evaluate fetched code on Host.

    command-literal is a deliberately narrow adapter for a single-quoted JS
    string containing PowerShell -Command. Unsupported syntax fails closed.
    The interactive NoExit switch is explicitly omitted in the returned batch
    analysis contract; the script body itself is unchanged.
    """
    if form == 'powershell-script':
        if start is not None or end is not None:
            raise ValueError('Script source must be used in full')
        return text, {'transform': 'identity'}
    if form != 'powershell-command-literal' or type(start) is not int or type(end) is not int:
        raise ValueError('Unsupported source form')
    if not 0 <= start < end <= len(text):
        raise ValueError('Invalid literal range')
    literal = text[start:end]
    if not re.fullmatch(r"'(?:[^'\\\r\n]|\\['\\])*'", literal):
        raise ValueError('Only a static single-quoted literal is supported')
    command = re.sub(r"\\(['\\])", r'\1', literal[1:-1])
    match = re.fullmatch(r'powershell(?:\.exe)? -NoProfile(?: -NoExit)? -Command "([^\r\n]+)"', command, re.I)
    if not match:
        raise ValueError('Unsupported PowerShell command form')
    return match[1], {'transform': 'powershell-command-to-batch-script-v1',
                      'original_command': command, 'interactive_noexit_removed': ' -noexit ' in command.lower()}


class WorkflowPort:
    """HostPort used by the existing Router, with lazy isolated execution."""
    def __init__(self, workflow):
        self.workflow = workflow

    async def submit(self, request):
        w = self.workflow
        if request.action.location == Location.LOCAL:
            receipt = await w.local.submit(request)
            w.queue_click_analysis(request.action, receipt)
            return receipt
        async with w.runtime_lock:
            if w.execution is None:
                await w.open_execution(request.action)
        return await w.execution.submit(request)

    async def status(self, request_id):
        w = self.workflow
        local = await w.local.status(request_id)
        if local.reason != 'REQUEST_NOT_FOUND' or w.execution is None:
            return local
        return await w.execution.status(request_id)

    async def verify(self, receipt):
        return await (self.workflow.local if receipt.execution_id.startswith('LOCAL-')
                      else self.workflow.execution).verify(receipt)

    async def read_result(self, receipt):
        port = self.workflow.local if receipt.execution_id.startswith('LOCAL-') else self.workflow.execution
        return await port.read_result(receipt)

    async def artifact(self, ref):
        return await self.workflow.execution.artifact(ref)

    async def stop_sandbox(self):
        if self.workflow.execution is not None:
            await self.workflow.execution.stop_sandbox()
        if self.workflow.browser is not None:
            await self.workflow.browser.close()

    async def close(self):
        if self.workflow.execution is not None:
            await self.workflow.execution.close()

    async def wait_unavailable(self):
        await self.workflow.runtime_ready.wait()
        await self.workflow.execution.wait_unavailable()


class RouterWorkflow:
    def __init__(self, *, directory, mailbox=None, origins, runner_exe, sandbox_root,
                 allow_execution=False, allow_gui=False, auto_analyze_clipboard=False,
                 runtime_factory=None, browser_factory=None, browsing_policy='scoped', task_checks=True):
        if type(task_checks) is not bool:
            raise ValueError('task_checks must be boolean')
        self.web_policy = WebPolicy(origins if task_checks else [], browsing_policy if task_checks else 'web')
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.data = self.directory / 'data'
        self.private = self.directory / 'private'
        self.data.mkdir(); self.private.mkdir()
        self.mailbox = Path(mailbox).resolve(strict=True) if mailbox is not None else None
        self.origins = frozenset(origins)
        self.runner_exe, self.sandbox_root = Path(runner_exe), Path(sandbox_root)
        self.allow_execution = allow_execution
        self.allow_gui = allow_gui
        self.auto_analyze_clipboard = auto_analyze_clipboard
        self.clipboard_analyses = {}
        self.click_analyses, self.followups = {}, set()
        self.live_bindings, self.clipboard_actions, self.clipboard_sources = {}, set(), set()
        self.runtime_factory = runtime_factory or InteractiveRuntime.open
        self.paths, self.reads, self.requests = {}, {}, {}
        self.execution = self.execution_action = None
        self.execution_identity = None
        self.binding = None
        self.closed = False
        from host.router_local_browser import LocalBrowser
        self.browser = (browser_factory or LocalBrowser)(self.private / 'browser', self.origins) if allow_gui else None
        if self.browser is not None:
            self.browser.policy = self.web_policy
        self.lock = asyncio.Lock()
        self.runtime_lock = asyncio.Lock()
        self.runtime_ready = asyncio.Event()
        self.authority = Authority(verify_source=self.verify_source, task_checks=task_checks)
        self.ledger = Ledger(self.private / 'local.sqlite')
        self.local = HostGateway(self.authority, self.ledger, LocalTools(self.data, browse=self.read, interaction=self.interact))
        self.service = RouterService(WorkflowPort(self), 'WORKFLOW', self.private / 'router.sqlite')

    def verify_source(self, source):
        path = self.paths.get(source.source_id)
        if path is None or path.is_symlink() or path.is_junction():
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == source.sha256

    def source(self, raw, reference, parents=(), suffix='.txt'):
        sid = 'SRC-' + uuid4().hex
        path = self.private / (sid + suffix)
        path.write_bytes(raw)
        record = Source(sid, reference, hashlib.sha256(raw).hexdigest(),
                        'generated' if parents else 'external', parents)
        self.paths[sid] = path
        self.authority.sources[sid] = record
        return record

    def audit(self, event, **fields):
        with (self.private / 'workflow.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'event': event, **fields}, ensure_ascii=False) + '\n')

    def read_sync(self, uri):
        if uri.startswith('mailbox:'):
            if self.mailbox is None:
                raise ValueError('Mailbox adapter not configured')
            name = uri[len('mailbox:'):]
            files = {p.stem: p for p in self.mailbox.glob('*.eml') if not p.is_symlink() and not p.is_junction()}
            if not name:
                return json.dumps([{'id': key, 'uri': 'mailbox:' + key} for key in sorted(files)]).encode()
            if name not in files or files[name].stat().st_size > LIMIT:
                raise ValueError('Mailbox item unavailable')
            message = BytesParser(policy=policy.default).parsebytes(files[name].read_bytes())
            body = message.get_body(preferencelist=('plain', 'html'))
            return json.dumps({'id': name, 'subject': str(message['Subject']), 'from': str(message['From']),
                               'body': body.get_content(), 'trust': 'untrusted'}, ensure_ascii=False).encode()
        self.web_policy.require(uri, 'read')
        with build_opener(NoRedirect(self.web_policy)).open(uri, timeout=20) as response:
            raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError('Response too large')
        raw.decode('utf-8')
        return raw

    async def read(self, action):
        # Called only by LocalTools after HostGateway checks the exact grant.
        raw = await asyncio.to_thread(self.read_sync, action.locator)
        source = self.source(raw, action.locator)
        self.reads[action.action_id] = source
        self.audit('SOURCE_CAPTURED', action_id=action.action_id, source=asdict(source))
        return raw

    async def interact(self, action):
        if self.browser is None:
            raise ValueError('Local browser disabled')
        if action.operation == Operation.LOCAL_BROWSER:
            doc = await self.browser.run(json.loads(action.locator))
            self.audit('LOCAL_BROWSER', action_id=action.action_id, result=doc)
        else:
            doc = self.browser.read_clipboard()
            record = self.source(doc['text'].encode(),
                f'clipboard:local:{doc["sequence"]}:{action.action_id}')
            self.reads[action.action_id] = record
            self.clipboard_sources.add(record.source_id)
            doc.update(contract='router-local-clipboard-v1', source=asdict(record),
                trust='external', execution_location='SANDBOX')
            self.audit('LOCAL_CLIPBOARD_CAPTURED', action_id=action.action_id, source=asdict(record),
                sequence=doc['sequence'], source_url=doc['source_url'])
        return json.dumps(doc, ensure_ascii=False).encode()

    async def auto_analysis(self, result):
        # Runs after a verified capture has completed, so no plan is extended
        # while its capture job is still running. No agent execute call needed.
        record = self.reads.get(result['action_id'])
        if not record or record.source_id not in self.clipboard_sources:
            return
        doc = json.loads(result['text'])
        key = (doc['sequence'], record.sha256)
        if key not in self.clipboard_analyses:
            rid = 'AUTO-' + record.source_id
            args = {'request_id': rid, 'source_id': record.source_id, 'form': 'powershell-command'}
            try:
                await self.execution_available()
                execution = self.prepare_execution(args)
            except ValueError as exc:
                self.clipboard_analyses[key] = {'state':'HELD', 'reason':str(exc), 'location':'SANDBOX'}
            else:
                self.requests[rid] = json.dumps(['router_execute', args], sort_keys=True)
                submitted = await self.register_submit(rid, execution)
                self.clipboard_analyses[key] = {'request_id':rid, 'location':'SANDBOX',
                    'state':'SUBMITTED' if submitted.get('ok') else 'HELD'}
        result['analysis'] = self.clipboard_analyses[key]

    def queue_click_analysis(self, action, receipt):
        """Schedule only after the Router-owned click job has completed.

        The continuation is Host policy, not a model tool choice or result-read
        side effect. It still registers clipboard and execution actions through
        RouterService and never bypasses Authority/HostGateway.
        """
        if (not self.auto_analyze_clipboard or action.operation != Operation.LOCAL_BROWSER
                or json.loads(action.locator).get('operation') != 'click'
                or receipt.state.value != 'SUCCEEDED'):
            return
        doc = json.loads(self.local.local.results[receipt.evidence_ref])
        if not doc.get('clipboard_changed') or action.action_id in self.click_analyses:
            return
        state = {'state':'PENDING', 'location':'SANDBOX'}
        self.click_analyses[action.action_id] = state
        parent = asyncio.current_task()

        async def continue_analysis():
            try:
                await asyncio.shield(parent)
                if self.service.stopped:
                    state.update(state='HELD', reason='PLAN_STOPPED')
                    return
                rid = 'CLIP-' + action.action_id
                state['capture_request_id'] = rid
                submitted = await self.call('router_clipboard_read', {'request_id':rid})
                if not submitted.get('ok'):
                    raise ValueError(submitted.get('error', 'CLIPBOARD_NOT_SUBMITTED'))
                await asyncio.gather(*list(self.service.jobs.values()), return_exceptions=True)
                captured = await self.call('router_result', {'request_id':rid})
                if not captured.get('ok') or not captured.get('analysis'):
                    raise ValueError('CLIPBOARD_NOT_VERIFIED_OR_STOPPED')
                state.update(captured['analysis'])
                self.audit('CLICK_AUTO_ANALYSIS', action_id=action.action_id, analysis=state)
                if 'request_id' not in state:
                    return
                deadline = time.monotonic() + 240
                while not self.service.stopped and time.monotonic() < deadline:
                    result = await self.call('router_result', {'request_id':state['request_id']})
                    terminal = result.get('receipt', {}).get('state')
                    if terminal in {'SUCCEEDED', 'FAILED', 'DENIED', 'HELD', 'UNKNOWN'}:
                        state.update(state=terminal, verified=bool(result.get('ok')))
                        self.audit('CLICK_ANALYSIS_FINISHED', action_id=action.action_id, analysis=state)
                        return
                    await asyncio.sleep(.5)
                state.update(state='UNKNOWN', reason='PLAN_STOPPED_OR_ANALYSIS_TIMEOUT')
            except asyncio.CancelledError:
                state.update(state='HELD', reason='WORKFLOW_CLOSED')
                raise
            except Exception as exc:
                state.update(state='HELD', reason=str(exc))
                self.audit('CLICK_ANALYSIS_HELD', action_id=action.action_id, reason=str(exc))

        task = asyncio.create_task(continue_analysis())
        self.followups.add(task)
        task.add_done_callback(self.followups.discard)

    def grant(self, action):
        self.authority.delegations[action.delegation_ref] = Delegation(
            action.delegation_ref, frozenset({action.operation}), frozenset({action.location}),
            action.scope, time.time() + 1800, frozenset({action.fingerprint}))

    async def register_submit(self, request_id, action):
        self.grant(action)
        definition = json.loads(json.dumps({'plan_id': 'WORKFLOW',
            'tasks': [asdict(Task(action.task_id, action.location))], 'actions': [asdict(action)]}))
        result = await self.service.call('router_plan', definition)
        if not result['ok']:
            raise ValueError('Plan registration refused')
        self.audit('ROUTER_SUBMIT', request_id=request_id, action=asdict(action))
        return await self.service.call('router_submit', {'request_id': request_id, 'action_id': action.action_id})

    async def open_execution(self, action):
        if action.action_id not in self.live_bindings or self.authority.check(action) != 'ALLOW':
            raise ValueError('Execution not authorized')
        # Read-only ownership check before creating a Host or invoking Manager.
        state = await asyncio.to_thread(subprocess.run, ['wsb', 'list', '--raw'], capture_output=True, check=True)
        if json.loads(state.stdout).get('WindowsSandboxEnvironments'):
            raise ValueError('Existing Sandbox must not be replaced')
        for port in (17443, 17444):
            with socket.socket() as sock:
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    raise ValueError('Existing Host must not be replaced')
        from sandbox_manager import SandboxManager
        session, runtime, generation = self.execution_identity
        args = argparse.Namespace(host='0.0.0.0', port=17443, upload_port=17444,
            session=session, runtime=runtime, generation=generation, startup_timeout=180,
            advertise_address=None, bootstrap_out=None, runner_exe=self.runner_exe,
            sandbox_root=self.sandbox_root, cert_dir=self.private/'certs', audit_dir=self.private/'audit',
            no_auto_restart=True, artifact_export=True, approval='deny', artifact_scanner='amsi',
            artifact_max_bytes=LIMIT, artifact_dir=self.private/'quarantine', export_dir=self.data/'exports')
        factory = self.runtime_factory
        self.execution = await factory(args=args, manager=SandboxManager(self.sandbox_root),
            authority=self.authority, execution_action=action, bindings=self.live_bindings,
            data_directory=self.data, private_directory=self.private/'execution', command_launch_enabled=True)
        self.audit('GUI_BACKEND_CREATED_BY_ROUTER', session=session, runtime=runtime, generation=generation)
        self.runtime_ready.set()

    async def execution_available(self):
        # New commands never overlap an unfinished or uncertain execution.
        for rid, signature in self.requests.items():
            if json.loads(signature)[0] != 'router_execute':
                continue
            result = await self.service.call('router_status', {'request_id': rid})
            if result.get('receipt', {}).get('state') not in {'SUCCEEDED', 'FAILED', 'DENIED', 'HELD'}:
                raise ValueError('Execution busy or unconfirmed; query status or stop the session')

    def prepare_execution(self, args):
        if not self.allow_execution:
            raise ValueError('Execution disabled')
        record = self.authority.sources[args['source_id']]
        if record.parents or not self.verify_source(record):
            raise ValueError('Source changed or unsupported source ancestry')
        text = self.paths[record.source_id].read_text(encoding='utf-8')
        if args['form'] == 'powershell-command':
            if record.source_id not in self.clipboard_sources or args.get('start') is not None or args.get('end') is not None:
                raise ValueError('Actual captured clipboard source required')
            from host.router_command_intake import decode_powershell
            script, transform = decode_powershell(text)
        else:
            script, transform = script_from_source(text, args['form'], args.get('start'), args.get('end'))
        if not script.strip() or len(script.encode()) > 65536:
            raise ValueError('Invalid script size')
        derived = self.source(script.encode(), 'derived:' + record.source_id,
                              (record.source_id,), suffix='.ps1')
        binding = InputBinding(derived.source_id, self.paths[derived.source_id].absolute())
        identity = self.session_identity()
        aid = 'A-' + uuid4().hex
        action = Action(aid, aid, Operation.EXECUTE,
            Scope(reads=(binding.guest_path,), writes=(output_directory(identity),),
                  capabilities=('process.execute', 'gui.input', 'gui.observe', 'artifact.export.v1')),
            'D-' + aid, (record, derived),
            Command(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                    ('-NoProfile', '-NonInteractive', '-STA', '-File', binding.guest_path),
                    r'C:\UserFiles', derived.source_id), outputs=('stdout-' + aid,))
        self.execution_action, self.execution_identity, self.binding = action, identity, binding
        self.live_bindings[aid] = (binding,)
        self.audit('EXECUTION_FORCED_SANDBOX', source_id=record.source_id, derived=asdict(derived),
                   transform=transform, fingerprint=action.fingerprint)
        return action

    def session_identity(self):
        if self.execution_identity is None:
            self.execution_identity = ('SES-' + uuid4().hex, 'RT-SBX-001', 1)
        return self.execution_identity

    def prepare_gui(self, args):
        if not self.allow_gui:
            raise ValueError('GUI disabled by operator')
        op = args['operation']
        required = {'observe': set(), 'navigate': {'url'}, 'click': {'x', 'y', 'observation_id'}}
        if op not in required or set(args) != {'operation', 'request_id'} | required[op]:
            raise ValueError('Exact GUI arguments required')
        if op == 'navigate':
            url = args['url']
            self.web_policy.require(url, 'navigate')
        if op == 'click' and any(type(args[k]) is not int or not 0 <= args[k] <= 16383 for k in ('x','y')):
            raise ValueError('Invalid coordinates')
        aid = 'A-' + uuid4().hex
        return Action(aid, aid, Operation.LOCAL_BROWSER, Scope(network=self.web_policy.scope), 'D-' + aid,
            locator=json.dumps({k: v for k, v in args.items() if k != 'request_id'}, sort_keys=True))

    def prepare_clipboard(self):
        if not self.allow_gui:
            raise ValueError('Clipboard analysis disabled')
        aid = 'A-' + uuid4().hex
        return Action(aid, aid, Operation.LOCAL_CLIPBOARD, Scope(), 'D-' + aid, locator='clipboard:local')

    async def call(self, name, args):
        async with self.lock:
            if name in ('router_status', 'router_result', 'router_stop'):
                result = await self.service.call(name, args)
                if name == 'router_result' and result.get('ok'):
                    aid = result['action_id']
                    if aid in self.clipboard_actions and aid not in self.reads and result.get('outputs'):
                        captured = json.loads(result['outputs'][0]['text'].lstrip('\ufeff'))
                        if (captured.get('contract') != 'router-clipboard-v1' or captured.get('user') != 'WDAGUtilityAccount'
                                or type(captured.get('sequence')) is not int or not isinstance(captured.get('text'), str)):
                            raise ValueError('Clipboard evidence invalid')
                        record = self.source(captured['text'].encode(),
                            f'clipboard:{self.execution_identity[0]}:{captured["sequence"]}:{aid}')
                        self.reads[aid] = record
                        self.clipboard_sources.add(record.source_id)
                        self.audit('GUEST_CLIPBOARD_CAPTURED', action_id=aid, sequence=captured['sequence'], source=asdict(record))
                    if self.auto_analyze_clipboard and not self.service.stopped:
                        await self.auto_analysis(result)
                    source = self.reads.get(result['action_id'])
                    if source:
                        result['source'] = asdict(source)
                    if aid in self.click_analyses:
                        result['analysis'] = dict(self.click_analyses[aid])
                return result
            if name not in ('router_read', 'router_execute', 'router_gui', 'router_clipboard_read'):
                self.audit('DIRECT_TOOL_DENIED', tool=name)
                return {'ok': False, 'error': 'TOOL_NOT_EXPOSED'}
            if self.service.stopped:
                return {'ok': False, 'error': 'PLAN_STOPPED'}
            rid = args['request_id']; identifier(rid)
            signature = json.dumps([name, args], sort_keys=True)
            if rid in self.requests:
                if self.requests[rid] != signature:
                    return {'ok': False, 'error': 'IDEMPOTENCY_CONFLICT'}
                return await self.service.call('router_status', {'request_id': rid})
            if len(self.requests) >= 128:
                raise ValueError('Workflow request limit')
            if name == 'router_read':
                if not args['uri'].startswith('mailbox:'):
                    self.web_policy.require(args['uri'], 'read')
                aid = 'A-' + uuid4().hex
                network = (self.web_policy.scope if self.web_policy.mode == 'web'
                           and not args['uri'].startswith('mailbox:') else (args['uri'],))
                action = Action(aid, aid, Operation.BROWSE, Scope(network=network),
                                'D-' + aid, locator=args['uri'])
            elif name == 'router_gui':
                action = self.prepare_gui(args)
            elif name == 'router_clipboard_read':
                if set(args) != {'request_id'}:
                    raise ValueError('Clipboard read takes only request_id')
                action = self.prepare_clipboard()
            else:
                await self.execution_available()
                action = self.prepare_execution(args)
            self.requests[rid] = signature
            return await self.register_submit(rid, action)

    async def close(self):
        if self.closed:
            return
        try:
            await self.service.close()
        finally:
            for task in self.followups:
                task.cancel()
            if self.followups:
                await asyncio.gather(*list(self.followups), return_exceptions=True)
            if self.browser:
                await self.browser.close()
            self.ledger.close()
            self.closed = True
