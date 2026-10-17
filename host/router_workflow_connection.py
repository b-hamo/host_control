"""Keep MCP transport alive across explicitly stopped dynamic workflows.

Retired workflows are immutable query targets. Only a fresh work request can
create a new workflow, after confirmed cleanup; reads of old results never do.
"""
import asyncio
import json
from pathlib import Path
from uuid import uuid4

from host.router_workflow import RouterWorkflow
from router.models import identifier
from host.router_task_scope import load_task


class WorkflowConnection:
    def __init__(self, **config):
        self.task_file = config.pop('task_file', None)
        self.directory = Path(config.pop('directory'))
        self.directory.mkdir(parents=True, exist_ok=False)
        self.config = config
        self.workflows = []
        self.lock = asyncio.Lock()
        self.closed = False

    def owner(self, request_id):
        return next((w for w in self.workflows if request_id in w.requests), None)

    def screenshot_root(self, body):
        owner = self.owner(body['receipt']['request_id'])
        if owner is None:
            raise ValueError('Unknown screenshot owner')
        return owner.private / 'browser'

    async def call(self, name, args):
        async with self.lock:
            if self.closed:
                return {'ok': False, 'error': 'CONNECTION_CLOSED'}
            if name == 'router_stop':
                if not self.workflows:
                    return {'ok': True, 'stopped': True}
                return await self.workflows[-1].call(name, args)
            if name not in {'router_status', 'router_result', 'router_read',
                            'router_execute', 'router_gui', 'router_clipboard_read'}:
                return {'ok': False, 'error': 'TOOL_NOT_EXPOSED'}
            rid = args['request_id']
            identifier(rid)
            owner = self.owner(rid)
            if name in {'router_status', 'router_result'}:
                return (await owner.call(name, args) if owner else
                        {'ok': False, 'error': 'REQUEST_NOT_FOUND'})
            if owner:
                if owner.requests[rid] != json.dumps([name, args], sort_keys=True):
                    return {'ok': False, 'error': 'IDEMPOTENCY_CONFLICT'}
                return await owner.call('router_status', {'request_id': rid})

            current = self.workflows[-1] if self.workflows else None
            if current and current.service.stopped:
                # Also waits for the runtime-loss watcher to finish cleanup.
                stopped = await current.call('router_stop', {})
                if not stopped.get('ok'):
                    return {'ok': False, 'error': 'CLEANUP_UNCONFIRMED'}
                # Cancel old automatic continuations before another session exists.
                for task in list(current.followups):
                    task.cancel()
                await asyncio.gather(*list(current.followups), return_exceptions=True)
                current = None
            if current is None:
                config = dict(self.config)
                task = load_task(self.task_file) if self.task_file else None
                if task:
                    config.update(origins=task['origins'], browsing_policy='scoped')
                current = RouterWorkflow(directory=self.directory / ('WORK-' + uuid4().hex), **config)
                if task:
                    current.audit('USER_TASK_SCOPE', **task)
                self.workflows.append(current)
            if name == 'router_execute' and args['source_id'] not in current.authority.sources:
                # Reuse captured data, never a retired execution/grant. Validate
                # the original immutable file before minting a new exact action.
                sid = args['source_id']
                previous = next((w for w in self.workflows[:-1] if sid in w.authority.sources), None)
                if previous is None:
                    raise ValueError('Source unavailable')
                source = previous.authority.sources[sid]
                if source.parents or not previous.verify_source(source):
                    raise ValueError('Source changed or unsupported source ancestry')
                current.paths[sid] = previous.paths[sid]
                current.authority.sources[sid] = source
                if sid in previous.clipboard_sources:
                    current.clipboard_sources.add(sid)
            return await current.call(name, args)

    async def close(self):
        async with self.lock:
            self.closed = True
            errors = []
            for workflow in self.workflows:
                try:
                    await workflow.close()
                except Exception as exc:
                    errors.append(exc)
            if errors:
                raise RuntimeError('Workflow cleanup unconfirmed')
