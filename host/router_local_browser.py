"""Owned local Edge tab. No desktop keys, shell, arbitrary CDP or JS tool API.

This confines Router's own input surface, not unrelated Host processes. Website
JavaScript still runs in Edge's normal browser sandbox. Clipboard provenance is
temporal evidence, not proof against other programs writing concurrently.
"""
import asyncio
import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit
from uuid import uuid4


def clipboard_snapshot():
    user = ctypes.WinDLL('user32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    user.GetClipboardData.argtypes = [wintypes.UINT]
    user.GetClipboardData.restype = wintypes.HANDLE
    kernel.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel.GlobalLock.restype = ctypes.c_void_p
    kernel.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel.GlobalSize.argtypes = [wintypes.HGLOBAL]
    kernel.GlobalSize.restype = ctypes.c_size_t
    if not user.OpenClipboard(None):
        raise ValueError('Clipboard busy; no fallback')
    try:
        sequence = user.GetClipboardSequenceNumber()
        handle = user.GetClipboardData(13)
        text = ''
        if handle:
            size = kernel.GlobalSize(handle)
            if not 0 < size <= 131074:
                raise ValueError('Clipboard exceeds capture limit')
            ptr = kernel.GlobalLock(handle)
            if not ptr:
                raise ValueError('Clipboard unavailable')
            try:
                raw = ctypes.string_at(ptr, size)
                text = raw.decode('utf-16-le').split('\0', 1)[0]
            finally:
                kernel.GlobalUnlock(handle)
        return {'sequence': sequence, 'text': text}
    finally:
        user.CloseClipboard()


class LocalBrowser:
    def __init__(self, directory, origins, clipboard=clipboard_snapshot):
        self.directory = Path(directory)
        self.directory.mkdir()
        self.origins = frozenset(origins)
        self.clipboard = clipboard
        self.ws = self.process = self.reader = None
        self.pending, self.tasks = {}, set()
        self.serial = 0
        self.session = None
        self.observation = None
        self.captured = None
        self.url = 'about:blank'
        self.lock = asyncio.Lock()

    def allowed(self, url):
        p = urlsplit(url)
        return (p.scheme == 'https' and not p.username and not p.password
                and f'{p.scheme}://{p.netloc}' in self.origins)

    async def command(self, method, params=None, session=None):
        self.serial += 1
        serial = self.serial
        future = asyncio.get_running_loop().create_future()
        self.pending[serial] = future
        message = {'id': serial, 'method': method, 'params': params or {}}
        if session:
            message['sessionId'] = session
        try:
            await self.ws.send(json.dumps(message))
            return await asyncio.wait_for(future, 20)
        finally:
            self.pending.pop(serial, None)

    async def receive(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if msg.get('id') in self.pending:
                    future = self.pending[msg['id']]
                    if not future.done():
                        if 'error' in msg:
                            future.set_exception(ValueError(str(msg['error'])))
                        else:
                            future.set_result(msg.get('result', {}))
                elif 'method' in msg:
                    task = asyncio.create_task(self.event(msg))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ValueError('Owned browser disconnected'))

    async def event(self, msg):
        p = msg['params']
        if msg['method'] == 'Fetch.requestPaused':
            permitted = self.allowed(p['request']['url'])
            await self.command('Fetch.continueRequest' if permitted else 'Fetch.failRequest',
                {'requestId': p['requestId'], **({} if permitted else {'errorReason': 'BlockedByClient'})},
                msg.get('sessionId'))
        elif msg['method'] == 'Target.attachedToTarget':
            # New windows/workers never receive an input channel; close pages
            # while still paused before any content is allowed to run.
            if p['targetInfo']['type'] == 'page' and p['targetInfo']['targetId'] != getattr(self, 'target', None):
                await self.command('Target.closeTarget', {'targetId': p['targetInfo']['targetId']})

    async def start(self):
        if self.ws:
            return
        candidates = [Path(os.environ[k]) / 'Microsoft/Edge/Application/msedge.exe'
                      for k in ('ProgramFiles(x86)', 'ProgramFiles') if k in os.environ]
        executable = next((p for p in candidates if p.is_file()), None)
        if executable is None:
            raise ValueError('Installed Edge unavailable')
        profile = self.directory / 'profile'
        self.process = subprocess.Popen([str(executable), '--remote-debugging-port=0',
            '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + str(profile),
            '--no-first-run', '--no-default-browser-check', '--disable-background-mode',
            '--disable-extensions', '--window-size=1200,900', 'about:blank'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        marker = profile / 'DevToolsActivePort'
        for _ in range(100):
            if marker.exists():
                break
            await asyncio.sleep(.1)
        port, endpoint = marker.read_text().splitlines()[:2]
        from websockets.asyncio.client import connect
        self.ws = await connect(f'ws://127.0.0.1:{int(port)}{endpoint}', max_size=16 * 1024 * 1024)
        self.reader = asyncio.create_task(self.receive())
        await self.command('Browser.setDownloadBehavior', {'behavior': 'deny'})
        targets = (await self.command('Target.getTargets'))['targetInfos']
        self.target = next(t['targetId'] for t in targets if t['type'] == 'page')
        self.session = (await self.command('Target.attachToTarget', {'targetId': self.target, 'flatten': True}))['sessionId']
        await self.command('Target.setAutoAttach', {'autoAttach': True, 'waitForDebuggerOnStart': True, 'flatten': True})
        await self.command('Page.enable', session=self.session)
        await self.command('Fetch.enable', {'patterns': [{'urlPattern': '*'}]}, self.session)
        await self.command('Emulation.setDeviceMetricsOverride',
            {'width': 1180, 'height': 780, 'deviceScaleFactor': 1, 'mobile': False}, self.session)
        for origin in self.origins:
            await self.command('Browser.setPermission', {'permission': {'name': 'clipboard-write'},
                'setting': 'granted', 'origin': origin})

    async def run(self, args):
        async with self.lock:
            await self.start()
            op = args['operation']
            if op == 'navigate':
                if not self.allowed(args['url']):
                    raise ValueError('Navigation outside operator scope')
                self.captured = None
                result = await self.command('Page.navigate', {'url': args['url']}, self.session)
                if result.get('errorText'):
                    raise ValueError(result['errorText'])
                await asyncio.sleep(.8)
            elif op == 'click':
                if args['observation_id'] != self.observation:
                    raise ValueError('Fresh observation required')
                if not (0 <= args['x'] < 1180 and 0 <= args['y'] < 780):
                    raise ValueError('Click outside owned browser viewport')
                before = self.clipboard()
                self.captured = None
                for kind in ('mousePressed', 'mouseReleased'):
                    await self.command('Input.dispatchMouseEvent', {'type': kind, 'x': args['x'],
                        'y': args['y'], 'button': 'left', 'clickCount': 1}, self.session)
                await asyncio.sleep(.8)
                after = self.clipboard()
                if after['sequence'] != before['sequence'] and after['text']:
                    self.captured = {**after, 'source_url': self.url, 'after_observation': self.observation}
            elif op != 'observe':
                raise ValueError('Only scoped navigation, observation and pointer clicks exist')
            tree = await self.command('Page.getFrameTree', session=self.session)
            self.url = tree['frameTree']['frame']['url']
            if self.url != 'about:blank' and not self.allowed(self.url):
                raise ValueError('Unscoped page; no further input allowed')
            image = await self.command('Page.captureScreenshot', {'format': 'png'}, self.session)
            raw = base64.b64decode(image['data'], validate=True)
            self.observation = 'OBS-' + uuid4().hex
            path = self.directory / (self.observation + '.png')
            path.write_bytes(raw)
            return {'contract': 'router-local-browser-v1', 'location': 'LOCAL', 'url': self.url,
                'observation_id': self.observation, 'screenshot_path': str(path),
                'screenshot_sha256': hashlib.sha256(raw).hexdigest(),
                'clipboard_changed': self.captured is not None}

    def read_clipboard(self):
        current = self.clipboard()
        if self.captured is None or any(current[k] != self.captured[k] for k in ('sequence', 'text')):
            raise ValueError('No unchanged clipboard captured after an owned browser click')
        return dict(self.captured)

    async def close(self):
        if self.ws:
            try:
                await self.command('Browser.close')
            except Exception:
                pass
            await self.ws.close()
        if self.reader:
            await asyncio.gather(self.reader, return_exceptions=True)
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.ws = self.reader = None
