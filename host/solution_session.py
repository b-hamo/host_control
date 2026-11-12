"""Ordinary-user MCP client for standalone start and interactive export verification.

The user closes the Sandbox and chooses keep/delete in the actual Host dialog.
No stop/approve RPC, mock scanner or direct Host-side test file creation is used.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from host.solution_config import read_profile


class Client:
    def __init__(self, config: Path, profile: dict):
        self.log = (Path(profile['state']) / 'session-client.log').open('a', encoding='utf-8')
        self.process = subprocess.Popen(
            [profile['python'], str(REPO / 'host/solution.py'), '--config', str(config)],
            cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
            text=True, encoding='utf-8', env=os.environ | {'PYTHONIOENCODING': 'utf-8'})
        self.responses = queue.Queue()
        self.seq = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            try:
                self.responses.put(json.loads(line))
            except ValueError:
                self.responses.put({'error': {'message': 'non-JSON MCP stdout'}})
        self.responses.put({'error': {'message': 'MCP Host exited'}})

    def rpc(self, method: str, params: dict, timeout=950):
        self.seq += 1
        self.process.stdin.write(json.dumps(dict(jsonrpc='2.0', id=self.seq, method=method, params=params))+'\n')
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            message = self.responses.get(timeout=max(.01, deadline-time.monotonic()))
            if 'error' in message:
                raise RuntimeError(message['error'])
            if message.get('id') == self.seq:
                return message['result']
            if time.monotonic() >= deadline:
                raise TimeoutError('MCP response deadline exceeded; input will not be repeated')

    def call(self, name: str, **arguments):
        response = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        values = [json.loads(c['text']) for c in response.get('content', []) if c.get('type') == 'text']
        result = values[0] if values else {}
        if response.get('isError') or result.get('ok') is False:
            raise RuntimeError(f'{name}: {result}')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if args.verify:
        from host.unified_verification import main as verify_output
        return verify_output(['--config', str(args.config)]) or 0
    profile = read_profile(args.config)
    state = Path(profile['state'])
    client = Client(args.config, profile)
    report = {'status': 'STARTING', 'verification': args.verify}
    report_path = state / 'session-result.json'

    def save():
        temp = report_path.with_suffix('.tmp')
        temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        temp.replace(report_path)

    save()
    try:
        client.rpc('initialize', {'protocolVersion': '2024-11-05', 'capabilities': {},
                                 'clientInfo': {'name': 'solution-session', 'version': '1'}})
        client.call('task_submit', goal='Start the integrated Sandbox for user-operated work. Save results through the Desktop Output shortcut.',
                    required_capabilities=['gui.observe', 'gui.input', 'filesystem.workspace', 'process.execute'],
                    artifact_expected=True)
        deadline = time.monotonic() + 200
        while True:
            runtime = client.call('runtime_get_state')
            if runtime.get('runtime_state') == 'READY':
                break
            if runtime.get('runtime_state') in ('TERMINATED', 'FAILED') or time.monotonic() > deadline:
                raise RuntimeError(f'Sandbox did not become READY: {runtime}')
            time.sleep(2)
        report.update(status='READY', sandbox=runtime.get('sandbox'))
        save()
        print('SOLUTION_READY. Close the Sandbox window when finished; choose keep/delete in the Host dialog.', flush=True)
        while True:
            runtime = client.call('runtime_get_state')
            if runtime.get('runtime_state') == 'TERMINATED':
                break
            time.sleep(2)
        report['status'] = 'TERMINATED'
        save()
        client.process.stdin.close()
        client.process.wait(timeout=30)
        print(json.dumps(report, ensure_ascii=False), flush=True)
    except (Exception, KeyboardInterrupt) as exc:
        report.update(status='FAILED', error=str(exc))
        save()
        print(f'VERIFICATION_FAILED: {exc}. Existing Sandbox is not stopped automatically. Close its window to finish.', flush=True)
        # Keep the MCP pipe alive until the user closes the VM; do not terminate on timeout.
        while client.process.poll() is None:
            try:
                if client.call('runtime_get_state').get('runtime_state') in ('TERMINATED', 'NOT_STARTED'):
                    client.process.stdin.close()
                    client.process.wait(timeout=30)
                    break
            except Exception:
                pass
            time.sleep(2)
        return 1
    finally:
        client.log.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
