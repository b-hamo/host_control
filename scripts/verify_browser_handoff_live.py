"""Opt-in real MCP/Windows Sandbox smoke test; harmless fixed payload only."""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runner-exe', type=Path, required=True)
    parser.add_argument('--sandbox-root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    before = json.loads(subprocess.check_output(['wsb', 'list', '--raw']))
    if before['WindowsSandboxEnvironments']:
        raise RuntimeError('Existing Sandbox must not be replaced')
    root = args.evidence.resolve()
    root.mkdir(parents=True, exist_ok=False)
    config = dict(directory=str(root/'host'), origins=[], allow_execution=True,
                  allow_external_capture=True, allow_gui=False,
                  runner_exe=str(args.runner_exe.resolve()), sandbox_root=str(args.sandbox_root.resolve()))
    cfg = root/'operator.json'
    cfg.write_text(json.dumps(config), encoding='utf-8')
    log = (root/'stderr.log').open('wb')
    proc = subprocess.Popen([sys.executable, str(Path(__file__).with_name('launch_router_workflow.py')),
        '--config', str(cfg)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    replies = queue.Queue()
    def read():
        for line in proc.stdout:
            replies.put(json.loads(line))
        replies.put(None)
    threading.Thread(target=read, daemon=True).start()
    serial = 0
    def rpc(method, params):
        nonlocal serial
        serial += 1
        message = dict(jsonrpc='2.0', id=serial, method=method, params=params)
        proc.stdin.write((json.dumps(message)+'\n').encode()); proc.stdin.flush()
        response = replies.get(timeout=60)
        with (root/'transport.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(dict(request=message, response=response))+'\n')
        assert response and response['id']==serial, response
        assert 'error' not in response, response
        return response['result']
    def call(name, **arguments):
        result = rpc('tools/call', dict(name=name, arguments=arguments))
        return json.loads(next(c['text'] for c in result['content'] if c['type']=='text'))
    try:
        rpc('initialize', dict(protocolVersion='2025-06-18',capabilities={},clientInfo=dict(name='handoff-smoke',version='1')))
        contracts=rpc('tools/list', {})
        assert 'router_capture' in {t['name'] for t in contracts['tools']}
        # Synthetic browser observation: no hostile URL is fetched and no payload runs on Host.
        host_profile = str(Path.home()).replace("'", "''")
        text = ("Write-Output ('User: ' + $env:USERNAME); Write-Output 'SCRP_HANDOFF_OK'; "
                + "Write-Output ('HostProfileVisible: ' + (Test-Path '" + host_profile + "'))")
        capture=call('router_capture',request_id='capture',source_url='http://127.0.0.1:8787/synthetic-clickfix',text=text)
        assert capture['ok'] and capture['independently_verified'] is False
        assert call('router_execute',request_id='execute',source_id=capture['source']['source_id'],form='powershell-script')['ok']
        deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            result=call('router_result',request_id='execute')
            state=result.get('receipt',{}).get('state')
            if state in {'SUCCEEDED','FAILED','DENIED','HELD','UNKNOWN'}:
                break
            time.sleep(2)
        (root/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        assert result['ok'] and state=='SUCCEEDED',result
        outputs='\n'.join(o.get('text','') for o in result['outputs'])
        assert 'WDAGUtilityAccount' in outputs and 'SCRP_HANDOFF_OK' in outputs, outputs
        assert 'HostProfileVisible: False' in outputs, outputs
        assert call('router_stop')['stopped']
        retained=call('router_result',request_id='execute')
        assert retained['outputs']==result['outputs']
        assert not json.loads(subprocess.check_output(['wsb','list','--raw']))['WindowsSandboxEnvironments']
        summary=dict(passed=True,real_sandbox=True,synthetic_browser_observation=True,
            host_profile_invisible=True,retained_result=True,cleanup=True,
            outbound_network_isolation_tested=False)
        (root/'verification.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(json.dumps(summary),flush=True)
    finally:
        try:
            call('router_stop')
        finally:
            proc.stdin.close()
            proc.wait(timeout=120)
            log.close()

if __name__=='__main__':
    main()
