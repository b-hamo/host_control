import json
import os
import time

from dashboard.collect import Collector
from dashboard.export_history import blocked_exports
from host.dashboard_status import _scan_code


def journal(root, sid='SES-test', **changes):
    path = root / sid / 'output-state.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    row = dict(identity=[sid, 'RT-1', 1], artifact_id='ART-000001',
               path=r'Output\eicar-export-test.txt', stage='BLOCKED',
               result={'code': 'BLOCKED', 'detail': 'MALWARE_DETECTED: test signature'})
    row.update(changes)
    path.write_text(json.dumps({'files': [row]}), encoding='utf-8')
    return path


def test_receipt_needs_no_payload_and_never_exposes_export_path(tmp_path):
    journal(tmp_path)
    rows = list(blocked_exports([tmp_path, tmp_path]))
    assert len(rows) == 1
    assert rows[0]['name'] == 'eicar-export-test.txt'
    assert rows[0]['scan_code'] == 'MALWARE_DETECTED'
    assert rows[0]['export_path'] is None
    assert rows[0]['time_source'] == 'journal_updated_at'


def test_malformed_and_mismatched_receipts_are_ignored(tmp_path):
    path = journal(tmp_path, identity=['SES-other', 'RT-1', 1])
    assert list(blocked_exports([tmp_path])) == []
    for value in ('{', '[]', '{"files": null}', '{"files": [null, 1, {}]}'):
        path.write_text(value, encoding='utf-8')
        assert list(blocked_exports([tmp_path])) == []


def test_only_blocked_receipts_are_used_and_errors_stay_errors(tmp_path):
    journal(tmp_path, stage='EXPORTED')
    assert list(blocked_exports([tmp_path])) == []
    journal(tmp_path, result={'code': 'BLOCKED', 'detail': {'error': {'code': 'SCAN_TIMEOUT'}}})
    assert list(blocked_exports([tmp_path]))[0]['scan_code'] == 'SCAN_TIMEOUT'
    assert _scan_code('BLOCKED', {'error': 'unavailable'}) is None
    assert _scan_code('BLOCKED', {'error': {'code': 'MALWARE_DETECTED'}}) == 'MALWARE_DETECTED'


def test_live_export_wins_and_artifact_ids_are_scoped_to_session(tmp_path):
    journal(tmp_path, 'SES-one')
    journal(tmp_path, 'SES-two')
    c = Collector([], tmp_path / 'dash', output_roots=[tmp_path])
    live = dict(artifact_id='ART-000001', session_id='SES-one', name='live.txt', stage='BLOCKED')
    rows = c._exports({'SES-one': {'exports': [live]}}, {'SES-one': 'VM-01'}, time.time())
    assert len(rows) == 2
    assert next(r for r in rows if r['session_id'] == 'SES-one')['name'] == 'live.txt'
    assert next(r for r in rows if r['session_id'] == 'SES-one')['session_label'] == 'VM-01'


def test_old_journal_is_not_shown_as_recent(tmp_path):
    path = journal(tmp_path)
    old = time.time() - 90000
    os.utime(path, (old, old))
    c = Collector([], tmp_path / 'dash', output_roots=[tmp_path])
    assert c._exports({}, {}, time.time()) == []


def test_windows_av_denial_is_recognized_without_relabeling_generic_errors(tmp_path):
    for number in (225, 226):
        detail = f'SCAN_ERROR: [WinError {number}] OS denied the file'
        journal(tmp_path, result={'code': 'QUARANTINED', 'detail': detail})
        row = list(blocked_exports([tmp_path]))[0]
        assert row['scan_code'] == _scan_code('QUARANTINED', detail) == 'WINDOWS_MALWARE_BLOCKED'
        assert row['code'] == 'QUARANTINED'
    for detail in ('SCAN_ERROR: [WinError 5] access denied', 'SCAN_ERROR: filename [WinError 225]',
                   'SCAN_ERROR: [WinError 2250] other error'):
        journal(tmp_path, result={'code': 'QUARANTINED', 'detail': detail})
        assert list(blocked_exports([tmp_path]))[0]['scan_code'] == 'SCAN_ERROR'
        assert _scan_code('QUARANTINED', detail) == 'SCAN_ERROR'
