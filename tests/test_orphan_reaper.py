"""The watcher of a batch child Host (2026-11-26): a Host ended before it could stop its runtime.

- it acts only after that one Host is gone, on that Host's own Manager folder (reclaim_orphans)
- when it cannot tell whether the Host is alive, it does nothing
- starting it never fails the Host
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from host import orphan_reaper


class Manager:
    def __init__(self, found):
        self.found, self.calls = found, 0

    def reclaim_orphans(self):
        self.calls += 1
        return self.found


def test_it_waits_for_the_host_and_then_reclaims_what_is_left():
    states, naps, events = iter([True, True, False]), [], []
    manager = Manager(["SES-1"])
    got = orphan_reaper.watch({"pid": 4242}, alive=lambda: next(states), manager=manager, sleep=naps.append,
                              on_event=events.append)
    assert got == ["SES-1"] and manager.calls == 1
    assert naps == [orphan_reaper.POLL_S, orphan_reaper.POLL_S, orphan_reaper.SETTLE_S]    # not before it is gone
    assert events == ["Host pid 4242 is gone; checking its sessions", "reclaimed ['SES-1']"]


def test_after_a_normal_end_there_is_nothing_to_stop():
    events = []
    assert orphan_reaper.watch({"pid": 1}, alive=lambda: False, manager=Manager([]), sleep=lambda s: None,
                               on_event=events.append) == []
    assert events[-1] == "nothing left to stop"


def test_a_host_it_cannot_check_counts_as_alive(monkeypatch):
    import sandbox_manager.process as process
    answers = iter([OSError("access denied"), 111, 222, None])

    def started(pid):
        answer = next(answers)
        if isinstance(answer, OSError):
            raise answer
        return answer
    monkeypatch.setattr(process, "process_started", started)
    naps = []
    manager = Manager([])
    orphan_reaper.watch({"pid": 7, "started": 111}, manager=manager, sleep=naps.append)
    # unreadable -> alive; same start time -> alive; another start time (the pid was reused) -> gone
    assert naps == [orphan_reaper.POLL_S, orphan_reaper.POLL_S, orphan_reaper.SETTLE_S] and manager.calls == 1


def test_the_host_leaves_the_plan_and_starts_the_watcher_outside_its_tree(tmp_path):
    args = SimpleNamespace(sandbox_root=tmp_path / "sandbox", micro_vm_package=Path("C:/pkg"), micro_vm_root=Path("C:/vm"),
                           micro_vm_relay=Path("C:/pkg/relay.exe"), micro_vm_max_active=8, auto_vm_app_window=True)
    launched = []
    assert orphan_reaper.start(args, launch=launched.append) is True
    plan = json.loads((tmp_path / "sandbox" / "reaper.json").read_text(encoding="utf-8"))
    import os
    assert plan["pid"] == os.getpid() and plan["root"] == str(tmp_path / "sandbox")
    assert plan["micro_vm"] == {"package": str(Path("C:/pkg")), "vm_root": str(Path("C:/vm")),
                                "relay": str(Path("C:/pkg/relay.exe")), "max_active": 8, "automatic": True}
    assert len(launched) == 1 and "orphan_reaper.py" in launched[0] and "reaper.json" in launched[0]

    def broken(command):
        raise OSError("no WMI")
    assert orphan_reaper.start(args, launch=broken) is False            # the Host goes on without it


def test_the_watcher_builds_the_hosts_own_kind_of_manager(tmp_path):
    plain = orphan_reaper.build_manager({"root": str(tmp_path / "a"), "micro_vm": None}, lambda m: None)
    assert type(plain).__name__ == "SandboxManager" and plain.root == tmp_path / "a"
    assert sys.platform != "win32" or callable(plain.reclaim_orphans)
