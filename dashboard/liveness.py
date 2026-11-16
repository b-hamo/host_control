"""Read-only OS evidence. Unknown is distinct from an absent process/runtime."""
from __future__ import annotations

import ctypes
import json
import subprocess
import sys


def process_started(pid):
    """Live process creation FILETIME, None if absent; OSError if inspection is unavailable."""
    if type(pid) is not int or pid <= 0:
        return None
    if sys.platform != 'win32':
        raise OSError('process identity requires Windows')
    from ctypes import wintypes
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    k.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    k.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = k.OpenProcess(0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: no such process
            return None
        raise OSError(error, 'cannot inspect process')
    try:
        code = wintypes.DWORD()
        if not k.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise OSError('cannot read process exit status')
        if code.value != 259:
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            raise OSError('cannot read process creation time')
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    finally:
        k.CloseHandle(handle)


def owner_alive(owner, lookup=process_started):
    if not isinstance(owner, dict) or type(owner.get('pid')) is not int:
        return None
    try:
        actual = lookup(owner['pid'])
    except OSError:
        return None
    if actual is None:
        return False
    expected = owner.get('started')
    return actual == expected if type(expected) is int else None


def wsb_ids():
    try:
        result = subprocess.run(['wsb', 'list', '--raw'], capture_output=True, text=True, timeout=10,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode:
            return None
        rows = json.loads(result.stdout)['WindowsSandboxEnvironments']
        if not isinstance(rows, list) or any(not isinstance(r, dict) or not isinstance(r.get('Id'), str) for r in rows):
            return None
        return {r['Id'].lower() for r in rows}
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return None


def hcs_ids():
    """Current compute systems; permission failures must never become an empty inventory."""
    if sys.platform != 'win32':
        return None
    try:
        c = ctypes.WinDLL('computecore.dll')
        c.HcsCreateOperation.restype = ctypes.c_void_p
        c.HcsCreateOperation.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        c.HcsEnumerateComputeSystems.argtypes = (ctypes.c_wchar_p, ctypes.c_void_p)
        c.HcsWaitForOperationResult.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p))
        c.HcsCloseOperation.argtypes = (ctypes.c_void_p,)
        k = ctypes.WinDLL('kernel32')
        k.LocalFree.argtypes = (ctypes.c_void_p,)
        k.LocalFree.restype = ctypes.c_void_p
        op = c.HcsCreateOperation(None, None)
        if not op:
            return None
        result = ctypes.c_void_p()
        try:
            if c.HcsEnumerateComputeSystems('{}', op) < 0:
                return None
            if c.HcsWaitForOperationResult(op, 5000, ctypes.byref(result)) < 0 or not result.value:
                return None
            rows = json.loads(ctypes.wstring_at(result.value))
            if not isinstance(rows, list) or any(not isinstance(r, dict) or not isinstance(r.get('Id'), str) for r in rows):
                return None
            return {r['Id'].lower() for r in rows if r.get('State') not in ('Stopped', 'Stopping')}
        finally:
            if result.value:
                k.LocalFree(result)
            c.HcsCloseOperation(op)
    except (OSError, ValueError, AttributeError):
        return None
