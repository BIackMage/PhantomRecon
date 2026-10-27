"""Start a program without administrator rights, from a process that has them.

GitHub's Windows runners run every step as an administrator, so code paths that
only run for a normal user (a check that cannot read a protected key, a task it may
not open) are never exercised there. This module asks Windows for the same token a
"Basic User" gets (SAFER level NORMALUSER: the Administrators group becomes deny-only
and the admin privileges are removed), lowers it to medium integrity, and starts the
program with it. Nothing is changed on the machine: no account, no setting, no
service. Defensive use only: it restricts this machine's own test run.

Windows only. Used by run_tests.py --unelevated.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import subprocess

SAFER_SCOPEID_USER = 2
SAFER_LEVELID_NORMALUSER = 0x20000
SAFER_LEVEL_OPEN = 1
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION_CLASS = 20      # TokenElevation
TOKEN_INTEGRITY_CLASS = 25      # TokenIntegrityLevel
TOKEN_GROUPS_CLASS = 2          # TokenGroups
SE_GROUP_ENABLED = 0x4
SE_GROUP_USE_FOR_DENY_ONLY = 0x10
SE_GROUP_INTEGRITY = 0x20
ADMINISTRATORS_SID = "S-1-5-32-544"
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
INFINITE = 0xFFFFFFFF
WAIT_TIMEOUT = 0x00000102
MEDIUM_INTEGRITY_SID = "S-1-16-8192"


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD),
                ("dwThreadId", wt.DWORD)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


_advapi = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel = ctypes.WinDLL("kernel32", use_last_error=True)

_advapi.SaferCreateLevel.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD, ctypes.POINTER(wt.HANDLE), ctypes.c_void_p]
_advapi.SaferCreateLevel.restype = wt.BOOL
_advapi.SaferComputeTokenFromLevel.argtypes = [wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE), wt.DWORD,
                                               ctypes.c_void_p]
_advapi.SaferComputeTokenFromLevel.restype = wt.BOOL
_advapi.SaferCloseLevel.argtypes = [wt.HANDLE]
_advapi.SaferCloseLevel.restype = wt.BOOL
_advapi.ConvertStringSidToSidW.argtypes = [wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
_advapi.ConvertStringSidToSidW.restype = wt.BOOL
_advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_advapi.EqualSid.restype = wt.BOOL
_advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
_advapi.GetLengthSid.restype = wt.DWORD
_advapi.SetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
_advapi.SetTokenInformation.restype = wt.BOOL
_advapi.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
_advapi.GetTokenInformation.restype = wt.BOOL
_advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
_advapi.OpenProcessToken.restype = wt.BOOL
_advapi.CreateProcessAsUserW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL,
                                         wt.DWORD, ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                         ctypes.POINTER(PROCESS_INFORMATION)]
_advapi.CreateProcessAsUserW.restype = wt.BOOL
_kernel.CloseHandle.argtypes = [wt.HANDLE]
_kernel.CloseHandle.restype = wt.BOOL
_kernel.LocalFree.argtypes = [ctypes.c_void_p]
_kernel.LocalFree.restype = ctypes.c_void_p
_kernel.GetCurrentProcess.restype = wt.HANDLE
_kernel.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_kernel.WaitForSingleObject.restype = wt.DWORD
_kernel.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
_kernel.GetExitCodeProcess.restype = wt.BOOL
_kernel.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
_kernel.TerminateProcess.restype = wt.BOOL
_kernel.SetHandleInformation.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD]
_kernel.SetHandleInformation.restype = wt.BOOL


def _check(ok, what: str):
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error(), what)


def token_is_elevated(token) -> bool:
    """TokenElevation as Windows reports it. With UAC turned off (as on GitHub's
    runners) this stays true even for a token whose Administrators group is deny-only,
    so it is only reported for the log; admin_group_active() decides."""
    value = wt.DWORD(0)
    size = wt.DWORD(0)
    _check(_advapi.GetTokenInformation(token, TOKEN_ELEVATION_CLASS, ctypes.byref(value), ctypes.sizeof(value),
                                       ctypes.byref(size)), "GetTokenInformation(TokenElevation)")
    return value.value != 0


def admin_group_active(token) -> bool:
    """True when the token holds the Administrators group enabled and not deny-only:
    the thing that decides whether admin-only files, keys and logs can be opened. The
    program's IsProcessElevated() asks the same question with CheckTokenMembership."""
    size = wt.DWORD(0)
    _advapi.GetTokenInformation(token, TOKEN_GROUPS_CLASS, None, 0, ctypes.byref(size))
    if size.value == 0:
        raise ctypes.WinError(ctypes.get_last_error(), "GetTokenInformation(TokenGroups) size")
    buffer = ctypes.create_string_buffer(size.value)
    _check(_advapi.GetTokenInformation(token, TOKEN_GROUPS_CLASS, buffer, size, ctypes.byref(size)),
           "GetTokenInformation(TokenGroups)")
    count = ctypes.cast(buffer, ctypes.POINTER(wt.DWORD))[0]
    # TOKEN_GROUPS: a DWORD count, then the SID_AND_ATTRIBUTES array at pointer alignment.
    offset = ctypes.sizeof(ctypes.c_void_p)
    groups = (SID_AND_ATTRIBUTES * count).from_buffer(buffer, offset)
    admins = ctypes.c_void_p()
    _check(_advapi.ConvertStringSidToSidW(ADMINISTRATORS_SID, ctypes.byref(admins)), "ConvertStringSidToSidW")
    try:
        for group in groups:
            if _advapi.EqualSid(group.Sid, admins):
                return bool(group.Attributes & SE_GROUP_ENABLED) and not (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY)
        return False
    finally:
        _kernel.LocalFree(admins)


def current_process_is_elevated() -> bool:
    token = wt.HANDLE()
    _check(_advapi.OpenProcessToken(_kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)), "OpenProcessToken")
    try:
        return token_is_elevated(token)
    finally:
        _kernel.CloseHandle(token)


def _normal_user_token():
    level = wt.HANDLE()
    _check(_advapi.SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN,
                                    ctypes.byref(level), None), "SaferCreateLevel")
    token = wt.HANDLE()
    try:
        _check(_advapi.SaferComputeTokenFromLevel(level, None, ctypes.byref(token), 0, None),
               "SaferComputeTokenFromLevel")
    finally:
        _advapi.SaferCloseLevel(level)

    # Medium integrity, as a normal desktop program has. Lowering is always allowed.
    sid = ctypes.c_void_p()
    _check(_advapi.ConvertStringSidToSidW(MEDIUM_INTEGRITY_SID, ctypes.byref(sid)), "ConvertStringSidToSidW")
    try:
        label = TOKEN_MANDATORY_LABEL()
        label.Label.Sid = sid
        label.Label.Attributes = SE_GROUP_INTEGRITY
        size = ctypes.sizeof(label) + _advapi.GetLengthSid(sid)
        _check(_advapi.SetTokenInformation(token, TOKEN_INTEGRITY_CLASS, ctypes.byref(label), size),
               "SetTokenInformation(TokenIntegrityLevel)")
    finally:
        _kernel.LocalFree(sid)
    return token


def run_unelevated(args: list, stdout_file, timeout_seconds: int) -> int:
    """Run args (a list) with a normal-user token. stdout and stderr go to stdout_file
    (an open binary file). Returns the exit code; raises subprocess.TimeoutExpired when
    the program runs longer than timeout_seconds (it is stopped first)."""
    import msvcrt

    token = _normal_user_token()
    print(f"[tools] restricted token: Administrators active {admin_group_active(token)}, "
          f"TokenElevation {token_is_elevated(token)}", flush=True)
    if admin_group_active(token):
        _kernel.CloseHandle(token)
        raise RuntimeError("the restricted token still has the Administrators group enabled")
    out_handle = wt.HANDLE(msvcrt.get_osfhandle(stdout_file.fileno()))
    _check(_kernel.SetHandleInformation(out_handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT), "SetHandleInformation")
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    startup.dwFlags = STARTF_USESTDHANDLES
    startup.hStdInput = None
    startup.hStdOutput = out_handle
    startup.hStdError = out_handle
    info = PROCESS_INFORMATION()
    command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(a) for a in args]))
    try:
        _check(_advapi.CreateProcessAsUserW(token, None, command, None, None, True, CREATE_NO_WINDOW, None, None,
                                            ctypes.byref(startup), ctypes.byref(info)), "CreateProcessAsUserW")
    finally:
        _kernel.SetHandleInformation(out_handle, HANDLE_FLAG_INHERIT, 0)
        _kernel.CloseHandle(token)
    try:
        wait = _kernel.WaitForSingleObject(info.hProcess, timeout_seconds * 1000 if timeout_seconds else INFINITE)
        if wait == WAIT_TIMEOUT:
            _kernel.TerminateProcess(info.hProcess, 4)
            _kernel.WaitForSingleObject(info.hProcess, 30000)
            raise subprocess.TimeoutExpired(args, timeout_seconds)
        code = wt.DWORD(0)
        _check(_kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)), "GetExitCodeProcess")
        return code.value
    finally:
        _kernel.CloseHandle(info.hThread)
        _kernel.CloseHandle(info.hProcess)
