"""Start the window program, wait for its main window, close it, and check it exits.

  python tools/gui_start_check.py [--exe x64/Release/PhantomRecon.exe] [--start-timeout 60]
                                  [--close-timeout 90] [--allow-dialog]

Catches what a unit test cannot: a program that does not start at all (a missing DLL
such as the Visual C++ runtime ends it with 0xC0000135 before any code runs), one
that shows an error box instead of its window, and one that does not shut down when
its window is closed (a worker that is never joined).

Steps: start the program; wait until it shows a visible top-level window; fail if it
exits first or if that window is a dialog box (an error message) unless
--allow-dialog; let it run a few seconds; post WM_CLOSE to the window, the same
message the title bar's X sends; require a clean exit (code 0) within
--close-timeout. On failure the program is stopped and the titles of its open
windows are printed. Nothing is clicked and no key is pressed.

Windows only; needs a desktop session (GitHub's Windows runners have one).
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import pathlib
import subprocess
import sys
import time

from release_common import DEFAULT_EXE_DIR, configure_console, log

WM_CLOSE = 0x0010
DIALOG_CLASS = "#32770"
KNOWN_EXIT_CODES = {
    0xC0000135: "a DLL the program needs is missing (STATUS_DLL_NOT_FOUND)",
    0xC000007B: "a DLL is for the wrong architecture (STATUS_INVALID_IMAGE_FORMAT)",
    0xC0000139: "a function the program needs is missing from a DLL (STATUS_ENTRYPOINT_NOT_FOUND)",
    0xC0000005: "the program crashed (access violation)",
    0xC0000409: "the program stopped itself after detecting a corrupted stack or a failed check",
}

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_ENUM_PROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
_user32.EnumWindows.argtypes = [_ENUM_PROC, wt.LPARAM]
_user32.EnumWindows.restype = wt.BOOL
_user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
_user32.GetWindowThreadProcessId.restype = wt.DWORD
_user32.IsWindowVisible.argtypes = [wt.HWND]
_user32.IsWindowVisible.restype = wt.BOOL
_user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
_user32.GetWindowTextW.restype = ctypes.c_int
_user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
_user32.GetClassNameW.restype = ctypes.c_int
_user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
_user32.PostMessageW.restype = wt.BOOL


class StartCheckFailure(Exception):
    pass


def visible_windows(pid: int) -> list:
    """(hwnd, class name, title) of every visible top-level window of the process."""
    found = []

    def callback(hwnd, _):
        owner = wt.DWORD(0)
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and _user32.IsWindowVisible(hwnd):
            title = ctypes.create_unicode_buffer(512)
            cls = ctypes.create_unicode_buffer(256)
            _user32.GetWindowTextW(hwnd, title, 512)
            _user32.GetClassNameW(hwnd, cls, 256)
            found.append((hwnd, cls.value, title.value))
        return True

    _user32.EnumWindows(_ENUM_PROC(callback), 0)
    return found


def describe_exit(code: int) -> str:
    code &= 0xFFFFFFFF
    meaning = KNOWN_EXIT_CODES.get(code, "")
    return f"{code} (0x{code:08X}){': ' + meaning if meaning else ''}"


def check(exe: pathlib.Path, start_timeout: float, close_timeout: float, settle: float, allow_dialog: bool) -> None:
    if not exe.is_file():
        raise StartCheckFailure(f"{exe} does not exist")
    log(f"starting {exe}")
    process = subprocess.Popen([str(exe)], cwd=str(exe.parent))
    try:
        deadline = time.monotonic() + start_timeout
        windows = []
        while time.monotonic() < deadline:
            code = process.poll()
            if code is not None:
                raise StartCheckFailure(f"the program exited before showing a window, exit code {describe_exit(code)}")
            windows = visible_windows(process.pid)
            if windows:
                break
            time.sleep(0.25)
        if not windows:
            raise StartCheckFailure(f"no visible window after {start_timeout:.0f} s")
        for hwnd, cls, title in windows:
            log(f"window: class {cls!r}, title {title!r}")

        # Give the startup work (settings, the first audit) a moment, then look again:
        # an error box often comes up right after the main window.
        time.sleep(settle)
        code = process.poll()
        if code is not None:
            raise StartCheckFailure(f"the program exited on its own after starting, exit code {describe_exit(code)}")
        windows = visible_windows(process.pid)
        dialogs = [w for w in windows if w[1] == DIALOG_CLASS]
        if dialogs and not allow_dialog:
            raise StartCheckFailure("a dialog box is open: " + "; ".join(repr(w[2]) for w in dialogs))
        main = next((w for w in windows if w[1] != DIALOG_CLASS), windows[0] if windows else None)
        if main is None:
            raise StartCheckFailure("the program's window went away")

        log(f"closing the window {main[2]!r} with WM_CLOSE")
        if not _user32.PostMessageW(main[0], WM_CLOSE, 0, 0):
            raise StartCheckFailure(f"PostMessage(WM_CLOSE) failed, error {ctypes.get_last_error()}")
        try:
            code = process.wait(timeout=close_timeout)
        except subprocess.TimeoutExpired:
            still = visible_windows(process.pid)
            raise StartCheckFailure(f"still running {close_timeout:.0f} s after WM_CLOSE; open windows: "
                                    + ("; ".join(f"{w[1]} {w[2]!r}" for w in still) or "none visible"))
        if code != 0:
            raise StartCheckFailure(f"exit code after closing was {describe_exit(code)}, expected 0")
        log("the program closed cleanly")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", type=pathlib.Path, default=DEFAULT_EXE_DIR / "PhantomRecon.exe")
    parser.add_argument("--start-timeout", type=float, default=60.0)
    parser.add_argument("--close-timeout", type=float, default=90.0)
    parser.add_argument("--settle", type=float, default=5.0, help="seconds to let it run before closing")
    parser.add_argument("--allow-dialog", action="store_true",
                        help="a dialog box as the window is fine (for programs whose main window is one)")
    args = parser.parse_args()
    try:
        check(args.exe.resolve(), args.start_timeout, args.close_timeout, args.settle, args.allow_dialog)
    except StartCheckFailure as failure:
        print(f"START CHECK FAILED: {failure}", flush=True)
        return 1
    print("The window program started and closed cleanly.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
