// PhantomReconCli.exe: console front end for the Phantom Recon engine.
// All the work happens in CliRunner (engine library); this file only wires up
// console output, the optional desktop notification and the exit code.

#include "../pch.h"
#include "../AppPaths.h"
#include "../CliRunner.h"
#include "../StringConv.h"

#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

#pragma comment(lib, "shell32.lib")

// Write to the console with WriteConsoleW (correct for any language); when
// output is redirected to a file or pipe, write UTF-8 instead.
static void WriteOut(const std::wstring& text)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == NULL || h == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    DWORD written = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, text.c_str(), static_cast<DWORD>(text.size()), &written, NULL);
    }
    else {
        std::string utf8 = WideToUtf8(text);
        WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, NULL);
    }
}

static LRESULT CALLBACK NotifyWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Balloon notification from the tray, shown for a few seconds, then removed.
static void ShowNotification(const std::wstring& title, const std::wstring& text)
{
    HINSTANCE inst = GetModuleHandleW(NULL);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = NotifyWndProc;
    wc.hInstance = inst;
    wc.lpszClassName = L"PhantomReconCliNotify";
    RegisterClassExW(&wc);
    HWND hWnd = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
    if (!hWnd) return;

    NOTIFYICONDATAW nid = {};
    nid.cbSize = sizeof(nid);
    nid.hWnd = hWnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_INFO;
    nid.hIcon = LoadIconW(NULL, IDI_INFORMATION);
    wcsncpy_s(nid.szTip, L"Phantom Recon", _TRUNCATE);
    wcsncpy_s(nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szInfo, text.c_str(), _TRUNCATE);
    nid.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_ADD, &nid);

    ULONGLONG until = GetTickCount64() + 8000;
    MSG msg;
    while (GetTickCount64() < until) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(100);
    }
    Shell_NotifyIconW(NIM_DELETE, &nid);
    DestroyWindow(hWnd);
}

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::wstring> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);

    CliEnvironment env;
    env.out = WriteOut;
    env.notify = ShowNotification;
    env.exePathForSchedule = GetExePath();
    env.defaultBaselinePath = AppFilePath(L"phantom_recon_baseline.prbl");
    env.defaultReportsDir = DefaultReportsDirectory();

    return RunCli(ParseCliArguments(args), env);
}
