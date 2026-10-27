#include "pch.h"
#include "StartupArgs.h"

#include "AppPaths.h"
#include "MainCommands.h"
#include "TextUtils.h"

#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[StartupArgs] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

void OpenFileByType(AppState& app, HWND hWnd, const std::wstring& path, bool confirmBaseline)
{
    std::wstring full = AbsolutePath(path);
    std::wstring ext = ExtensionOf(full);
    DebugLog(L"Opening " + full);
    if (ext == L".csv") OpenScanResultsFile(app, hWnd, full);
    else if (ext == L".prbl") OpenBaselineFile(app, hWnd, full, confirmBaseline);
    else MessageBoxW(hWnd, (L"Phantom Recon opens .csv scan results and .prbl baselines. Not this file:\n" + full).c_str(),
                     L"Open", MB_OK | MB_ICONINFORMATION);
}

bool HandleStartupArguments(AppState& app, HWND hWnd)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;
    std::vector<std::wstring> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    LocalFree(argv);

    StartupRequest r = ParseStartupArguments(args);
    if (!r.unknown.empty()) {
        std::wstring text = L"These command-line arguments were not understood and were ignored:\n";
        for (const std::wstring& u : r.unknown) text += L"  " + u + L"\n";
        text += L"\nThe window program accepts .csv and .prbl files and --samples <folder>. "
                L"PhantomReconCli.exe --help lists the console options.";
        MessageBoxW(hWnd, text.c_str(), L"Phantom Recon", MB_OK | MB_ICONINFORMATION);
    }
    for (const std::wstring& f : r.files) OpenFileByType(app, hWnd, f, false);
    if (!r.samplesFolder.empty()) CreateSamplePackInFolder(app, hWnd, AbsolutePath(r.samplesFolder), false);
    return !r.files.empty() || !r.samplesFolder.empty();
}

void OnDropFiles(AppState& app, HWND hWnd, HDROP drop)
{
    UINT count = DragQueryFileW(drop, 0xFFFFFFFF, NULL, 0);
    std::vector<std::wstring> paths;
    for (UINT i = 0; i < count; ++i) {
        UINT len = DragQueryFileW(drop, i, NULL, 0);
        std::wstring path(static_cast<size_t>(len) + 1, L'\0');
        DragQueryFileW(drop, i, &path[0], len + 1);
        path.resize(len);
        paths.push_back(path);
    }
    DragFinish(drop);
    for (const std::wstring& p : paths) OpenFileByType(app, hWnd, p, true);
}
