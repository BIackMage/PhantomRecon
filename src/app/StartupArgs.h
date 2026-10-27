#pragma once

#include <windows.h>
#include <shellapi.h>
#include <string>
#include "AppState.h"
#include "StartupRequest.h"

// ---------------------------------------------------------------------------
// StartupArgs: what PhantomRecon.exe does with its command line (parsed by
// StartupRequest.cpp) and with files dropped on the window. UI thread only.
// The console program (PhantomReconCli.exe) has the full set of options.
// ---------------------------------------------------------------------------

// Read the real command line and act on it. True when it asked for something,
// so the Getting Started window is skipped.
bool HandleStartupArguments(AppState& app, HWND hWnd);

// Open one .csv or .prbl file (command line or drag and drop).
void OpenFileByType(AppState& app, HWND hWnd, const std::wstring& path, bool confirmBaseline);

// WM_DROPFILES handler. Takes ownership of the drop handle.
void OnDropFiles(AppState& app, HWND hWnd, HDROP drop);
