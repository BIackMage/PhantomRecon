#pragma once

#include <windows.h>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "AiSidebar.h"
#include "AppMessages.h"
#include "BackgroundWorker.h"
#include "Baseline.h"

#define MAX_LOADSTRING 100

// ---------------------------------------------------------------------------
// AppState: the single owner of application state.
//
// One instance lives on the stack in wWinMain. The main window stores a pointer
// to it in GWLP_USERDATA at WM_NCCREATE; everything else reaches it through
// GetAppState(hWnd) or a reference passed down. There are no other globals.
// ---------------------------------------------------------------------------

// Handles of the controls on the main window. UI thread only.
struct MainControls {
    HWND systemInfoTitle    = NULL;
    HWND systemInfoLabel    = NULL;
    HWND operationInfoTitle = NULL;
    HWND operationInfoLabel = NULL;
    HWND progressBar        = NULL;
    HWND cancelButton       = NULL;
    HWND resultsListView    = NULL;
};

// Live state of the scan in flight. Written by the scan thread, read by the UI
// thread. Atomics for counters and flags, textMutex for the strings, rowsMutex
// for the row queue.
struct ScanProgress {
    std::atomic<int>  filesProcessed{0};
    std::atomic<int>  executablesFound{0};
    std::atomic<bool> cancelRequested{false};
    std::atomic<bool> running{false};

    // At most one of each message is in flight. The poster sets the flag with
    // exchange(true); the UI handler clears it after draining.
    std::atomic<bool> progressPosted{false};
    std::atomic<bool> rowsPosted{false};

    std::mutex   textMutex;
    std::wstring state = L"Stopped";
    std::wstring currentFileName;
    std::wstring currentFilePath;

    std::mutex           rowsMutex;
    std::vector<ScanRow> pendingRows;
};

struct AppState {
    HINSTANCE hInstance   = NULL;
    HWND      hMainWindow = NULL;
    WCHAR     title[MAX_LOADSTRING]       = {};
    WCHAR     windowClass[MAX_LOADSTRING] = {};

    MainControls   controls;
    AiSidebarState aiSidebar;

    std::wstring outputCsvPath    = L"output.csv";
    std::wstring baselineFilePath = L"phantom_recon_baseline.prbl";

    ScanProgress progress;

    std::mutex baselineMutex;   // guards currentBaseline while the UI thread swaps it
    Baseline   currentBaseline; // the active baseline used by Full Scan and Fast Scan

    BackgroundWorker worker;    // every background thread; joined in wWinMain
};

// Fetch the AppState pointer stored on the main window. Returns nullptr before
// WM_NCCREATE has run.
inline AppState* GetAppState(HWND hMainWindow)
{
    return reinterpret_cast<AppState*>(GetWindowLongPtrW(hMainWindow, GWLP_USERDATA));
}
