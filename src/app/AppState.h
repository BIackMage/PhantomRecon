#pragma once

#include <windows.h>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "AiSidebar.h"
#include "AppMessages.h"
#include "AuditHistory.h"
#include "BackgroundWorker.h"
#include "Baseline.h"
#include "HardeningScore.h"
#include "ResultsModel.h"
#include "ScanCore.h"
#include "SecurityChecks.h"
#include "SettingsDialog.h"

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
    HWND scoreTitle         = NULL;
    HWND scoreValue         = NULL;   // big number
    HWND scoreCaption       = NULL;   // label and counts
    HWND findingsButton     = NULL;
    HWND progressBar        = NULL;
    HWND cancelButton       = NULL;
    HWND filterLabel        = NULL;
    HWND filterCombo        = NULL;
    HWND searchLabel        = NULL;
    HWND searchEdit         = NULL;
    HWND countLabel         = NULL;
    HWND resultsListView    = NULL;
};

// GDI objects the main window creates and destroys. UI thread only.
struct UiResources {
    HFONT uiFont    = NULL;   // message-box font for every control
    HFONT titleFont = NULL;   // panel titles
    HFONT scoreFont = NULL;   // the hardening score number
};

// Live state of the scan in flight. Written by the scan thread, read by the UI
// thread. Atomics for counters and flags, textMutex for the strings, rowsMutex
// for the row queue.
struct ScanProgress {
    std::atomic<int>  filesProcessed{0};
    std::atomic<int>  executablesFound{0};
    std::atomic<int>  totalFiles{0};          // 0 until the pre-count finishes
    std::atomic<unsigned long long> walkStartTick{0};   // GetTickCount64 when the pre-count ended
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

// The posture audit: progress while it runs, results after. Progress fields are
// written by the audit thread; results are written on the UI thread only.
struct AuditState {
    std::atomic<bool> running{false};
    std::atomic<bool> cancelRequested{false};
    std::atomic<int>  done{0};
    std::atomic<int>  total{0};
    std::atomic<bool> progressPosted{false};
    std::mutex        textMutex;
    std::wstring      currentTitle;

    bool                             hasResults = false;
    std::vector<SecurityCheckResult> results;
    HardeningScore                   score;
    std::wstring                     finishedAt;

    // What changed since the previous audit (AuditHistory.h), for the score line, the
    // findings window and the reports. hasHistory false: history off or not available.
    bool                     hasHistory = false;
    AuditComparison          history;
    std::vector<AuditRecord> historyRecords;
    std::wstring             historyError;
};

// The last finished scan, for reports. UI thread only.
struct LastScan {
    bool         has = false;
    ScanSummary  summary;
    std::wstring title;
};

struct AppState {
    HINSTANCE hInstance   = NULL;
    HWND      hMainWindow = NULL;
    WCHAR     title[MAX_LOADSTRING]       = {};
    WCHAR     windowClass[MAX_LOADSTRING] = {};

    MainControls   controls;
    UiResources    ui;
    AiSidebarState aiSidebar;
    HWND           findingsWindow = NULL;   // modeless, at most one
    HWND           detailWindow   = NULL;   // modeless, at most one

    AppSettings  settings;                  // loaded in wWinMain, saved by the Settings dialog
    std::wstring outputCsvPath;             // CSV of the last scan
    std::wstring baselineFilePath;          // active baseline for Full and Fast Scan
    bool         baselinePathChangePending = false;   // Settings changed the baseline file during a scan;
                                                      // OnScanFinished applies it

    ScanProgress progress;
    AuditState   audit;
    LastScan     lastScan;
    ResultsModel results;                   // rows behind the results list, UI thread only

    std::mutex baselineMutex;   // guards currentBaseline while the UI thread swaps it
    Baseline   currentBaseline; // the active baseline used by Full Scan and Fast Scan

    PayloadTracker   payloads;  // every WM_APP payload between post and handler (AppMessages.h)
    BackgroundWorker worker;    // every background thread; joined in wWinMain (with a time limit, see there).
                                // Declared last so it is destroyed (joined) before anything a job uses.
};

// Fetch the AppState pointer stored on the main window. Returns nullptr before
// WM_NCCREATE has run.
inline AppState* GetAppState(HWND hMainWindow)
{
    return reinterpret_cast<AppState*>(GetWindowLongPtrW(hMainWindow, GWLP_USERDATA));
}
