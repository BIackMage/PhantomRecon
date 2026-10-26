#include "pch.h"
#include "MainCommands.h"

#include "resource.h"
#include "GuiComponents.h"
#include "ScanEngine.h"
#include "SettingsDialog.h"

#include <commctrl.h>
#include <commdlg.h>
#include <sstream>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[MainCommands] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

// Forward declaration: the About box procedure lives in PhantomRecon.cpp.
INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// True (and tells the user) when a scan is running and the command must wait.
static bool RefuseWhileScanning(AppState& app, HWND hWnd, const wchar_t* what)
{
    if (!app.progress.running) return false;
    std::wstring text = std::wstring(L"A scan is running. Cancel it or wait for it to finish before you ") + what + L".";
    MessageBoxW(hWnd, text.c_str(), L"Scan In Progress", MB_OK | MB_ICONINFORMATION);
    return true;
}

// Show a Save dialog for the CSV path and store it on the app. False if cancelled.
static bool PromptForOutputPath(AppState& app, HWND hWnd)
{
    wchar_t szFile[MAX_PATH] = L"output.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Choose Output Location for Scan Results";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) {
        DebugLog(L"Output path selection cancelled");
        return false;
    }
    app.outputCsvPath = szFile;
    DebugLog(L"Output path selected: " + app.outputCsvPath);
    return true;
}

// Load the active baseline from disk for a comparison scan and warn if it is stale.
// Returns false if there is no baseline or the user declined a stale one.
static bool LoadBaselineForComparison(AppState& app, HWND hWnd, const wchar_t* scanName)
{
    std::lock_guard<std::mutex> lock(app.baselineMutex);
    if (!app.currentBaseline.LoadFromFile(app.baselineFilePath)) {
        MessageBoxW(hWnd, L"No baseline found. Please run a Baseline Scan first on a known-clean system.",
            scanName, MB_OK | MB_ICONWARNING);
        return false;
    }
    DebugLog(std::wstring(scanName) + L": loaded baseline with " + std::to_wstring(app.currentBaseline.Count()) + L" entries");

    if (app.currentBaseline.IsOlderThan(30)) {
        std::wstringstream ageMsg;
        ageMsg << L"Warning: Baseline is " << app.currentBaseline.GetAgeDays()
               << L" days old (created " << app.currentBaseline.GetCreationTimeString() << L").\n\n"
               << L"A stale baseline may produce inaccurate results.\n"
               << L"Consider creating a fresh baseline on a verified clean system.\n\n"
               << L"Continue with the existing baseline?";
        if (MessageBoxW(hWnd, ageMsg.str().c_str(), L"Stale Baseline Warning", MB_YESNO | MB_ICONWARNING) != IDYES) {
            return false;
        }
    }

    app.currentBaseline.ResetSeenFlags();
    return true;
}

// ---------------------------------------------------------------------------
// Help and File menu
// ---------------------------------------------------------------------------
static void CmdAbout(AppState& app, HWND hWnd)
{
    DialogBoxW(app.hInstance, MAKEINTRESOURCEW(IDD_ABOUTBOX), hWnd, AboutDlgProc);
}

static void CmdExit(AppState&, HWND hWnd)
{
    DestroyWindow(hWnd);
}

static void CmdSettings(AppState& app, HWND hWnd)
{
    ShowSettingsDialog(hWnd, app.hInstance, app.worker);
}

static void CmdOpenScanResults(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"open old results")) return;

    std::wstring csvPath = BrowseForScanFile(hWnd);
    if (csvPath.empty()) return;

    std::vector<BaselineEntry> entries;
    std::vector<std::wstring> statuses;
    if (!ParseScanResultCSV(csvPath, entries, statuses)) {
        MessageBoxW(hWnd, L"Failed to parse scan results file.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    ClearResultRows(app.controls.resultsListView);
    for (size_t i = 0; i < entries.size(); i++) {
        AddResultRow(app.controls.resultsListView, entries[i], statuses[i]);
    }

    std::wstringstream ss;
    ss << L"Loaded " << entries.size() << L" results from:\n" << csvPath;
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());

    DebugLog(L"Loaded " + std::to_wstring(entries.size()) + L" scan results from CSV");
}

static void CmdOpenBaseline(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"change the active baseline")) return;

    std::wstring baselinePath = BrowseForBaselineFile(hWnd);
    if (baselinePath.empty()) return;

    Baseline loadedBaseline;
    if (!loadedBaseline.LoadFromFile(baselinePath)) {
        MessageBoxW(hWnd, L"Failed to load baseline file. It may be corrupted or an unsupported version.",
            L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(app.baselineMutex);
        app.currentBaseline = loadedBaseline;
    }

    std::wstringstream ss;
    ss << L"Baseline loaded: " << loadedBaseline.Count() << L" entries\n"
       << L"Created: " << loadedBaseline.GetCreationTimeString() << L"\n"
       << L"Age: " << loadedBaseline.GetAgeDays() << L" days\n"
       << L"Source: " << baselinePath;
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());

    if (loadedBaseline.IsOlderThan(30)) {
        MessageBoxW(hWnd,
            L"Warning: This baseline is more than 30 days old.\n"
            L"Consider creating a fresh baseline for accurate comparisons.",
            L"Baseline Age Warning", MB_OK | MB_ICONWARNING);
    }

    DebugLog(L"Baseline opened: " + baselinePath + L" (" + std::to_wstring(loadedBaseline.Count()) + L" entries)");
}

static void CmdImportBaseline(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"import a baseline")) return;

    std::wstring sourcePath = BrowseForBaselineFile(hWnd);
    if (sourcePath.empty()) return;

    Baseline importBaseline;
    if (!importBaseline.LoadFromFile(sourcePath)) {
        MessageBoxW(hWnd, L"Failed to load baseline file. It may be corrupted or an unsupported version.",
            L"Import Error", MB_OK | MB_ICONERROR);
        return;
    }

    if (GetFileAttributesW(app.baselineFilePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        int result = MessageBoxW(hWnd,
            L"A local baseline already exists. Importing will replace it.\n\nContinue?",
            L"Import Baseline", MB_YESNO | MB_ICONQUESTION);
        if (result != IDYES) return;
    }

    if (!CopyFileW(sourcePath.c_str(), app.baselineFilePath.c_str(), FALSE)) {
        MessageBoxW(hWnd, L"Failed to copy baseline file to local directory.",
            L"Import Error", MB_OK | MB_ICONERROR);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(app.baselineMutex);
        app.currentBaseline = importBaseline;
    }

    std::wstringstream ss;
    ss << L"Baseline imported: " << importBaseline.Count() << L" entries\n"
       << L"Created: " << importBaseline.GetCreationTimeString() << L"\n"
       << L"Source: " << sourcePath << L"\n"
       << L"Saved to: " << app.baselineFilePath;
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());

    MessageBoxW(hWnd,
        (L"Baseline imported successfully.\n\n"
         L"Entries: " + std::to_wstring(importBaseline.Count()) + L"\n"
         L"Created: " + importBaseline.GetCreationTimeString() + L"\n\n"
         L"This baseline is now active for Full Scan and Fast Scan comparisons.").c_str(),
        L"Import Successful", MB_OK | MB_ICONINFORMATION);

    DebugLog(L"Baseline imported from: " + sourcePath);
}

static void CmdExportBaseline(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"export the baseline")) return;

    std::lock_guard<std::mutex> lock(app.baselineMutex);
    if (app.currentBaseline.Count() == 0) {
        if (!app.currentBaseline.LoadFromFile(app.baselineFilePath)) {
            MessageBoxW(hWnd, L"No baseline is currently loaded.\n\n"
                L"Run a Baseline Scan first, or open/import an existing baseline.",
                L"No Baseline", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    std::wstring exportPath = SaveBaselineFileDialog(hWnd);
    if (exportPath.empty()) return;

    if (!app.currentBaseline.SaveToFile(exportPath)) {
        MessageBoxW(hWnd, L"Failed to export baseline file.", L"Export Error", MB_OK | MB_ICONERROR);
        return;
    }

    MessageBoxW(hWnd,
        (L"Baseline exported successfully.\n\n"
         L"Entries: " + std::to_wstring(app.currentBaseline.Count()) + L"\n"
         L"Saved to: " + exportPath).c_str(),
        L"Export Successful", MB_OK | MB_ICONINFORMATION);

    DebugLog(L"Baseline exported to: " + exportPath);
}

// ---------------------------------------------------------------------------
// Scans menu
// ---------------------------------------------------------------------------
static void CmdBaselineScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"start another scan")) return;

    MessageBoxW(hWnd,
        L"This will create a ground truth baseline of all executables on disk.\n\n"
        L"Only run this on a verified clean system!",
        L"Baseline Scan", MB_OK | MB_ICONINFORMATION);

    std::wstring directoryToScan = BrowseForScanDirectory(hWnd);
    if (directoryToScan.empty()) return;

    if (!PromptForOutputPath(app, hWnd)) return;

    StartScanInBackground(app, ScanMode::Baseline, directoryToScan);
}

static void CmdFullScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"start another scan")) return;
    if (!LoadBaselineForComparison(app, hWnd, L"Full Scan")) return;

    std::wstring directoryToScan = BrowseForScanDirectory(hWnd);
    if (directoryToScan.empty()) return;

    if (!PromptForOutputPath(app, hWnd)) return;

    StartScanInBackground(app, ScanMode::FullScan, directoryToScan);
}

static void CmdFastScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"start another scan")) return;
    if (!LoadBaselineForComparison(app, hWnd, L"Fast Scan")) return;

    if (!PromptForOutputPath(app, hWnd)) return;

    StartScanInBackground(app, ScanMode::FastScan, L"");
}

static void CmdCancelScan(AppState& app, HWND)
{
    if (!app.progress.running) return;
    app.progress.cancelRequested = true;
    {
        std::lock_guard<std::mutex> lock(app.progress.textMutex);
        app.progress.state = L"Cancelling...";
    }
    DebugLog(L"Cancel requested by user");
}

// ---------------------------------------------------------------------------
// AI sidebar buttons
// ---------------------------------------------------------------------------
static void CmdAiToggle(AppState& app, HWND)
{
    ToggleAiSidebar(app.aiSidebar);
}

static void CmdAiSend(AppState& app, HWND)
{
    wchar_t inputText[2048] = {};
    GetWindowTextW(app.aiSidebar.hInputField, inputText, 2048);
    SendUserMessage(app.aiSidebar, inputText);
}

static void CmdAiTriage(AppState& app, HWND)
{
    HWND hList = app.controls.resultsListView;
    if (!hList) return;

    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel < 0) {
        AppendToChatDisplay(app.aiSidebar, L"\r\n[Info]: Select a file in the results list first.\r\n");
        return;
    }

    // Columns as laid out by CreateResultsListView: 0 path, 2 score, 4 signature, 5 packing.
    wchar_t pathBuf[512] = {};
    ListView_GetItemText(hList, sel, 0, pathBuf, 512);
    wchar_t scoreBuf[32] = {};
    ListView_GetItemText(hList, sel, 2, scoreBuf, 32);
    wchar_t sigBuf[256] = {};
    ListView_GetItemText(hList, sel, 4, sigBuf, 256);
    wchar_t packBuf[256] = {};
    ListView_GetItemText(hList, sel, 5, packBuf, 256);

    BaselineEntry triageEntry;
    triageEntry.path = pathBuf;
    triageEntry.malwareScore = _wtof(scoreBuf);
    triageEntry.signature = sigBuf;
    triageEntry.packingStatus = packBuf;
    TriageSelectedFile(app.aiSidebar, triageEntry);
}

static void CmdAiSummary(AppState& app, HWND)
{
    RequestScanSummary(app.aiSidebar,
        app.progress.filesProcessed.load(),
        app.progress.executablesFound.load());
}

static void CmdAiAudit(AppState& app, HWND)
{
    // Read the panel text here, on the UI thread, before handing it to the worker.
    int len = GetWindowTextLengthW(app.controls.systemInfoLabel);
    std::wstring auditText(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(app.controls.systemInfoLabel, &auditText[0], len + 1);
    auditText.resize(static_cast<size_t>(len));

    RequestAuditAnalysis(app.aiSidebar, auditText);
}

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------
bool DispatchCommand(AppState& app, HWND hWnd, int commandId)
{
    typedef void (*CommandHandler)(AppState&, HWND);
    struct Entry { int id; CommandHandler handler; };

    static const Entry kTable[] = {
        { IDM_ABOUT,                CmdAbout },
        { IDM_EXIT,                 CmdExit },
        { ID_SETTINGS,              CmdSettings },
        { ID_FILE_OPEN_SCAN,        CmdOpenScanResults },
        { ID_FILE_OPEN_BASELINE,    CmdOpenBaseline },
        { ID_FILE_IMPORT_BASELINE,  CmdImportBaseline },
        { ID_FILE_EXPORT_BASELINE,  CmdExportBaseline },
        { ID_SCANS_BASELINE,        CmdBaselineScan },
        { ID_SCANS_FULLSCAN,        CmdFullScan },
        { ID_SCANS_FASTSCAN,        CmdFastScan },
        { ID_BUTTON_CANCEL,         CmdCancelScan },
        { ID_AI_TOGGLE,             CmdAiToggle },
        { ID_AI_SEND,               CmdAiSend },
        { ID_AI_TRIAGE,             CmdAiTriage },
        { ID_AI_SUMMARY,            CmdAiSummary },
        { ID_AI_AUDIT,              CmdAiAudit },
    };

    for (const Entry& entry : kTable) {
        if (entry.id == commandId) {
            entry.handler(app, hWnd);
            return true;
        }
    }
    return false;
}
