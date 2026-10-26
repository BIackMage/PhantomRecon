// PhantomRecon.cpp : entry point, main window class, message dispatcher and handlers.
//
// Rules (see CLAUDE.md): MainWndProc dispatches only. Commands live in MainCommands.cpp.
// Scanning lives in ScanEngine.cpp. Nothing here runs on a background thread except the
// body of RunSecurityAuditInBackground, which posts its result back.

#include "pch.h"
#include "PhantomRecon.h"

#include "DarkMode.h"
#include "GuiComponents.h"
#include "MainCommands.h"
#include "ScanEngine.h"
#include "ScoringConfig.h"
#include "SecurityChecks.h"
#include "SettingsDialog.h"
#include "SystemInfo.h"

#include <commctrl.h>
#include <memory>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[PhantomRecon] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// wWinMain
// ---------------------------------------------------------------------------
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE hPrevInstance,
                      _In_ LPWSTR    lpCmdLine,
                      _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // The one and only AppState. Everything else gets a pointer or reference to it.
    AppState app;
    app.hInstance = hInstance;

    // Dark mode brushes must exist before any window is created.
    InitDarkMode();

    // Scoring config: load it, or write the default template on first run.
    ScoringConfig& scoringCfg = GetScoringConfig();
    if (!scoringCfg.LoadFromFile(L"phantom_recon_scoring.ini")) {
        scoringCfg.SaveToFile(L"phantom_recon_scoring.ini");
        DebugLog(L"Generated default scoring config template");
    }

    // App settings (LLM endpoint etc.) into the LLM client.
    AppSettings appSettings = LoadAppSettings();
    ApplySettingsToLLMClient(appSettings);

    LoadStringW(hInstance, IDS_APP_TITLE, app.title, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_PHANTOMRECON, app.windowClass, MAX_LOADSTRING);
    RegisterMainWindowClass(app);
    RegisterAiSidebarClass(hInstance);

    if (!CreateMainWindow(app, nCmdShow)) {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(IDC_PHANTOMRECON));

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!TranslateAcceleratorW(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // Shutdown: stop any scan and wait for every worker before AppState goes away.
    app.progress.cancelRequested = true;
    app.worker.JoinAll();
    DebugLog(L"Exit");

    return static_cast<int>(msg.wParam);
}

// ---------------------------------------------------------------------------
// Window class and creation
// ---------------------------------------------------------------------------
ATOM RegisterMainWindowClass(AppState& app)
{
    WNDCLASSEXW wcex = {};
    wcex.cbSize        = sizeof(WNDCLASSEXW);
    wcex.style         = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc   = MainWndProc;
    wcex.cbClsExtra    = 0;
    wcex.cbWndExtra    = 0;
    wcex.hInstance     = app.hInstance;
    wcex.hIcon         = LoadIconW(app.hInstance, MAKEINTRESOURCEW(IDI_PHANTOMRECON));
    wcex.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName  = MAKEINTRESOURCEW(IDC_PHANTOMRECON);
    wcex.lpszClassName = app.windowClass;
    wcex.hIconSm       = LoadIconW(app.hInstance, MAKEINTRESOURCEW(IDI_SMALL));
    return RegisterClassExW(&wcex);
}

BOOL CreateMainWindow(AppState& app, int nCmdShow)
{
    InitGuiCommonControls();

    // &app travels in lpCreateParams and lands in GWLP_USERDATA at WM_NCCREATE.
    HWND hWnd = CreateWindowW(app.windowClass, app.title, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 1000, 720, nullptr, nullptr, app.hInstance, &app);
    if (!hWnd) {
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Control creation
// ---------------------------------------------------------------------------
void CreateMainControls(AppState& app, HWND hWnd)
{
    const int columnWidth  = 360;
    const int columnHeight = 280;
    const int columnMargin = 20;
    const int leftColumnX  = 20;
    const int rightColumnX = leftColumnX + columnWidth + columnMargin;
    const int titleHeight  = 20;
    const int buffer       = 10;

    MainControls& c = app.controls;

    c.systemInfoTitle = CreateWindowW(L"STATIC", L"System Information",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        leftColumnX, 10, columnWidth, titleHeight,
        hWnd, NULL, app.hInstance, NULL);

    c.operationInfoTitle = CreateWindowW(L"STATIC", L"Current Operation Information",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        rightColumnX, 10, columnWidth, titleHeight,
        hWnd, NULL, app.hInstance, NULL);

    c.systemInfoLabel = CreateWindowW(L"STATIC", L"CPU: \nRAM: \nDisk Space: ",
        WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
        leftColumnX + buffer, 40 + titleHeight + buffer,
        columnWidth - 2 * buffer, columnHeight - titleHeight - 2 * buffer,
        hWnd, NULL, app.hInstance, NULL);

    c.operationInfoLabel = CreateWindowW(L"STATIC", L"Scan Progress: \nFiles Processed: \nExecutable Files: ",
        WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
        rightColumnX + buffer, 40 + titleHeight + buffer,
        columnWidth - 2 * buffer, columnHeight - titleHeight - 2 * buffer,
        hWnd, NULL, app.hInstance, NULL);

    const int progressY = 40 + columnHeight + 10;
    const int progressBarWidth = rightColumnX + columnWidth - leftColumnX - 170;  // room for Cancel
    c.progressBar = CreateScanProgressBar(hWnd, app.hInstance, leftColumnX, progressY, progressBarWidth, 22);

    c.cancelButton = CreateWindowW(L"BUTTON", L"Cancel Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        leftColumnX + progressBarWidth + 10, progressY - 2, 150, 26,
        hWnd, (HMENU)ID_BUTTON_CANCEL, app.hInstance, NULL);

    const int listViewY = progressY + 30;
    const int listViewHeight = 300;
    c.resultsListView = CreateResultsListView(hWnd, app.hInstance, leftColumnX, listViewY,
        rightColumnX + columnWidth - leftColumnX, listViewHeight);

    ApplyDarkModeToListView(c.resultsListView);
    ApplyDarkModeToProgressBar(c.progressBar);
}

// The .rc file defines Exit, the Scans menu and About. The rest of File is built here.
static void AddRuntimeMenuItems(HWND hWnd)
{
    HMENU hMenuBar = GetMenu(hWnd);
    if (!hMenuBar) return;

    HMENU hFileMenu = GetSubMenu(hMenuBar, 0);
    if (hFileMenu) {
        InsertMenuW(hFileMenu, 0, MF_BYPOSITION | MF_STRING, ID_FILE_OPEN_SCAN, L"Open Scan Results...");
        InsertMenuW(hFileMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        InsertMenuW(hFileMenu, 2, MF_BYPOSITION | MF_STRING, ID_FILE_OPEN_BASELINE, L"Open Baseline...");
        InsertMenuW(hFileMenu, 3, MF_BYPOSITION | MF_STRING, ID_FILE_IMPORT_BASELINE, L"Import Baseline (Set as Active)...");
        InsertMenuW(hFileMenu, 4, MF_BYPOSITION | MF_STRING, ID_FILE_EXPORT_BASELINE, L"Export Current Baseline...");
        InsertMenuW(hFileMenu, 5, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        InsertMenuW(hFileMenu, 6, MF_BYPOSITION | MF_STRING, ID_SETTINGS, L"Settings...");
        InsertMenuW(hFileMenu, 7, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
    }
    DrawMenuBar(hWnd);
}

// ---------------------------------------------------------------------------
// Background audit
// ---------------------------------------------------------------------------
void RunSecurityAuditInBackground(AppState& app)
{
    HWND hMain = app.hMainWindow;
    app.worker.Run([hMain]() {
        std::vector<SecurityCheckResult> results = RunAllSecurityChecks();
        WriteSecurityReport(L"security_audit_report.txt", results);

        std::wstring text = BuildSystemInfoText() + L"\n" + GetSecuritySummary(results);
        PostPayload(hMain, WM_APP_AUDIT_FINISHED, new std::wstring(text));
    });
}

// ---------------------------------------------------------------------------
// Label refresh
// ---------------------------------------------------------------------------
void RefreshOperationLabel(AppState& app)
{
    std::wstring state;
    std::wstring filePath;
    {
        std::lock_guard<std::mutex> lock(app.progress.textMutex);
        state = app.progress.state;
        filePath = app.progress.currentFilePath;
    }

    std::wstringstream ss;
    ss << L"Current Scan State: " << state << L"\n"
       << L"Files Processed: " << app.progress.filesProcessed.load() << L"\n"
       << L"Executable Files: " << app.progress.executablesFound.load() << L"\n"
       << L"Current File: " << filePath << L"\n";
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());
}

// ---------------------------------------------------------------------------
// Message handlers (UI thread)
// ---------------------------------------------------------------------------
static LRESULT OnGetMinMaxInfo(LPARAM lParam)
{
    MINMAXINFO* mmInfo = reinterpret_cast<MINMAXINFO*>(lParam);
    mmInfo->ptMinTrackSize.x = 800;   // main content only; the AI panel is a separate window
    mmInfo->ptMinTrackSize.y = 650;
    return 0;
}

static void OnCreate(AppState& app, HWND hWnd)
{
    CreateMainControls(app, hWnd);
    SetWindowTextW(app.controls.systemInfoLabel, BuildSystemInfoText().c_str());
    RunSecurityAuditInBackground(app);
    CreateAiSidebar(hWnd, app.hInstance, app.aiSidebar, app.worker);
    AddRuntimeMenuItems(hWnd);
}

static void OnPaint(HWND hWnd)
{
    PAINTSTRUCT ps;
    BeginPaint(hWnd, &ps);
    EndPaint(hWnd, &ps);
}

static LRESULT OnNotify(AppState& app, HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
    if (pnmh->hwndFrom == app.controls.resultsListView && pnmh->code == NM_CUSTOMDRAW) {
        return HandleDarkResultsCustomDraw(lParam);
    }
    return DefWindowProcW(hWnd, message, wParam, lParam);
}

// Drain the row queue into the list view. Clear the in-flight flag first so a row
// queued during the drain triggers a fresh post instead of waiting forever.
static void OnScanRows(AppState& app)
{
    app.progress.rowsPosted = false;

    std::vector<ScanRow> rows;
    {
        std::lock_guard<std::mutex> lock(app.progress.rowsMutex);
        rows.swap(app.progress.pendingRows);
    }

    for (const ScanRow& row : rows) {
        AddResultRow(app.controls.resultsListView, row.entry, row.status);
    }
    SetProgressPosition(app.controls.progressBar, app.progress.executablesFound.load());
}

static void OnScanProgress(AppState& app)
{
    app.progress.progressPosted = false;
    RefreshOperationLabel(app);
}

static void OnScanFinished(AppState& app, HWND hWnd, ScanFinishedPayload* rawPayload)
{
    std::unique_ptr<ScanFinishedPayload> payload(rawPayload);

    OnScanRows(app);                                 // catch any rows still queued
    SetProgressMarquee(app.controls.progressBar, false);
    RefreshOperationLabel(app);
    app.progress.running = false;

    if (payload) {
        DebugLog(L"Scan finished: " + payload->finalState);
        if (payload->showDialog) {
            MessageBoxW(hWnd, payload->dialogText.c_str(), payload->dialogTitle.c_str(),
                MB_OK | payload->dialogIcon);
        }
    }
}

static void OnAuditFinished(AppState& app, std::wstring* rawText)
{
    std::unique_ptr<std::wstring> text(rawText);
    if (text) {
        SetWindowTextW(app.controls.systemInfoLabel, text->c_str());
    }
}

static void OnClose(AppState& app, HWND hWnd)
{
    // Ask any running scan to stop now. wWinMain joins the workers after the loop ends.
    app.progress.cancelRequested = true;
    DestroyWindow(hWnd);
}

// ---------------------------------------------------------------------------
// MainWndProc: dispatch only
// ---------------------------------------------------------------------------
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    // Messages that need no state, or arrive before the state pointer is stored.
    switch (message) {
    case WM_GETMINMAXINFO:
        return OnGetMinMaxInfo(lParam);

    case WM_NCCREATE: {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        AppState* created = reinterpret_cast<AppState*>(cs->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(created));
        if (created) created->hMainWindow = hWnd;
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    default:
        break;
    }

    AppState* appPtr = GetAppState(hWnd);
    if (!appPtr) {
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    AppState& app = *appPtr;

    switch (message) {
    case WM_CREATE:
        OnCreate(app, hWnd);
        return 0;

    case WM_MOVE:
    case WM_SIZE:
        RepositionAiSidebar(app.aiSidebar);
        return 0;

    case WM_COMMAND:
        if (DispatchCommand(app, hWnd, LOWORD(wParam))) return 0;
        return DefWindowProcW(hWnd, message, wParam, lParam);

    case WM_PAINT:
        OnPaint(hWnd);
        return 0;

    case WM_ERASEBKGND:
        return HandleDarkEraseBkgnd(reinterpret_cast<HDC>(wParam), hWnd);

    case WM_CTLCOLORSTATIC:
        return reinterpret_cast<LRESULT>(HandleDarkCtlColorStatic(reinterpret_cast<HDC>(wParam)));

    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(HandleDarkCtlColorEdit(reinterpret_cast<HDC>(wParam)));

    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(HandleDarkCtlColorBtn(reinterpret_cast<HDC>(wParam)));

    case WM_NOTIFY:
        return OnNotify(app, hWnd, message, wParam, lParam);

    case WM_APP_SCAN_ROWS:
        OnScanRows(app);
        return 0;

    case WM_APP_SCAN_PROGRESS:
        OnScanProgress(app);
        return 0;

    case WM_APP_SCAN_FINISHED:
        OnScanFinished(app, hWnd, reinterpret_cast<ScanFinishedPayload*>(lParam));
        return 0;

    case WM_APP_AUDIT_FINISHED:
        OnAuditFinished(app, reinterpret_cast<std::wstring*>(lParam));
        return 0;

    case WM_CLOSE:
        OnClose(app, hWnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
}

// ---------------------------------------------------------------------------
// About box
// ---------------------------------------------------------------------------
INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
