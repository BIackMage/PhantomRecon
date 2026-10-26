// PhantomRecon.cpp : entry point, main window class, message dispatcher and handlers.
//
// Rules (see CLAUDE.md): MainWndProc dispatches only. Commands live in the
// *Commands.cpp files, controls in MainLayout.cpp, scanning in ScanEngine.cpp,
// the audit in AuditController.cpp. Nothing here runs on a background thread.

#include "pch.h"
#include "PhantomRecon.h"

#include "AppDialogs.h"
#include "AppPaths.h"
#include "AuditController.h"
#include "CommandHelpers.h"
#include "GuiComponents.h"
#include "MainCommands.h"
#include "MainLayout.h"
#include "ScoringConfig.h"
#include "SettingsDialog.h"
#include "StartupArgs.h"
#include "Theme.h"

#include <commctrl.h>
#include <shellapi.h>
#include <objbase.h>
#include <memory>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")

// Common Controls 6: themed controls, cue banners, sort arrows in the list header.
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

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
static void LoadScoringConfigOrTemplate()
{
    std::wstring path = AppFilePath(L"phantom_recon_scoring.ini");
    ScoringConfig& cfg = GetScoringConfig();
    if (!cfg.LoadFromFile(path)) {
        if (cfg.SaveToFile(path)) DebugLog(L"Wrote the default scoring config template to " + path);
    }
}

// Keyboard routing: modeless windows get Tab and Esc; the main window gets accelerators.
static bool PreTranslate(AppState& app, HACCEL accel, MSG& msg)
{
    if (app.findingsWindow && IsDialogMessageW(app.findingsWindow, &msg)) return true;
    if (app.detailWindow && IsDialogMessageW(app.detailWindow, &msg)) return true;
    if (app.hMainWindow && (msg.hwnd == app.hMainWindow || IsChild(app.hMainWindow, msg.hwnd))) {
        if (TranslateAcceleratorW(app.hMainWindow, accel, &msg)) return true;
    }
    return false;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // The file dialogs use COM on this thread.
    HRESULT comInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    // The one and only AppState. Everything else gets a pointer or reference to it.
    AppState app;
    app.hInstance = hInstance;
    app.settings = LoadAppSettings();
    app.baselineFilePath = EffectiveBaselinePath(app.settings);
    ApplySettingsToLLMClient(app.settings);
    LoadScoringConfigOrTemplate();

    // Theme brushes must exist before any window is created.
    InitTheme(static_cast<ThemeMode>(app.settings.theme));

    LoadStringW(hInstance, IDS_APP_TITLE, app.title, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_PHANTOMRECON, app.windowClass, MAX_LOADSTRING);
    InitGuiCommonControls();
    RegisterMainWindowClass(app);
    RegisterAiSidebarClass(hInstance);

    if (!CreateMainWindow(app, nCmdShow)) {
        if (SUCCEEDED(comInit)) CoUninitialize();
        return FALSE;
    }

    HACCEL accel = LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(IDC_PHANTOMRECON));
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (PreTranslate(app, accel, msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Shutdown: stop any scan or audit and wait for every worker before AppState goes away.
    app.progress.cancelRequested = true;
    app.audit.cancelRequested = true;
    app.worker.JoinAll();
    if (SUCCEEDED(comInit)) CoUninitialize();
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
    wcex.hInstance     = app.hInstance;
    wcex.hIcon         = LoadIconW(app.hInstance, MAKEINTRESOURCEW(IDI_PHANTOMRECON));
    wcex.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wcex.hbrBackground = NULL;   // WM_ERASEBKGND paints the theme colour
    wcex.lpszMenuName  = MAKEINTRESOURCEW(IDC_PHANTOMRECON);
    wcex.lpszClassName = app.windowClass;
    wcex.hIconSm       = LoadIconW(app.hInstance, MAKEINTRESOURCEW(IDI_SMALL));
    return RegisterClassExW(&wcex);
}

BOOL CreateMainWindow(AppState& app, int nCmdShow)
{
    // &app travels in lpCreateParams and lands in GWLP_USERDATA at WM_NCCREATE.
    HWND hWnd = CreateWindowExW(WS_EX_CONTROLPARENT, app.windowClass, app.title, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, 0, 1240, 820, nullptr, nullptr, app.hInstance, &app);
    if (!hWnd) return FALSE;
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    PostMessageW(hWnd, WM_APP_STARTUP, 0, 0);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Message handlers (UI thread)
// ---------------------------------------------------------------------------
static LRESULT OnGetMinMaxInfo(LPARAM lParam)
{
    MINMAXINFO* mmInfo = reinterpret_cast<MINMAXINFO*>(lParam);
    mmInfo->ptMinTrackSize.x = 900;   // main content only; the AI panel is a separate window
    mmInfo->ptMinTrackSize.y = 640;
    return 0;
}

static void OnCreate(AppState& app, HWND hWnd)
{
    CreateMainControls(app, hWnd);
    CreateAiSidebar(hWnd, app.hInstance, app.aiSidebar, app.worker);
    if (app.aiSidebar.hPanel) {
        EnumChildWindows(app.aiSidebar.hPanel, [](HWND child, LPARAM font) -> BOOL {
            SendMessageW(child, WM_SETFONT, static_cast<WPARAM>(font), TRUE);
            return TRUE;
        }, reinterpret_cast<LPARAM>(app.ui.uiFont));
    }
    SetControlFont(app.aiSidebar.hToggleTab, app.ui.uiFont);
    ApplyThemeToMainWindow(app);
    ApplyThemeToAiSidebar(app.aiSidebar);
    RefreshOperationLabel(app);
    UpdateScoreDisplay(app);
    if (IsPortableMode()) {
        std::wstring title = std::wstring(app.title) + L" (portable)";
        SetWindowTextW(hWnd, title.c_str());
    }
    if (app.settings.auditOnStartup) StartAuditInBackground(app);
}

static void OnStartup(AppState& app, HWND hWnd)
{
    DragAcceptFiles(hWnd, TRUE);
    if (HandleStartupArguments(app, hWnd)) return;   // asked for a file or the samples: skip the welcome
    if (!app.settings.showGettingStarted) return;
    GettingStartedResult r = ShowGettingStarted(hWnd, app.hInstance, app.settings.showGettingStarted);
    if (r.showAtStartup != app.settings.showGettingStarted) {
        app.settings.showGettingStarted = r.showAtStartup;
        SaveAppSettings(app.settings);
    }
    if (r.createSamples) CreateSamplePackAndScan(app, hWnd);
}

static void OnSize(AppState& app)
{
    LayoutMainControls(app);
    RepositionAiSidebar(app.aiSidebar);
}

static void OnPaint(HWND hWnd)
{
    PAINTSTRUCT ps;
    BeginPaint(hWnd, &ps);
    EndPaint(hWnd, &ps);
}

static void ShowResultsContextMenu(AppState& app, HWND hWnd, POINT screenPoint)
{
    if (!SelectedRow(app)) return;
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    AppendMenuW(menu, MF_STRING, ID_RESULTS_DETAILS, L"Show &Details");
    AppendMenuW(menu, MF_STRING, ID_RESULTS_COPY_PATH, L"Copy Full &Path");
    AppendMenuW(menu, MF_STRING, ID_RESULTS_COPY_SHA, L"Copy &SHA-256");
    AppendMenuW(menu, MF_STRING, ID_RESULTS_OPEN_LOCATION, L"Open File &Location");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, ID_RESULTS_TRIAGE, L"Ask the AI &About This File");
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc;
        GetWindowRect(app.controls.resultsListView, &rc);
        screenPoint.x = rc.left + 40;
        screenPoint.y = rc.top + 40;
    }
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hWnd, NULL);
    DestroyMenu(menu);
}

static LRESULT OnResultsNotify(AppState& app, HWND hWnd, LPARAM lParam)
{
    NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
    switch (hdr->code) {
    case LVN_GETDISPINFOW:
        FillResultsDispInfo(lParam, app.results);
        return 0;
    case NM_CUSTOMDRAW:
        return ThemeResultsCustomDraw(lParam, app.results);
    case LVN_COLUMNCLICK: {
        NMLISTVIEW* lv = reinterpret_cast<NMLISTVIEW*>(lParam);
        app.results.SortBy(static_cast<ResultColumn>(lv->iSubItem));
        ListView_SetItemState(app.controls.resultsListView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        UpdateSortArrow(app.controls.resultsListView, app.results);
        RefreshResultsList(app.controls.resultsListView, app.results);
        return 0;
    }
    case NM_DBLCLK:
    case NM_RETURN:
        DispatchCommand(app, hWnd, ID_RESULTS_DETAILS, 0);
        return 0;
    case NM_RCLICK: {
        POINT pt;
        GetCursorPos(&pt);
        ShowResultsContextMenu(app, hWnd, pt);
        return 0;
    }
    case LVN_KEYDOWN: {
        NMLVKEYDOWN* key = reinterpret_cast<NMLVKEYDOWN*>(lParam);
        if (key->wVKey == 'C' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            DispatchCommand(app, hWnd, ID_RESULTS_COPY_PATH, 0);
        }
        else if (key->wVKey == VK_APPS || (key->wVKey == VK_F10 && (GetKeyState(VK_SHIFT) & 0x8000))) {
            ShowResultsContextMenu(app, hWnd, POINT{ -1, -1 });
        }
        return 0;
    }
    default:
        return 0;
    }
}

static LRESULT OnNotify(AppState& app, HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
    if (hdr->hwndFrom == app.controls.resultsListView) return OnResultsNotify(app, hWnd, lParam);
    return DefWindowProcW(hWnd, message, wParam, lParam);
}

// Drain the row queue into the model. Clear the in-flight flag first so a row
// queued during the drain triggers a fresh post instead of waiting forever.
static void OnScanRows(AppState& app)
{
    app.progress.rowsPosted = false;
    std::vector<ScanRow> rows;
    {
        std::lock_guard<std::mutex> lock(app.progress.rowsMutex);
        rows.swap(app.progress.pendingRows);
    }
    if (rows.empty()) return;
    app.results.Append(rows);
    RefreshResultsList(app.controls.resultsListView, app.results);
    UpdateResultCount(app);
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
    app.progress.running = false;
    SetProgressMarquee(app.controls.progressBar, false);
    EnableWindow(app.controls.cancelButton, FALSE);
    if (!payload) return;

    const ScanSummary& s = payload->summary;
    app.lastScan.has = true;
    app.lastScan.summary = s;
    app.lastScan.title = payload->title;
    SetProgressRange(app.controls.progressBar, 100);
    SetProgressPosition(app.controls.progressBar, s.cancelled ? 0 : 100);

    std::wstringstream ss;
    ss << payload->finalState << L"\n" << payload->title << L"\n\n";
    ss << L"Programs and scripts analysed: " << s.executables << L" of " << s.filesProcessed << L" files, in "
       << static_cast<int>(s.seconds + 0.5) << L" s\n";
    if (s.mode != ScanMode::Baseline) {
        ss << L"New " << s.added << L", changed " << s.changed << L", missing " << s.missing << L", unchanged " << s.match
           << L"\nUpdated by Microsoft " << s.updated << L", on your known-good list " << s.known << L"\n";
    }
    if (s.highRisk > 0) ss << s.highRisk << L" file(s) scored 7 or more. Filter \"Score 7 or more\" to see them.\n";
    if (!s.csvPath.empty() && !s.csvFailed) ss << L"CSV: " << s.csvPath << L"\n";
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());
    DebugLog(L"Scan finished: " + payload->finalState);

    if (payload->showDialog) {
        MessageBoxW(hWnd, payload->dialogText.c_str(), payload->dialogTitle.c_str(), MB_OK | payload->dialogIcon);
    }
}

static void OnSettingChange(AppState& app, LPARAM lParam)
{
    const wchar_t* area = reinterpret_cast<const wchar_t*>(lParam);
    if (!area || wcscmp(area, L"ImmersiveColorSet") != 0) return;
    if (!RefreshThemeFromSystem()) return;
    DebugLog(L"Windows theme changed; repainting");
    ApplyThemeToMainWindow(app);
    ApplyThemeToAiSidebar(app.aiSidebar);
    if (app.findingsWindow) ApplyThemeToWindowTree(app.findingsWindow);
    if (app.detailWindow) ApplyThemeToWindowTree(app.detailWindow);
}

static LRESULT OnCtlColorStatic(AppState& app, HDC hdc, HWND control)
{
    if (control == app.controls.systemInfoLabel) return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(hdc));
    HBRUSH brush = ThemeCtlColorStatic(hdc);
    if (control == app.controls.scoreValue) SetTextColor(hdc, ScoreColor(app));
    else if (control == app.controls.scoreCaption || control == app.controls.countLabel) SetTextColor(hdc, ThemeColors().TextSecondary);
    return reinterpret_cast<LRESULT>(brush);
}

static void OnClose(AppState& app, HWND hWnd)
{
    // Ask any running scan or audit to stop now. wWinMain joins the workers after the loop ends.
    app.progress.cancelRequested = true;
    app.audit.cancelRequested = true;
    DestroyWindow(hWnd);
}

static void OnDestroy(AppState& app)
{
    if (app.findingsWindow) DestroyWindow(app.findingsWindow);
    if (app.detailWindow) DestroyWindow(app.detailWindow);
    for (HFONT* font : { &app.ui.uiFont, &app.ui.titleFont, &app.ui.scoreFont }) {
        if (*font) DeleteObject(*font);
        *font = NULL;
    }
    PostQuitMessage(0);
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
    if (!appPtr) return DefWindowProcW(hWnd, message, wParam, lParam);
    AppState& app = *appPtr;

    switch (message) {
    case WM_CREATE:
        OnCreate(app, hWnd);
        return 0;
    case WM_APP_STARTUP:
        OnStartup(app, hWnd);
        return 0;
    case WM_SIZE:
        OnSize(app);
        return 0;
    case WM_MOVE:
        RepositionAiSidebar(app.aiSidebar);
        return 0;
    case WM_COMMAND:
        if (DispatchCommand(app, hWnd, LOWORD(wParam), HIWORD(wParam))) return 0;
        return DefWindowProcW(hWnd, message, wParam, lParam);
    case WM_INITMENUPOPUP:
        UpdateMenuState(app, reinterpret_cast<HMENU>(wParam));
        return 0;
    case WM_PAINT:
        OnPaint(hWnd);
        return 0;
    case WM_ERASEBKGND:
        return ThemeEraseBackground(reinterpret_cast<HDC>(wParam), hWnd);
    case WM_CTLCOLORSTATIC:
        return OnCtlColorStatic(app, reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam));
    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORLISTBOX:
        return reinterpret_cast<LRESULT>(ThemeCtlColorListBox(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(ThemeCtlColorButton(reinterpret_cast<HDC>(wParam)));
    case WM_NOTIFY:
        return OnNotify(app, hWnd, message, wParam, lParam);
    case WM_SETTINGCHANGE:
        OnSettingChange(app, lParam);
        return DefWindowProcW(hWnd, message, wParam, lParam);
    case WM_DROPFILES:
        OnDropFiles(app, hWnd, reinterpret_cast<HDROP>(wParam));
        return 0;
    case WM_APP_SCAN_ROWS:
        OnScanRows(app);
        return 0;
    case WM_APP_SCAN_PROGRESS:
        OnScanProgress(app);
        return 0;
    case WM_APP_SCAN_FINISHED:
        OnScanFinished(app, hWnd, reinterpret_cast<ScanFinishedPayload*>(lParam));
        return 0;
    case WM_APP_AUDIT_PROGRESS:
        OnAuditProgressMessage(app);
        return 0;
    case WM_APP_AUDIT_FINISHED:
        OnAuditFinishedMessage(app, reinterpret_cast<AuditFinishedPayload*>(lParam));
        return 0;
    case WM_CLOSE:
        OnClose(app, hWnd);
        return 0;
    case WM_DESTROY:
        OnDestroy(app);
        return 0;
    default:
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
}
