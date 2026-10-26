#include "pch.h"
#include "MainLayout.h"

#include "AppPaths.h"
#include "DetailText.h"
#include "GuiComponents.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "Theme.h"
#include "resource.h"

#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[MainLayout] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

static const int kMargin = 12;
static const int kTabRoom = 36;      // the AI toggle tab on the right edge
static const int kPanelHeight = 230;
static const int kTitleHeight = 22;

static HWND MakeChild(AppState& app, HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int id,
                      DWORD exStyle = 0)
{
    HWND hwnd = CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), app.hInstance, NULL);
    SetControlFont(hwnd, app.ui.uiFont);
    return hwnd;
}

void CreateMainControls(AppState& app, HWND hWnd)
{
    app.ui.uiFont = CreateUiFont(hWnd, 0, false);
    app.ui.titleFont = CreateUiFont(hWnd, 1, true);
    app.ui.scoreFont = CreateUiFont(hWnd, 26, true);

    MainControls& c = app.controls;
    c.systemInfoTitle = MakeChild(app, hWnd, L"STATIC", L"This PC", SS_LEFT, -1);
    c.systemInfoLabel = MakeChild(app, hWnd, L"EDIT", ToWindowsLineEnds(BuildSystemInfoText() + L"\nSecurity audit: not run yet. Press F5 to run it.").c_str(),
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, -1, WS_EX_CLIENTEDGE);
    c.operationInfoTitle = MakeChild(app, hWnd, L"STATIC", L"Current operation", SS_LEFT, -1);
    c.operationInfoLabel = MakeChild(app, hWnd, L"STATIC",
        L"No scan yet.\n\nScans > Take Baseline records what is on the PC now.\nFull Scan and Fast Scan show what changed since.",
        SS_LEFT | SS_NOPREFIX | WS_BORDER, -1);
    c.scoreTitle = MakeChild(app, hWnd, L"STATIC", L"Hardening score", SS_CENTER, -1);
    c.scoreValue = MakeChild(app, hWnd, L"STATIC", L"--", SS_CENTER | SS_CENTERIMAGE, -1);
    c.scoreCaption = MakeChild(app, hWnd, L"STATIC", L"Audit not run yet", SS_CENTER | SS_NOPREFIX, -1);
    c.findingsButton = MakeChild(app, hWnd, L"BUTTON", L"Findings and Fixes (F6)", WS_TABSTOP | BS_PUSHBUTTON, ID_FINDINGS_BUTTON);

    c.progressBar = CreateScanProgressBar(hWnd, app.hInstance, 0, 0, 10, 10);
    c.cancelButton = MakeChild(app, hWnd, L"BUTTON", L"Cancel Scan", WS_TABSTOP | BS_PUSHBUTTON, ID_BUTTON_CANCEL);
    EnableWindow(c.cancelButton, FALSE);

    c.filterLabel = MakeChild(app, hWnd, L"STATIC", L"Show:", SS_LEFT | SS_CENTERIMAGE, -1);
    c.filterCombo = MakeChild(app, hWnd, L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, ID_FILTER_COMBO);
    FillFilterCombo(c.filterCombo);
    c.searchLabel = MakeChild(app, hWnd, L"STATIC", L"Search:", SS_LEFT | SS_CENTERIMAGE, -1);
    c.searchEdit = MakeChild(app, hWnd, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, ID_SEARCH_EDIT, WS_EX_CLIENTEDGE);
    SendMessageW(c.searchEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"name, path, signer or SHA-256"));
    c.countLabel = MakeChild(app, hWnd, L"STATIC", L"", SS_RIGHT | SS_CENTERIMAGE, -1);

    c.resultsListView = CreateResultsListView(hWnd, app.hInstance, 0, 0, 10, 10);
    SetControlFont(c.resultsListView, app.ui.uiFont);

    SetControlFont(c.systemInfoTitle, app.ui.titleFont);
    SetControlFont(c.operationInfoTitle, app.ui.titleFont);
    SetControlFont(c.scoreTitle, app.ui.titleFont);
    SetControlFont(c.scoreValue, app.ui.scoreFont);

    LayoutMainControls(app);
    UpdateResultCount(app);
    DebugLog(L"Main controls created");
}

void LayoutMainControls(AppState& app)
{
    HWND hWnd = app.hMainWindow;
    if (!hWnd || !app.controls.resultsListView) return;
    MainControls& c = app.controls;

    RECT rc;
    GetClientRect(hWnd, &rc);
    const int width = rc.right - rc.left;
    const int height = rc.bottom - rc.top;
    const int contentRight = width - kTabRoom;
    const int contentWidth = contentRight - kMargin;
    if (contentWidth < 200) return;

    // Three panels across the top.
    const int gap = 12;
    const int scoreW = 200;
    const int panelW = (contentWidth - scoreW - 2 * gap) / 2;
    const int top = kMargin;
    const int bodyTop = top + kTitleHeight + 4;
    const int bodyH = kPanelHeight - kTitleHeight - 4;

    int x = kMargin;
    MoveWindow(c.systemInfoTitle, x, top, panelW, kTitleHeight, TRUE);
    MoveWindow(c.systemInfoLabel, x, bodyTop, panelW, bodyH, TRUE);
    x += panelW + gap;
    MoveWindow(c.operationInfoTitle, x, top, panelW, kTitleHeight, TRUE);
    MoveWindow(c.operationInfoLabel, x, bodyTop, panelW, bodyH, TRUE);
    x += panelW + gap;
    MoveWindow(c.scoreTitle, x, top, scoreW, kTitleHeight, TRUE);
    MoveWindow(c.scoreValue, x, bodyTop, scoreW, 90, TRUE);
    MoveWindow(c.scoreCaption, x, bodyTop + 94, scoreW, 64, TRUE);
    MoveWindow(c.findingsButton, x + 10, bodyTop + bodyH - 32, scoreW - 20, 30, TRUE);

    // Progress row.
    int y = top + kPanelHeight + 10;
    const int cancelW = 120;
    MoveWindow(c.progressBar, kMargin, y + 3, contentWidth - cancelW - 10, 20, TRUE);
    MoveWindow(c.cancelButton, contentRight - cancelW, y, cancelW, 26, TRUE);

    // Filter row.
    y += 36;
    int fx = kMargin;
    MoveWindow(c.filterLabel, fx, y, 44, 24, TRUE);
    fx += 48;
    MoveWindow(c.filterCombo, fx, y, 330, 300, TRUE);
    fx += 330 + 16;
    MoveWindow(c.searchLabel, fx, y, 54, 24, TRUE);
    fx += 58;
    const int countW = 170;
    int searchW = contentRight - countW - 10 - fx;
    if (searchW < 120) searchW = 120;
    MoveWindow(c.searchEdit, fx, y, searchW, 24, TRUE);
    MoveWindow(c.countLabel, contentRight - countW, y, countW, 24, TRUE);

    // List fills the rest.
    y += 34;
    int listH = height - y - kMargin;
    if (listH < 80) listH = 80;
    MoveWindow(c.resultsListView, kMargin, y, contentWidth, listH, TRUE);
}

void ApplyThemeToMainWindow(AppState& app)
{
    ApplyThemeToWindowTree(app.hMainWindow);
    DebugLog(ThemeColors().dark ? L"Main window themed dark" : L"Main window themed light");
}

COLORREF ScoreColor(const AppState& app)
{
    const Palette& p = ThemeColors();
    if (!app.audit.hasResults) return p.TextSecondary;
    int s = app.audit.score.score;
    if (s >= 75) return p.Good;
    if (s >= 50) return p.Warn;
    return p.Bad;
}

void UpdateScoreDisplay(AppState& app)
{
    MainControls& c = app.controls;
    if (app.audit.running) {
        std::wstring title;
        {
            std::lock_guard<std::mutex> lock(app.audit.textMutex);
            title = app.audit.currentTitle;
        }
        int done = app.audit.done.load();
        int total = app.audit.total.load();
        std::wstring caption = L"Auditing";
        if (total > 0) caption += L" " + std::to_wstring((std::min)(done + 1, total)) + L" of " + std::to_wstring(total);
        caption += L":\n" + title;
        if (!app.audit.hasResults) SetWindowTextW(c.scoreValue, L"...");
        SetWindowTextW(c.scoreCaption, caption.c_str());
    }
    else if (app.audit.hasResults) {
        const HardeningScore& s = app.audit.score;
        SetWindowTextW(c.scoreValue, std::to_wstring(s.score).c_str());
        std::wstring caption = s.label + L"\n" + std::to_wstring(s.fail) + L" fail, " + std::to_wstring(s.warn) +
                               L" warning, " + std::to_wstring(s.pass) + L" pass\n" + app.audit.finishedAt;
        SetWindowTextW(c.scoreCaption, caption.c_str());
    }
    else {
        SetWindowTextW(c.scoreValue, L"--");
        SetWindowTextW(c.scoreCaption, L"Audit not run yet.\nPress F5 to run it.");
    }
    InvalidateRect(c.scoreValue, NULL, TRUE);
}

void RefreshOperationLabel(AppState& app)
{
    std::wstring state;
    std::wstring filePath;
    {
        std::lock_guard<std::mutex> lock(app.progress.textMutex);
        state = app.progress.state;
        filePath = app.progress.currentFilePath;
    }
    int processed = app.progress.filesProcessed.load();
    int total = app.progress.totalFiles.load();

    std::wstringstream ss;
    ss << state << L"\n\n";
    ss << L"Files looked at: " << processed;
    if (total > 0) ss << L" of " << total << L" (" << (std::min)(100, processed * 100 / total) << L"%)";
    ss << L"\nPrograms and scripts analysed: " << app.progress.executablesFound.load() << L"\n";
    if (!filePath.empty()) ss << L"Now: " << filePath << L"\n";
    if (!app.baselineFilePath.empty()) {
        ss << L"\nActive baseline: " << FileNameOf(app.baselineFilePath);
        if (!FileExists(app.baselineFilePath)) ss << L" (not taken yet)";
        ss << L"\n";
    }
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());

    if (app.progress.running) {
        if (total > 0) {
            SetProgressMarquee(app.controls.progressBar, false);
            SetProgressRange(app.controls.progressBar, total);
            SetProgressPosition(app.controls.progressBar, (std::min)(processed, total));
        }
        else {
            SetProgressMarquee(app.controls.progressBar, true);
        }
    }
}

void UpdateResultCount(AppState& app)
{
    std::wstring text;
    size_t total = app.results.TotalCount();
    size_t shown = app.results.ViewCount();
    if (total == 0) text = L"No results";
    else if (shown == total) text = std::to_wstring(total) + (total == 1 ? L" row" : L" rows");
    else text = std::to_wstring(shown) + L" of " + std::to_wstring(total) + L" rows";
    SetWindowTextW(app.controls.countLabel, text.c_str());
}
