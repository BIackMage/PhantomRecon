#include "pch.h"
#include "MainCommands.h"

#include "CommandHelpers.h"
#include "DetailWindow.h"
#include "GuiComponents.h"
#include "MainLayout.h"
#include "resource.h"

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[ResultsCommands] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

static void InfoNoSelection(AppState& app)
{
    AppendToChatDisplay(app.aiSidebar, L"\r\n[Info]: Select a file in the results list first.\r\n");
}

// ---------------------------------------------------------------------------
// Results menu
// ---------------------------------------------------------------------------
static void CmdDetails(AppState& app, HWND)
{
    const ScanRow* row = SelectedRow(app);
    if (row) ShowRowDetailWindow(app, *row);
}

static void CmdCopyPath(AppState& app, HWND hWnd)
{
    const ScanRow* row = SelectedRow(app);
    if (row) CopyTextToClipboard(hWnd, row->entry.path);
}

static void CmdCopySha(AppState& app, HWND hWnd)
{
    const ScanRow* row = SelectedRow(app);
    if (row) CopyTextToClipboard(hWnd, row->entry.sha256);
}

static void CmdOpenLocation(AppState& app, HWND)
{
    const ScanRow* row = SelectedRow(app);
    if (row) ShowFileInExplorer(row->entry.path);
}

static void CmdClear(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"clear the results")) return;
    app.lastScan = LastScan();
    ShowRows(app, {});
    DebugLog(L"Results cleared");
}

static void CmdFocusSearch(AppState& app, HWND)
{
    SetFocus(app.controls.searchEdit);
    SendMessageW(app.controls.searchEdit, EM_SETSEL, 0, -1);
}

// ---------------------------------------------------------------------------
// AI panel
// ---------------------------------------------------------------------------
static void CmdAiToggle(AppState& app, HWND)
{
    ToggleAiSidebar(app.aiSidebar);
}

static void CmdAiSend(AppState& app, HWND)
{
    SendUserMessage(app.aiSidebar, GetWindowTextString(app.aiSidebar.hInputField));
}

static void CmdAiTriage(AppState& app, HWND)
{
    const ScanRow* row = SelectedRow(app);
    if (!row) {
        InfoNoSelection(app);
        return;
    }
    if (!app.aiSidebar.expanded) ToggleAiSidebar(app.aiSidebar);
    TriageSelectedFile(app.aiSidebar, *row);
}

static void CmdAiSummary(AppState& app, HWND)
{
    if (!app.lastScan.has) {
        AppendToChatDisplay(app.aiSidebar, L"\r\n[Info]: Run a scan or compare two baselines first.\r\n");
        return;
    }
    RequestScanSummary(app.aiSidebar, app.lastScan.summary, app.lastScan.title);
}

static void CmdAiAudit(AppState& app, HWND)
{
    RequestAuditAnalysis(app.aiSidebar, app.audit.results, static_cast<size_t>(app.settings.llmMaxPromptChars));
}

// ---------------------------------------------------------------------------
// Filter and search controls
// ---------------------------------------------------------------------------
static void OnFilterChanged(AppState& app)
{
    int sel = static_cast<int>(SendMessageW(app.controls.filterCombo, CB_GETCURSEL, 0, 0));
    if (sel < 0) sel = 0;
    app.results.SetFilter(static_cast<StatusFilter>(sel));
    ListView_SetItemState(app.controls.resultsListView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    RefreshResultsList(app.controls.resultsListView, app.results);
    UpdateResultCount(app);
}

static void OnSearchChanged(AppState& app)
{
    app.results.SetSearch(GetWindowTextString(app.controls.searchEdit));
    ListView_SetItemState(app.controls.resultsListView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    RefreshResultsList(app.controls.resultsListView, app.results);
    UpdateResultCount(app);
}

bool DispatchResultsCommand(AppState& app, HWND hWnd, int commandId, int notifyCode)
{
    if (commandId == ID_FILTER_COMBO) {
        if (notifyCode == CBN_SELCHANGE) OnFilterChanged(app);
        return true;
    }
    if (commandId == ID_SEARCH_EDIT) {
        if (notifyCode == EN_CHANGE) OnSearchChanged(app);
        return true;
    }

    typedef void (*CommandHandler)(AppState&, HWND);
    struct Entry { int id; CommandHandler handler; };
    static const Entry kTable[] = {
        { ID_RESULTS_DETAILS,       CmdDetails },
        { ID_RESULTS_COPY_PATH,     CmdCopyPath },
        { ID_RESULTS_COPY_SHA,      CmdCopySha },
        { ID_RESULTS_OPEN_LOCATION, CmdOpenLocation },
        { ID_RESULTS_CLEAR,         CmdClear },
        { ID_RESULTS_FOCUS_SEARCH,  CmdFocusSearch },
        { ID_RESULTS_TRIAGE,        CmdAiTriage },
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
