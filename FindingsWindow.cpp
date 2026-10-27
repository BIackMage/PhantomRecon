#include "pch.h"
#include "FindingsWindow.h"

#include "CheckCatalog.h"
#include "DetailText.h"
#include "GuiComponents.h"
#include "MainCommands.h"
#include "Theme.h"
#include "resource.h"

#include <algorithm>
#include <map>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[FindingsWindow] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

static const wchar_t* FINDINGS_CLASS = L"PhantomRecon_Findings";

enum FindingsControlId {
    IDC_FIND_FILTER = 4101,
    IDC_FIND_SUMMARY,
    IDC_FIND_LIST,
    IDC_FIND_TEXT,
    IDC_FIND_COPY_FIX,
    IDC_FIND_COPY_UNDO,
    IDC_FIND_COPY_ALL,
    IDC_FIND_CLOSE,
    IDC_FIND_SAVE_SCRIPT,
};

// Buttons: the three copy buttons under the text, Close at the right, and the fix
// script button under the list on the left.
static const int kCopyButtons = 3;
static const int kCloseButton = 3;
static const int kSaveScriptButton = 4;
static const int kButtonCount = 5;

enum FindingsFilter { FilterProblems = 0, FilterAll = 1 };

// Per-window state, owned by the window: created in ShowFindingsWindow,
// deleted at WM_NCDESTROY.
struct FindingsWindowState {
    AppState*                                   app = nullptr;
    std::map<std::wstring, SecurityCheckResult> resultsById;
    bool                                        hasResults = false;
    std::vector<size_t>                         rows;      // catalog index per list row
    HWND filter = NULL, summary = NULL, list = NULL, text = NULL;
    HWND buttons[kButtonCount] = {};
};

static FindingsWindowState* GetState(HWND hWnd)
{
    return reinterpret_cast<FindingsWindowState*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
}

static const SecurityCheckResult* ResultFor(const FindingsWindowState& st, const std::wstring& id)
{
    auto it = st.resultsById.find(id);
    return it == st.resultsById.end() ? nullptr : &it->second;
}

static int StatusRank(const SecurityCheckResult* r)
{
    if (!r) return 5;
    if (r->status == CHECK_FAIL) return 0;
    if (r->status == CHECK_WARNING) return 1;
    if (r->status == CHECK_ERROR) return 2;
    if (r->status == CHECK_INFO) return 3;
    if (r->status == CHECK_PASS) return 4;
    return 5;
}

static void LoadResults(FindingsWindowState& st)
{
    st.resultsById.clear();
    st.hasResults = st.app && st.app->audit.hasResults;
    if (!st.hasResults) return;
    for (const SecurityCheckResult& r : st.app->audit.results) st.resultsById[r.id] = r;
}

static void Layout(HWND hWnd, FindingsWindowState& st)
{
    RECT rc;
    GetClientRect(hWnd, &rc);
    const int m = 10;
    const int top = 40;
    const int btnH = 30;
    const int listW = (rc.right - 3 * m) * 2 / 5;
    const int bodyH = rc.bottom - top - 2 * m - btnH;

    MoveWindow(st.filter, m, m, 260, 300, TRUE);
    MoveWindow(st.summary, m + 270, m + 4, rc.right - 280 - m, 22, TRUE);
    MoveWindow(st.list, m, top, listW, bodyH, TRUE);
    MoveWindow(st.text, 2 * m + listW, top, rc.right - 3 * m - listW, bodyH, TRUE);

    int y = rc.bottom - m - btnH;
    int x = 2 * m + listW;
    for (int i = 0; i < kCopyButtons; ++i) {
        MoveWindow(st.buttons[i], x, y, 130, btnH, TRUE);
        x += 138;
    }
    MoveWindow(st.buttons[kCloseButton], rc.right - m - 100, y, 100, btnH, TRUE);
    MoveWindow(st.buttons[kSaveScriptButton], m, y, (std::min)(listW, 160), btnH, TRUE);
}

static void ShowSelected(FindingsWindowState& st)
{
    int sel = ListView_GetNextItem(st.list, -1, LVNI_SELECTED);
    bool has = sel >= 0 && static_cast<size_t>(sel) < st.rows.size();
    for (int i = 0; i < kCopyButtons; ++i) EnableWindow(st.buttons[i], has);
    EnableWindow(st.buttons[kSaveScriptButton], st.hasResults);
    if (!has) {
        SetWindowTextW(st.text, st.rows.empty()
            ? L"Nothing to show with this filter. Choose \"All checks\" to see every check."
            : L"Pick a check on the left to read what it means and how to fix it.");
        return;
    }
    const CheckInfo& info = GetCheckCatalog()[st.rows[static_cast<size_t>(sel)]];
    SetWindowTextW(st.text, ToWindowsLineEnds(BuildFindingDetailText(info, ResultFor(st, info.id))).c_str());
}

static void FillList(FindingsWindowState& st)
{
    const std::vector<CheckInfo>& catalog = GetCheckCatalog();
    bool problemsOnly = st.hasResults && SendMessageW(st.filter, CB_GETCURSEL, 0, 0) == FilterProblems;

    st.rows.clear();
    for (size_t i = 0; i < catalog.size(); ++i) {
        const SecurityCheckResult* r = ResultFor(st, catalog[i].id);
        if (problemsOnly && (!r || (r->status != CHECK_FAIL && r->status != CHECK_WARNING))) continue;
        st.rows.push_back(i);
    }
    if (problemsOnly) {
        std::stable_sort(st.rows.begin(), st.rows.end(), [&](size_t a, size_t b) {
            int ra = StatusRank(ResultFor(st, catalog[a].id));
            int rb = StatusRank(ResultFor(st, catalog[b].id));
            if (ra != rb) return ra < rb;
            return static_cast<int>(catalog[a].severity) > static_cast<int>(catalog[b].severity);
        });
    }

    SendMessageW(st.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(st.list);
    for (size_t row = 0; row < st.rows.size(); ++row) {
        const CheckInfo& info = catalog[st.rows[row]];
        const SecurityCheckResult* r = ResultFor(st, info.id);
        std::wstring status = r ? r->status : L"not run";
        std::wstring severity = SeverityName(info.severity);

        LVITEMW item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = static_cast<int>(row);
        item.pszText = const_cast<LPWSTR>(status.c_str());
        item.lParam = static_cast<LPARAM>(st.rows[row]);
        int idx = ListView_InsertItem(st.list, &item);
        ListView_SetItemText(st.list, idx, 1, const_cast<LPWSTR>(severity.c_str()));
        ListView_SetItemText(st.list, idx, 2, const_cast<LPWSTR>(info.title.c_str()));
        ListView_SetItemText(st.list, idx, 3, const_cast<LPWSTR>(info.category.c_str()));
    }
    SendMessageW(st.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(st.list, NULL, TRUE);

    std::wstring summary;
    if (!st.hasResults) {
        summary = L"The audit has not finished yet. These are all " + std::to_wstring(catalog.size()) + L" checks it runs.";
    }
    else {
        const HardeningScore& s = st.app->audit.score;
        summary = L"Score " + std::to_wstring(s.score) + L"/100 (" + s.label + L"): " + std::to_wstring(s.fail) +
                  L" fail, " + std::to_wstring(s.warn) + L" warning, " + std::to_wstring(s.pass) + L" pass. Audit finished " +
                  st.app->audit.finishedAt + L".";
    }
    SetWindowTextW(st.summary, summary.c_str());

    if (!st.rows.empty()) {
        ListView_SetItemState(st.list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ShowSelected(st);
}

static LRESULT OnCustomDraw(FindingsWindowState& st, LPARAM lParam)
{
    NMLVCUSTOMDRAW* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
    if (cd->nmcd.dwDrawStage != CDDS_ITEMPREPAINT) return CDRF_DODEFAULT;
    size_t catalogIndex = static_cast<size_t>(cd->nmcd.lItemlParam);
    const std::vector<CheckInfo>& catalog = GetCheckCatalog();
    if (catalogIndex >= catalog.size()) return CDRF_DODEFAULT;
    const SecurityCheckResult* r = ResultFor(st, catalog[catalogIndex].id);
    const Palette& p = ThemeColors();
    if (r && r->status == CHECK_FAIL) { cd->clrTextBk = p.RowHighRisk; cd->clrText = p.RowHighText; }
    else if (r && r->status == CHECK_WARNING) { cd->clrTextBk = p.RowMedRisk; cd->clrText = p.RowMedText; }
    else if (r && r->status == CHECK_PASS) { cd->clrTextBk = p.RowLowRisk; cd->clrText = p.RowLowText; }
    else { cd->clrTextBk = p.RowNormal; cd->clrText = p.TextPrimary; }
    return CDRF_NEWFONT;
}

static void OnCreate(HWND hWnd, FindingsWindowState& st, HINSTANCE hInst)
{
    HFONT font = st.app ? st.app->ui.uiFont : NULL;

    st.filter = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIND_FILTER)), hInst, NULL);
    SendMessageW(st.filter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Problems only (fail and warning)"));
    SendMessageW(st.filter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"All checks"));
    SendMessageW(st.filter, CB_SETCURSEL, st.hasResults ? FilterProblems : FilterAll, 0);

    st.summary = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
        0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIND_SUMMARY)), hInst, NULL);

    st.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIND_LIST)), hInst, NULL);
    ListView_SetExtendedListViewStyle(st.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    const wchar_t* columns[4] = { L"Status", L"Severity", L"Check", L"Category" };
    const int widths[4] = { 75, 70, 240, 150 };
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = const_cast<LPWSTR>(columns[i]);
        col.cx = widths[i];
        col.iSubItem = i;
        ListView_InsertColumn(st.list, i, &col);
    }

    st.text = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIND_TEXT)), hInst, NULL);

    const wchar_t* labels[kButtonCount] = { L"Copy the Fix", L"Copy the Undo", L"Copy All", L"Close", L"Save Fix Script..." };
    const int ids[kButtonCount] = { IDC_FIND_COPY_FIX, IDC_FIND_COPY_UNDO, IDC_FIND_COPY_ALL, IDC_FIND_CLOSE, IDC_FIND_SAVE_SCRIPT };
    for (int i = 0; i < kButtonCount; ++i) {
        st.buttons[i] = CreateWindowW(L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ids[i])), hInst, NULL);
    }

    for (HWND h : { st.filter, st.summary, st.list, st.text }) SetControlFont(h, font);
    for (HWND h : st.buttons) SetControlFont(h, font);
    Layout(hWnd, st);
    FillList(st);
    ApplyThemeToWindowTree(hWnd);
}

static void CopySelected(HWND hWnd, FindingsWindowState& st, int what)
{
    int sel = ListView_GetNextItem(st.list, -1, LVNI_SELECTED);
    if (sel < 0 || static_cast<size_t>(sel) >= st.rows.size()) return;
    const CheckInfo& info = GetCheckCatalog()[st.rows[static_cast<size_t>(sel)]];
    std::wstring text;
    if (what == IDC_FIND_COPY_FIX) text = info.fix;
    else if (what == IDC_FIND_COPY_UNDO) text = info.undo;
    else text = BuildFindingDetailText(info, ResultFor(st, info.id));
    CopyTextToClipboard(hWnd, ToWindowsLineEnds(text));
    DebugLog(L"Copied " + std::to_wstring(what) + L" for " + info.id);
}

static void OnCommand(HWND hWnd, FindingsWindowState& st, int id, int code)
{
    switch (id) {
    case IDC_FIND_FILTER:
        if (code == CBN_SELCHANGE) FillList(st);
        break;
    case IDC_FIND_COPY_FIX:
    case IDC_FIND_COPY_UNDO:
    case IDC_FIND_COPY_ALL:
        CopySelected(hWnd, st, id);
        break;
    case IDC_FIND_SAVE_SCRIPT:
        if (st.app) SaveFixScriptFiles(*st.app, hWnd);
        DebugLog(L"Save Fix Script pressed");
        break;
    case IDC_FIND_CLOSE:
    case IDCANCEL:
        DestroyWindow(hWnd);
        break;
    default:
        break;
    }
}

static LRESULT CALLBACK FindingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    FindingsWindowState* st = GetState(hWnd);
    if (!st) return DefWindowProcW(hWnd, msg, wParam, lParam);

    switch (msg) {
    case WM_CREATE:
        OnCreate(hWnd, *st, reinterpret_cast<CREATESTRUCTW*>(lParam)->hInstance);
        return 0;
    case WM_SIZE:
        Layout(hWnd, *st);
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mm = reinterpret_cast<MINMAXINFO*>(lParam);
        mm->ptMinTrackSize.x = 820;
        mm->ptMinTrackSize.y = 420;
        return 0;
    }
    case WM_COMMAND:
        OnCommand(hWnd, *st, LOWORD(wParam), HIWORD(wParam));
        return 0;
    case WM_NOTIFY: {
        NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->hwndFrom == st->list) {
            if (hdr->code == LVN_ITEMCHANGED) {
                // Selected or deselected: both change what the copy buttons can act on,
                // so a click on empty space greys them out again.
                NMLISTVIEW* lv = reinterpret_cast<NMLISTVIEW*>(lParam);
                if ((lv->uChanged & LVIF_STATE) && ((lv->uOldState ^ lv->uNewState) & LVIS_SELECTED)) {
                    ShowSelected(*st);
                }
                return 0;
            }
            if (hdr->code == NM_CUSTOMDRAW) return OnCustomDraw(*st, lParam);
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HWND ctl = reinterpret_cast<HWND>(lParam);
        if (ctl == st->text) return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));
        return reinterpret_cast<LRESULT>(ThemeCtlColorStatic(reinterpret_cast<HDC>(wParam)));
    }
    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORLISTBOX:
        return reinterpret_cast<LRESULT>(ThemeCtlColorListBox(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(ThemeCtlColorButton(reinterpret_cast<HDC>(wParam)));
    case WM_ERASEBKGND:
        return ThemeEraseBackground(reinterpret_cast<HDC>(wParam), hWnd);
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    case WM_NCDESTROY:
        if (st->app && st->app->findingsWindow == hWnd) st->app->findingsWindow = NULL;
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, 0);
        delete st;
        DebugLog(L"Findings window closed");
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    default:
        break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static void EnsureClass(HINSTANCE hInst)
{
    WNDCLASSEXW existing = {};
    existing.cbSize = sizeof(existing);
    if (GetClassInfoExW(hInst, FINDINGS_CLASS, &existing)) return;
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = FindingsWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_PHANTOMRECON));
    wc.lpszClassName = FINDINGS_CLASS;
    RegisterClassExW(&wc);
}

void ShowFindingsWindow(AppState& app)
{
    if (app.findingsWindow && IsWindow(app.findingsWindow)) {
        ShowWindow(app.findingsWindow, SW_SHOWNORMAL);
        SetForegroundWindow(app.findingsWindow);
        return;
    }
    EnsureClass(app.hInstance);
    FindingsWindowState* st = new FindingsWindowState();
    st->app = &app;
    LoadResults(*st);

    RECT mainRect;
    GetWindowRect(app.hMainWindow, &mainRect);
    HWND hWnd = CreateWindowExW(WS_EX_CONTROLPARENT, FINDINGS_CLASS, L"Security Findings and Fixes", WS_OVERLAPPEDWINDOW,
        mainRect.left + 40, mainRect.top + 40, 1100, 720, app.hMainWindow, NULL, app.hInstance, st);
    if (!hWnd) {
        DebugLog(L"Failed to create the findings window");
        delete st;
        return;
    }
    app.findingsWindow = hWnd;
    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);
    DebugLog(L"Findings window opened");
}

void RefreshFindingsWindow(AppState& app)
{
    if (!app.findingsWindow || !IsWindow(app.findingsWindow)) return;
    FindingsWindowState* st = GetState(app.findingsWindow);
    if (!st) return;
    LoadResults(*st);
    if (st->hasResults) SendMessageW(st->filter, CB_SETCURSEL, FilterProblems, 0);
    FillList(*st);
    DebugLog(L"Findings window refreshed");
}
