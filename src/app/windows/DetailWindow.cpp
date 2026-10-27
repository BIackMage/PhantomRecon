#include "pch.h"
#include "DetailWindow.h"

#include "AppPaths.h"
#include "DetailText.h"
#include "GuiComponents.h"
#include "Theme.h"
#include "resource.h"

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[DetailWindow] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

static const wchar_t* DETAIL_CLASS = L"PhantomRecon_Detail";

enum DetailControlId {
    IDC_DETAIL_TEXT = 4001,
    IDC_DETAIL_COPY,
    IDC_DETAIL_COPY_SHA,
    IDC_DETAIL_EXPLORER,
    IDC_DETAIL_CLOSE,
};

// Per-window state, owned by the window: created in ShowRowDetailWindow,
// deleted at WM_NCDESTROY.
struct DetailWindowState {
    AppState* app = nullptr;
    ScanRow   row;
    HWND      text = NULL;
    HWND      buttons[4] = {};
};

static DetailWindowState* GetState(HWND hWnd)
{
    return reinterpret_cast<DetailWindowState*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
}

static void Layout(HWND hWnd, DetailWindowState& st)
{
    RECT rc;
    GetClientRect(hWnd, &rc);
    const int m = 10;
    const int btnH = 30;
    const int btnW = 150;
    int textH = rc.bottom - 3 * m - btnH;
    if (textH < 50) textH = 50;
    MoveWindow(st.text, m, m, rc.right - 2 * m, textH, TRUE);
    int x = m;
    int y = rc.bottom - m - btnH;
    for (int i = 0; i < 3; ++i) {
        MoveWindow(st.buttons[i], x, y, btnW, btnH, TRUE);
        x += btnW + 8;
    }
    MoveWindow(st.buttons[3], rc.right - m - 100, y, 100, btnH, TRUE);
}

static void ShowRow(HWND hWnd, DetailWindowState& st)
{
    SetWindowTextW(st.text, ToWindowsLineEnds(BuildRowDetailText(st.row)).c_str());
    std::wstring title = L"Details: " + FileNameOf(st.row.entry.path);
    SetWindowTextW(hWnd, title.c_str());
    EnableWindow(st.buttons[1], !st.row.entry.sha256.empty());
}

static void OnCreate(HWND hWnd, DetailWindowState& st, HINSTANCE hInst)
{
    HFONT font = st.app ? st.app->ui.uiFont : NULL;
    st.text = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_DETAIL_TEXT)), hInst, NULL);
    SetControlFont(st.text, font);

    const wchar_t* labels[4] = { L"Copy All", L"Copy SHA-256", L"Show in Explorer", L"Close" };
    const int ids[4] = { IDC_DETAIL_COPY, IDC_DETAIL_COPY_SHA, IDC_DETAIL_EXPLORER, IDC_DETAIL_CLOSE };
    for (int i = 0; i < 4; ++i) {
        st.buttons[i] = CreateWindowW(L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 10, 10, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ids[i])), hInst, NULL);
        SetControlFont(st.buttons[i], font);
    }
    Layout(hWnd, st);
    ShowRow(hWnd, st);
    ApplyThemeToWindowTree(hWnd);
}

static void OnCommand(HWND hWnd, DetailWindowState& st, int id)
{
    switch (id) {
    case IDC_DETAIL_COPY:
        CopyTextToClipboard(hWnd, ToWindowsLineEnds(BuildRowDetailText(st.row)));
        break;
    case IDC_DETAIL_COPY_SHA:
        CopyTextToClipboard(hWnd, st.row.entry.sha256);
        break;
    case IDC_DETAIL_EXPLORER:
        ShowFileInExplorer(st.row.entry.path);
        break;
    case IDC_DETAIL_CLOSE:
    case IDCANCEL:
        DestroyWindow(hWnd);
        break;
    default:
        break;
    }
}

static LRESULT CALLBACK DetailWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    DetailWindowState* st = GetState(hWnd);
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
        mm->ptMinTrackSize.x = 560;
        mm->ptMinTrackSize.y = 300;
        return 0;
    }
    case WM_COMMAND:
        OnCommand(hWnd, *st, LOWORD(wParam));
        return 0;
    case WM_CTLCOLORSTATIC:
        return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(ThemeCtlColorButton(reinterpret_cast<HDC>(wParam)));
    case WM_ERASEBKGND:
        return ThemeEraseBackground(reinterpret_cast<HDC>(wParam), hWnd);
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    case WM_NCDESTROY:
        if (st->app && st->app->detailWindow == hWnd) st->app->detailWindow = NULL;
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, 0);
        delete st;
        DebugLog(L"Detail window closed");
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
    if (GetClassInfoExW(hInst, DETAIL_CLASS, &existing)) return;
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = DetailWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_PHANTOMRECON));
    wc.lpszClassName = DETAIL_CLASS;
    RegisterClassExW(&wc);
}

void ShowRowDetailWindow(AppState& app, const ScanRow& row)
{
    if (app.detailWindow && IsWindow(app.detailWindow)) {
        DetailWindowState* st = GetState(app.detailWindow);
        if (st) {
            st->row = row;
            ShowRow(app.detailWindow, *st);
        }
        ShowWindow(app.detailWindow, SW_SHOWNORMAL);
        SetForegroundWindow(app.detailWindow);
        return;
    }

    EnsureClass(app.hInstance);
    DetailWindowState* st = new DetailWindowState();
    st->app = &app;
    st->row = row;

    RECT mainRect;
    GetWindowRect(app.hMainWindow, &mainRect);
    HWND hWnd = CreateWindowExW(WS_EX_CONTROLPARENT, DETAIL_CLASS, L"Details", WS_OVERLAPPEDWINDOW,
        mainRect.left + 60, mainRect.top + 60, 760, 640, app.hMainWindow, NULL, app.hInstance, st);
    if (!hWnd) {
        DebugLog(L"Failed to create the detail window");
        delete st;
        return;
    }
    app.detailWindow = hWnd;
    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);
    DebugLog(L"Detail window opened for " + row.entry.path);
}
