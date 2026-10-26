#include "pch.h"
#include "Theme.h"

#include "RegUtil.h"
#include "ResultsModel.h"

#include <dwmapi.h>
#include <uxtheme.h>

#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")

static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[Theme] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

static const Palette kDark = {
    true,
    RGB(30, 30, 35), RGB(40, 40, 48), RGB(220, 220, 225), RGB(160, 160, 170), RGB(45, 45, 52), RGB(55, 55, 65), RGB(220, 220, 225),
    RGB(100, 30, 30), RGB(100, 90, 20), RGB(25, 80, 40), RGB(40, 40, 48),
    RGB(255, 180, 180), RGB(255, 255, 180), RGB(180, 255, 200),
    RGB(60, 130, 220), RGB(50, 180, 80), RGB(220, 60, 60), RGB(220, 180, 40),
};

static const Palette kLight = {
    false,
    RGB(246, 247, 249), RGB(255, 255, 255), RGB(29, 35, 48), RGB(91, 100, 117), RGB(255, 255, 255), RGB(235, 237, 241), RGB(29, 35, 48),
    RGB(255, 205, 205), RGB(255, 243, 190), RGB(212, 241, 214), RGB(255, 255, 255),
    RGB(120, 20, 20), RGB(100, 75, 0), RGB(20, 90, 35),
    RGB(47, 111, 222), RGB(46, 125, 50), RGB(198, 40, 40), RGB(178, 106, 0),
};

// UI-thread state for the current palette and its brushes (see CLAUDE.md on singletons).
struct ThemeState {
    ThemeMode mode = ThemeMode::System;
    bool      dark = true;
    HBRUSH    background = NULL;
    HBRUSH    surface = NULL;
    HBRUSH    edit = NULL;
    HBRUSH    button = NULL;
};

static ThemeState& State()
{
    static ThemeState state;
    return state;
}

static void RebuildBrushes()
{
    ThemeState& s = State();
    for (HBRUSH* b : { &s.background, &s.surface, &s.edit, &s.button }) {
        if (*b) DeleteObject(*b);
        *b = NULL;
    }
    const Palette& p = ThemeColors();
    s.background = CreateSolidBrush(p.Background);
    s.surface = CreateSolidBrush(p.Surface);
    s.edit = CreateSolidBrush(p.EditBackground);
    s.button = CreateSolidBrush(p.ButtonFace);
}

bool SystemPrefersDarkApps()
{
    DWORD light = 1;
    if (RegReadDword(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        L"AppsUseLightTheme", light)) {
        return light == 0;
    }
    return false;
}

static bool ResolveDark(ThemeMode mode)
{
    if (mode == ThemeMode::Dark) return true;
    if (mode == ThemeMode::Light) return false;
    return SystemPrefersDarkApps();
}

void InitTheme(ThemeMode mode)
{
    ThemeState& s = State();
    s.mode = mode;
    s.dark = ResolveDark(mode);
    RebuildBrushes();
    DebugLog(s.dark ? L"Theme initialized: dark" : L"Theme initialized: light");
}

void SetThemeMode(ThemeMode mode)
{
    InitTheme(mode);
}

ThemeMode GetThemeMode()
{
    return State().mode;
}

bool RefreshThemeFromSystem()
{
    ThemeState& s = State();
    bool dark = ResolveDark(s.mode);
    if (dark == s.dark) return false;
    s.dark = dark;
    RebuildBrushes();
    return true;
}

const Palette& ThemeColors()
{
    return State().dark ? kDark : kLight;
}

HBRUSH ThemeBackgroundBrush()
{
    return State().background;
}

HBRUSH ThemeCtlColorStatic(HDC hdc)
{
    const Palette& p = ThemeColors();
    SetTextColor(hdc, p.TextPrimary);
    SetBkColor(hdc, p.Background);
    SetBkMode(hdc, OPAQUE);
    return State().background;
}

HBRUSH ThemeCtlColorEdit(HDC hdc)
{
    const Palette& p = ThemeColors();
    SetTextColor(hdc, p.TextPrimary);
    SetBkColor(hdc, p.EditBackground);
    SetBkMode(hdc, OPAQUE);
    return State().edit;
}

HBRUSH ThemeCtlColorButton(HDC hdc)
{
    const Palette& p = ThemeColors();
    SetTextColor(hdc, p.ButtonText);
    SetBkColor(hdc, p.Background);
    SetBkMode(hdc, OPAQUE);
    return State().background;
}

HBRUSH ThemeCtlColorListBox(HDC hdc)
{
    return ThemeCtlColorEdit(hdc);
}

BOOL ThemeEraseBackground(HDC hdc, HWND hWnd)
{
    RECT rc;
    GetClientRect(hWnd, &rc);
    FillRect(hdc, &rc, State().background);
    return TRUE;
}

void ApplyThemeToWindowFrame(HWND hWnd)
{
    BOOL dark = ThemeColors().dark ? TRUE : FALSE;
    // DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on Windows 10 2004 and later.
    DwmSetWindowAttribute(hWnd, 20, &dark, sizeof(dark));
}

void ApplyThemeToListView(HWND hListView)
{
    if (!hListView) return;
    const Palette& p = ThemeColors();
    ListView_SetBkColor(hListView, p.Surface);
    ListView_SetTextBkColor(hListView, p.Surface);
    ListView_SetTextColor(hListView, p.TextPrimary);
    SetWindowTheme(hListView, p.dark ? L"DarkMode_Explorer" : L"Explorer", NULL);
    HWND header = ListView_GetHeader(hListView);
    if (header) SetWindowTheme(header, p.dark ? L"DarkMode_ItemsView" : L"ItemsView", NULL);
    InvalidateRect(hListView, NULL, TRUE);
}

void ApplyThemeToProgressBar(HWND hProgressBar)
{
    if (!hProgressBar) return;
    const Palette& p = ThemeColors();
    SetWindowTheme(hProgressBar, L"", L"");   // classic drawing so the colours apply
    SendMessageW(hProgressBar, PBM_SETBARCOLOR, 0, static_cast<LPARAM>(p.Accent));
    SendMessageW(hProgressBar, PBM_SETBKCOLOR, 0, static_cast<LPARAM>(p.Surface));
    InvalidateRect(hProgressBar, NULL, TRUE);
}

void ApplyThemeToControl(HWND hControl)
{
    if (!hControl) return;
    const Palette& p = ThemeColors();
    wchar_t cls[64] = {};
    GetClassNameW(hControl, cls, 64);
    if (_wcsicmp(cls, L"ComboBox") == 0) {
        SetWindowTheme(hControl, p.dark ? L"DarkMode_CFD" : L"CFD", NULL);
    }
    else if (_wcsicmp(cls, L"Button") == 0) {
        LONG_PTR type = GetWindowLongPtrW(hControl, GWL_STYLE) & BS_TYPEMASK;
        bool isCheck = type == BS_CHECKBOX || type == BS_AUTOCHECKBOX || type == BS_RADIOBUTTON ||
                       type == BS_AUTORADIOBUTTON || type == BS_GROUPBOX;
        if (isCheck) {
            // Themed check boxes ignore WM_CTLCOLORSTATIC text colour, so dark mode
            // draws them classic to keep the label readable.
            if (p.dark) SetWindowTheme(hControl, L"", L"");
            else SetWindowTheme(hControl, NULL, NULL);
        }
        else {
            SetWindowTheme(hControl, p.dark ? L"DarkMode_Explorer" : L"Explorer", NULL);
        }
    }
    else {
        SetWindowTheme(hControl, p.dark ? L"DarkMode_Explorer" : L"Explorer", NULL);
    }
    InvalidateRect(hControl, NULL, TRUE);
}

static BOOL CALLBACK ThemeChildProc(HWND hChild, LPARAM)
{
    wchar_t cls[64] = {};
    GetClassNameW(hChild, cls, 64);
    if (_wcsicmp(cls, WC_LISTVIEWW) == 0) ApplyThemeToListView(hChild);
    else if (_wcsicmp(cls, PROGRESS_CLASSW) == 0) ApplyThemeToProgressBar(hChild);
    else if (_wcsicmp(cls, WC_HEADERW) == 0) return TRUE;   // themed by its list view
    else if (_wcsicmp(cls, L"Static") != 0) ApplyThemeToControl(hChild);
    return TRUE;
}

void ApplyThemeToWindowTree(HWND hWnd)
{
    if (!hWnd) return;
    ApplyThemeToWindowFrame(hWnd);
    EnumChildWindows(hWnd, ThemeChildProc, 0);
    RedrawWindow(hWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
}

LRESULT ThemeResultsCustomDraw(LPARAM lParam, const ResultsModel& model)
{
    LPNMLVCUSTOMDRAW cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam);
    switch (cd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT: {
        size_t index = static_cast<size_t>(cd->nmcd.dwItemSpec);
        if (index >= model.ViewCount()) return CDRF_DODEFAULT;
        const ScanRow& row = model.ViewRow(index);
        const Palette& p = ThemeColors();
        double score = row.entry.malwareScore;
        if (score >= 7.0) {
            cd->clrTextBk = p.RowHighRisk;
            cd->clrText = p.RowHighText;
        }
        else if (score >= 4.0 || row.status == L"NEW" || row.status == L"CHANGED") {
            cd->clrTextBk = p.RowMedRisk;
            cd->clrText = p.RowMedText;
        }
        else if (score < 2.0 && row.status != L"MISSING") {
            cd->clrTextBk = p.RowLowRisk;
            cd->clrText = p.RowLowText;
        }
        else {
            cd->clrTextBk = p.RowNormal;
            cd->clrText = p.TextPrimary;
        }
        return CDRF_NEWFONT;
    }
    default:
        return CDRF_DODEFAULT;
    }
}
