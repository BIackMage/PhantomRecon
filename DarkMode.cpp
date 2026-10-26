#include "pch.h"
#include "DarkMode.h"

#include <uxtheme.h>

#pragma comment(lib, "uxtheme.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[DarkMode] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Persistent brushes (created once, never destroyed — live for app lifetime)
// ---------------------------------------------------------------------------
static HBRUSH g_hBrBackground = NULL;
static HBRUSH g_hBrSurface    = NULL;
static HBRUSH g_hBrEdit       = NULL;
static HBRUSH g_hBrButton     = NULL;

// ---------------------------------------------------------------------------
// InitDarkMode
// ---------------------------------------------------------------------------
void InitDarkMode()
{
    g_hBrBackground = CreateSolidBrush(DarkColors::Background);
    g_hBrSurface    = CreateSolidBrush(DarkColors::Surface);
    g_hBrEdit       = CreateSolidBrush(DarkColors::EditBackground);
    g_hBrButton     = CreateSolidBrush(DarkColors::ButtonFace);

    DebugLog(L"Dark mode initialized");
}

// ---------------------------------------------------------------------------
// WM_CTLCOLORSTATIC — static labels, read-only edits
// ---------------------------------------------------------------------------
HBRUSH HandleDarkCtlColorStatic(HDC hdc)
{
    SetTextColor(hdc, DarkColors::TextPrimary);
    SetBkColor(hdc, DarkColors::Background);
    SetBkMode(hdc, OPAQUE);
    return g_hBrBackground;
}

// ---------------------------------------------------------------------------
// WM_CTLCOLOREDIT — text input fields
// ---------------------------------------------------------------------------
HBRUSH HandleDarkCtlColorEdit(HDC hdc)
{
    SetTextColor(hdc, DarkColors::TextPrimary);
    SetBkColor(hdc, DarkColors::EditBackground);
    SetBkMode(hdc, OPAQUE);
    return g_hBrEdit;
}

// ---------------------------------------------------------------------------
// WM_CTLCOLORBTN — button backgrounds
// ---------------------------------------------------------------------------
HBRUSH HandleDarkCtlColorBtn(HDC hdc)
{
    SetTextColor(hdc, DarkColors::ButtonText);
    SetBkColor(hdc, DarkColors::Background);
    SetBkMode(hdc, OPAQUE);
    return g_hBrBackground;
}

// ---------------------------------------------------------------------------
// WM_CTLCOLORDLG — dialog backgrounds
// ---------------------------------------------------------------------------
HBRUSH HandleDarkCtlColorDlg(HDC hdc)
{
    return g_hBrBackground;
}

// ---------------------------------------------------------------------------
// WM_ERASEBKGND — paint window background dark
// ---------------------------------------------------------------------------
BOOL HandleDarkEraseBkgnd(HDC hdc, HWND hWnd)
{
    RECT rc;
    GetClientRect(hWnd, &rc);
    FillRect(hdc, &rc, g_hBrBackground);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Apply dark mode to ListView
// ---------------------------------------------------------------------------
void ApplyDarkModeToListView(HWND hListView)
{
    if (!hListView) return;

    ListView_SetBkColor(hListView, DarkColors::Surface);
    ListView_SetTextBkColor(hListView, DarkColors::Surface);
    ListView_SetTextColor(hListView, DarkColors::TextPrimary);

    // Try to set dark scrollbars via uxtheme (Windows 10 1809+)
    SetWindowTheme(hListView, L"DarkMode_Explorer", NULL);

    // Force header dark theme
    HWND hHeader = ListView_GetHeader(hListView);
    if (hHeader) {
        SetWindowTheme(hHeader, L"DarkMode_ItemsView", NULL);
    }

    InvalidateRect(hListView, NULL, TRUE);
    DebugLog(L"Dark mode applied to ListView");
}

// ---------------------------------------------------------------------------
// Apply dark mode to ProgressBar
// ---------------------------------------------------------------------------
void ApplyDarkModeToProgressBar(HWND hProgressBar)
{
    if (!hProgressBar) return;

    // Set bar color to accent blue and background to dark surface
    SendMessage(hProgressBar, PBM_SETBARCOLOR, 0, (LPARAM)DarkColors::AccentBlue);
    SendMessage(hProgressBar, PBM_SETBKCOLOR, 0, (LPARAM)DarkColors::Surface);

    SetWindowTheme(hProgressBar, L"DarkMode_Explorer", NULL);

    DebugLog(L"Dark mode applied to ProgressBar");
}

// ---------------------------------------------------------------------------
// Dark-themed custom draw for results ListView
// ---------------------------------------------------------------------------
LRESULT HandleDarkResultsCustomDraw(LPARAM lParam)
{
    LPNMLVCUSTOMDRAW pCD = reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam);

    switch (pCD->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;

    case CDDS_ITEMPREPAINT:
    {
        // Read the score text from column 2
        wchar_t scoreBuf[32] = {};
        ListView_GetItemText(pCD->nmcd.hdr.hwndFrom,
            static_cast<int>(pCD->nmcd.dwItemSpec), 2, scoreBuf, 32);

        double score = _wtof(scoreBuf);

        // Dark-themed color coding
        if (score >= 7.0) {
            pCD->clrTextBk = DarkColors::RowHighRisk;
            pCD->clrText = RGB(255, 180, 180);  // light red text
        }
        else if (score >= 4.0) {
            pCD->clrTextBk = DarkColors::RowMedRisk;
            pCD->clrText = RGB(255, 255, 180);  // light yellow text
        }
        else if (score < 2.0) {
            pCD->clrTextBk = DarkColors::RowLowRisk;
            pCD->clrText = RGB(180, 255, 200);  // light green text
        }
        else {
            pCD->clrTextBk = DarkColors::RowNormal;
            pCD->clrText = DarkColors::TextPrimary;
        }

        return CDRF_NEWFONT;
    }

    default:
        return CDRF_DODEFAULT;
    }
}

// ---------------------------------------------------------------------------
// GetDarkBackgroundBrush
// ---------------------------------------------------------------------------
HBRUSH GetDarkBackgroundBrush()
{
    return g_hBrBackground;
}
