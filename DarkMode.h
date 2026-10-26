#pragma once

#include <windows.h>
#include <commctrl.h>

// ---------------------------------------------------------------------------
// DarkMode — Dark theme for Win32 GUI controls.
//
// Provides color constants and WM_CTLCOLOR* handlers to paint all standard
// controls (STATIC, EDIT, BUTTON, LISTBOX, ListView, etc.) with a dark palette.
//
// Usage:
//   1. Call InitDarkMode() once at startup
//   2. In WndProc, forward WM_CTLCOLORSTATIC / WM_CTLCOLOREDIT /
//      WM_CTLCOLORBTN / WM_CTLCOLORDLG / WM_ERASEBKGND to the
//      corresponding Handle* functions
//   3. For ListView: call ApplyDarkModeToListView(hListView)
//   4. For ProgressBar: call ApplyDarkModeToProgressBar(hProgressBar)
// ---------------------------------------------------------------------------

// Dark palette — all colors in one place
namespace DarkColors {
    // Main backgrounds
    const COLORREF Background      = RGB(30,  30,  35);   // main window bg
    const COLORREF Surface         = RGB(40,  40,  48);   // panels, cards
    const COLORREF SurfaceLight    = RGB(50,  50,  58);   // hover, secondary

    // Text
    const COLORREF TextPrimary     = RGB(220, 220, 225);  // main text
    const COLORREF TextSecondary   = RGB(160, 160, 170);  // labels, hints
    const COLORREF TextDim         = RGB(110, 110, 120);  // disabled

    // Controls
    const COLORREF EditBackground  = RGB(45,  45,  52);   // text input bg
    const COLORREF EditBorder      = RGB(70,  70,  80);   // input borders
    const COLORREF ButtonFace      = RGB(55,  55,  65);   // button bg
    const COLORREF ButtonText      = RGB(220, 220, 225);  // button text

    // ListView score rows (dark-themed versions)
    const COLORREF RowHighRisk     = RGB(100, 30,  30);   // score >= 7
    const COLORREF RowMedRisk      = RGB(100, 90,  20);   // score >= 4
    const COLORREF RowLowRisk      = RGB(25,  80,  40);   // score < 2
    const COLORREF RowNormal       = RGB(40,  40,  48);   // score 2-3.9

    // Accents
    const COLORREF AccentBlue      = RGB(60,  130, 220);  // links, active
    const COLORREF AccentGreen     = RGB(50,  180, 80);   // success
    const COLORREF AccentRed       = RGB(220, 60,  60);   // error
    const COLORREF AccentYellow    = RGB(220, 180, 40);   // warning
}

// Initialize dark mode brushes. Call once at startup.
void InitDarkMode();

// WM_CTLCOLORSTATIC handler — returns HBRUSH for dark static controls
HBRUSH HandleDarkCtlColorStatic(HDC hdc);

// WM_CTLCOLOREDIT handler — returns HBRUSH for dark edit controls
HBRUSH HandleDarkCtlColorEdit(HDC hdc);

// WM_CTLCOLORBTN handler — returns HBRUSH for button backgrounds
HBRUSH HandleDarkCtlColorBtn(HDC hdc);

// WM_CTLCOLORDLG handler — returns HBRUSH for dialog backgrounds
HBRUSH HandleDarkCtlColorDlg(HDC hdc);

// WM_ERASEBKGND handler — paint dark background. Returns TRUE if handled.
BOOL HandleDarkEraseBkgnd(HDC hdc, HWND hWnd);

// Apply dark mode colors to a ListView control
void ApplyDarkModeToListView(HWND hListView);

// Apply dark mode colors to a ProgressBar control
void ApplyDarkModeToProgressBar(HWND hProgressBar);

// Dark-themed custom draw for ListView (replaces HandleResultsCustomDraw)
LRESULT HandleDarkResultsCustomDraw(LPARAM lParam);

// Get the dark background brush (for returning from WM_CTLCOLOR* handlers)
HBRUSH GetDarkBackgroundBrush();
