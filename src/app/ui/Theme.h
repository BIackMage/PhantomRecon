#pragma once

#include <windows.h>
#include <commctrl.h>

class ResultsModel;

// ---------------------------------------------------------------------------
// Theme: light and dark palettes for every window, chosen by the user or by
// Windows' own app theme setting. UI thread only.
//
// Usage: InitTheme(mode) once at startup; forward WM_CTLCOLOR* and
// WM_ERASEBKGND to the handlers below; call ApplyTheme* on list views,
// progress bars and top-level windows; on WM_SETTINGCHANGE call
// RefreshThemeFromSystem() and repaint.
// ---------------------------------------------------------------------------

enum class ThemeMode { System = 0, Dark = 1, Light = 2 };

struct Palette {
    bool     dark;
    COLORREF Background, Surface, TextPrimary, TextSecondary, EditBackground, ButtonFace, ButtonText;
    COLORREF RowHighRisk, RowMedRisk, RowLowRisk, RowNormal;
    COLORREF RowHighText, RowMedText, RowLowText;
    COLORREF Accent, Good, Bad, Warn;
};

void InitTheme(ThemeMode mode);
void SetThemeMode(ThemeMode mode);
ThemeMode GetThemeMode();

// Re-read Windows' setting when in System mode. True when the palette changed.
bool RefreshThemeFromSystem();

// True when Windows is set to dark mode for apps.
bool SystemPrefersDarkApps();

const Palette& ThemeColors();
HBRUSH ThemeBackgroundBrush();

HBRUSH ThemeCtlColorStatic(HDC hdc);
HBRUSH ThemeCtlColorEdit(HDC hdc);
HBRUSH ThemeCtlColorButton(HDC hdc);
HBRUSH ThemeCtlColorListBox(HDC hdc);
BOOL   ThemeEraseBackground(HDC hdc, HWND hWnd);

void ApplyThemeToWindowFrame(HWND hWnd);      // dark or light title bar
void ApplyThemeToListView(HWND hListView);
void ApplyThemeToProgressBar(HWND hProgressBar);
void ApplyThemeToControl(HWND hControl);      // edits, combo boxes, scroll bars, tab controls

// Frame plus every child control, by class. Then repaint the whole window.
void ApplyThemeToWindowTree(HWND hWnd);

// Row colouring for the results list, from the model's score and status.
LRESULT ThemeResultsCustomDraw(LPARAM lParam, const ResultsModel& model);
