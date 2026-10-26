#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include "ResultsModel.h"

// ---------------------------------------------------------------------------
// GuiComponents: reusable Win32 controls and dialogs. UI thread only.
//
// The results list is a virtual (owner-data) list view: it stores no text.
// It asks ResultsModel for each visible cell through LVN_GETDISPINFO, so a
// scan with 100,000 rows costs no more to show than one with 100.
// ---------------------------------------------------------------------------

// Initialize common controls (call once at startup before creating windows).
void InitGuiCommonControls();

// Fonts that follow the system message font, scaled for the window's DPI.
HFONT CreateUiFont(HWND hWnd, int pointSizeDelta, bool bold);
void  SetControlFont(HWND hControl, HFONT font);

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------
HWND CreateScanProgressBar(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height);
void SetProgressRange(HWND hProgressBar, int maxValue);
void SetProgressPosition(HWND hProgressBar, int position);
// Marquee (moving block) while the total is unknown.
void SetProgressMarquee(HWND hProgressBar, bool enable);

// ---------------------------------------------------------------------------
// Results list
// ---------------------------------------------------------------------------
HWND CreateResultsListView(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height);

// Tell the list how many rows the model shows now and repaint.
void RefreshResultsList(HWND hListView, const ResultsModel& model);

// LVN_GETDISPINFO: fill the requested cell from the model.
void FillResultsDispInfo(LPARAM lParam, const ResultsModel& model);

// Show the sort arrow in the header for the model's sort column.
void UpdateSortArrow(HWND hListView, const ResultsModel& model);

// View index of the focused or first selected row, or -1.
int SelectedResultIndex(HWND hListView);

// Fill the filter combo box with the StatusFilter names, in enum order.
void FillFilterCombo(HWND hCombo);
const wchar_t* StatusFilterName(StatusFilter filter);

// ---------------------------------------------------------------------------
// File and folder dialogs. Each returns "" when the user cancels.
// filter uses the OPENFILENAME format: L"Name (*.x)\0*.x\0".
// ---------------------------------------------------------------------------
std::wstring BrowseForFolder(HWND hParent, const wchar_t* title, const std::wstring& startFolder);
// The same picker with Ctrl and Shift selection. Empty when cancelled.
std::vector<std::wstring> BrowseForFolders(HWND hParent, const wchar_t* title, const std::wstring& startFolder);
std::wstring BrowseForOpenFile(HWND hParent, const wchar_t* title, const wchar_t* filter);
std::wstring BrowseForSaveFile(HWND hParent, const wchar_t* title, const wchar_t* filter,
                               const wchar_t* defaultExtension, const std::wstring& suggestedPath);

// Filters used by the commands.
extern const wchar_t kFilterCsv[];
extern const wchar_t kFilterBaseline[];
extern const wchar_t kFilterHtml[];
extern const wchar_t kFilterJson[];
extern const wchar_t kFilterText[];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
// Put text on the clipboard. False when the clipboard is busy.
bool CopyTextToClipboard(HWND hOwner, const std::wstring& text);

// Text of a window (edit, static) as a std::wstring.
std::wstring GetWindowTextString(HWND hWnd);

// Open Explorer with the file selected (or the folder when the file is gone).
void ShowFileInExplorer(const std::wstring& path);

// Open a folder or document with its default program.
void OpenWithShell(const std::wstring& path);

// "report-2026-10-26-1405" style stamp for default file names.
std::wstring FileTimeStamp();
