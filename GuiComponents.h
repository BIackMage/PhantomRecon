#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// GuiComponents — reusable Win32 GUI helpers for progress bar and results list
// ---------------------------------------------------------------------------

// Initialize common controls (call once at startup before creating windows)
void InitGuiCommonControls();

// ---------------------------------------------------------------------------
// Progress Bar
// ---------------------------------------------------------------------------

// Create a progress bar control inside the parent window
HWND CreateScanProgressBar(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height);

// Set the progress bar range (0 to max)
void SetProgressRange(HWND hProgressBar, int maxValue);

// Update the progress bar position
void SetProgressPosition(HWND hProgressBar, int position);

// Set progress bar to marquee mode (indeterminate — used when total count unknown)
void SetProgressMarquee(HWND hProgressBar, bool enable);

// ---------------------------------------------------------------------------
// Results ListView
// ---------------------------------------------------------------------------

// Create the results ListView with all columns
HWND CreateResultsListView(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height);

// Add a scan result row to the ListView
// Returns the row index, or -1 on failure.
int AddResultRow(HWND hListView, const BaselineEntry& entry, const std::wstring& status = L"");

// Clear all rows from the ListView
void ClearResultRows(HWND hListView);

// Set row color based on malware score (called from WM_NOTIFY / NM_CUSTOMDRAW)
// Returns the CDRF_ result for the custom draw handler.
LRESULT HandleResultsCustomDraw(LPARAM lParam);

// ---------------------------------------------------------------------------
// Directory / File Picker Dialogs
// ---------------------------------------------------------------------------

// Show a folder browse dialog and return the selected path.
// Returns empty string if user cancels.
std::wstring BrowseForScanDirectory(HWND hParent);

// Open File dialog filtered for CSV scan result files (.csv)
// Returns empty string if user cancels.
std::wstring BrowseForScanFile(HWND hParent);

// Open File dialog filtered for baseline files (.prbl)
// Returns empty string if user cancels.
std::wstring BrowseForBaselineFile(HWND hParent);

// Save File dialog for exporting a baseline (.prbl)
// Returns empty string if user cancels.
std::wstring SaveBaselineFileDialog(HWND hParent);

// ---------------------------------------------------------------------------
// CSV Scan Result Parser
// ---------------------------------------------------------------------------

// Parse a CSV scan result file and populate entries + statuses.
// Returns true if parsing succeeded (even if 0 rows).
bool ParseScanResultCSV(const std::wstring& filePath,
    std::vector<BaselineEntry>& outEntries,
    std::vector<std::wstring>& outStatuses);
