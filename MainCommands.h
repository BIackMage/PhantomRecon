#pragma once

#include <windows.h>
#include "AppState.h"

// ---------------------------------------------------------------------------
// MainCommands: one function per WM_COMMAND id. All run on the UI thread.
//   MainCommands.cpp     File and Scans menus, and the dispatcher
//   ReportCommands.cpp   Audit, Reports and Help menus
//   ResultsCommands.cpp  Results menu, the list's filter and search, the AI panel
// ---------------------------------------------------------------------------

// Route a command id to its handler. Returns false if the id is not ours.
// notifyCode is HIWORD(wParam) (edit and combo box notifications).
bool DispatchCommand(AppState& app, HWND hWnd, int commandId, int notifyCode);

// Each module's own table. False when the id is not in it.
bool DispatchFileScanCommand(AppState& app, HWND hWnd, int commandId);
bool DispatchReportCommand(AppState& app, HWND hWnd, int commandId);
bool DispatchResultsCommand(AppState& app, HWND hWnd, int commandId, int notifyCode);

// Help > Create Sample Pack (also offered by the Getting Started window).
void CreateSamplePackAndScan(AppState& app, HWND hWnd);

// Write the sample pack into folder (new or empty), make its demo baseline active
// for this session and run a Full Scan of it. askBeforeScan shows a Yes/No first.
void CreateSamplePackInFolder(AppState& app, HWND hWnd, const std::wstring& folder, bool askBeforeScan);

// File > Open Scan Results and File > Open Baseline, for a path already chosen
// (the command line, or a file dropped on the program). False when it failed;
// the user has been told why.
bool OpenScanResultsFile(AppState& app, HWND hWnd, const std::wstring& csvPath);
bool OpenBaselineFile(AppState& app, HWND hWnd, const std::wstring& path, bool confirm);

// Enable, disable and tick menu items to match the current state (WM_INITMENUPOPUP).
void UpdateMenuState(AppState& app, HMENU menu);
