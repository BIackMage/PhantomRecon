#pragma once

#include <string>
#include "AppState.h"
#include "Reports.h"

// ---------------------------------------------------------------------------
// CommandHelpers: small pieces several command modules share. UI thread only.
// ---------------------------------------------------------------------------

// True (and tells the user) when a scan is running and the command must wait.
bool RefuseWhileScanning(AppState& app, HWND hWnd, const wchar_t* what);

// Load the active baseline for a comparison scan and warn when it is stale.
// False when there is no usable baseline or the user declined a stale one.
bool LoadBaselineForComparison(AppState& app, HWND hWnd, const wchar_t* scanName);

// Replace the rows in the results list (keeps filter, search and sort).
void ShowRows(AppState& app, std::vector<ScanRow> rows);

// The selected row, or null.
const ScanRow* SelectedRow(AppState& app);

// The facts every report carries: host, the last audit and the last scan.
ReportData BuildReportData(AppState& app);

// Default path for a new report: <reports folder>\<stem>-<time>.<ext>.
std::wstring DefaultReportPath(AppState& app, const std::wstring& stem, const std::wstring& extension);
