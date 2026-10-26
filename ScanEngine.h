#pragma once

#include <string>
#include "AppState.h"
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// ScanEngine: everything that happens on the scan thread.
//
// StartScanInBackground is called on the UI thread. It resets the progress
// state, clears the list view, starts the marquee and hands the walk to
// AppState::worker. From then on the scan thread only writes to
// AppState::progress and posts WM_APP_* messages. It never touches a window.
// ---------------------------------------------------------------------------

// Run every analysis pass on one file. Thread-safe, no UI.
BaselineEntry AnalyzeFile(const std::wstring& fullPath);

// True for the 28 extensions that can carry or execute code on Windows.
bool IsExecutableExtension(const std::wstring& fileName);

// MATCH / NEW / CHANGED / MISSING.
std::wstring BaselineStatusToString(BaselineStatus status);

// Append one baseline-mode row (22 columns) to the CSV. Writes the header when the file is new.
void WriteCsvRow(const std::wstring& outputPath, const BaselineEntry& entry);

// Append one comparison row (22 columns + status, change details, risk delta).
void WriteCsvRowWithComparison(const std::wstring& outputPath, const BaselineEntry& entry,
                               const ComparisonResult& comparison);

// Start a scan on the worker. For FastScan the directory is ignored. Does nothing if a scan
// is already running. Callers must have loaded AppState::currentBaseline for Full and Fast.
void StartScanInBackground(AppState& app, ScanMode mode, const std::wstring& directory);
