#pragma once

#include <string>
#include <vector>
#include "AppState.h"
#include "ScanCore.h"
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// ScanEngine: the GUI's bridge to RunScan (ScanCore.cpp).
//
// StartScanInBackground is called on the UI thread. It resets the progress
// state, clears the results, starts the progress bar and hands RunScan to
// AppState::worker. RunScan's callbacks only write AppState::progress and post
// WM_APP_* messages. Nothing on the scan thread touches a window.
// ---------------------------------------------------------------------------

struct ScanRequest {
    ScanMode     mode = ScanMode::FullScan;
    std::vector<std::wstring> roots;   // folders for Baseline and Full; ignored for Fast
    std::wstring csvPath;           // may be empty (no CSV)
    std::wstring baselinePath;      // Baseline: where to save. Full/Fast: the file loaded into currentBaseline
    ScanOptions  options;
    std::wstring title;             // "Full Scan of C:\Program Files", for reports
};

// Start a scan on the worker. Does nothing if a scan is already running.
// For Full and Fast the caller must have loaded AppState::currentBaseline.
void StartScanInBackground(AppState& app, const ScanRequest& request);

// "Baseline Scan Running..." style label for the operation panel.
std::wstring ScanStateLabel(ScanMode mode);
