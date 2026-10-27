#pragma once

#include "AppState.h"

// ---------------------------------------------------------------------------
// DetailWindow: everything known about one result row, in plain words, with
// buttons to copy it, copy the SHA-256 and show the file in Explorer.
// Modeless and single: opening another row reuses the same window.
// UI thread only. AppState::detailWindow holds the handle while it is open.
// ---------------------------------------------------------------------------

void ShowRowDetailWindow(AppState& app, const ScanRow& row);
