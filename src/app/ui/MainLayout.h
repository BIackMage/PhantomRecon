#pragma once

#include "AppState.h"

// ---------------------------------------------------------------------------
// MainLayout: the controls on the main window, where they go when the window
// is resized, and the labels that show live state. UI thread only.
//
//   +----------------+-----------------------+---------------+
//   | This PC        | Current operation     | Hardening     |
//   | (system info + | (scan state, counts,  | score  59     |
//   |  audit summary)|  current file)        | [Findings]    |
//   +----------------+-----------------------+---------------+
//   | progress bar ..................................  [Cancel] |
//   | Show: [filter]   Search: [.........]          123 of 456 |
//   | results list (owner data)                                |
//   +----------------------------------------------------------+
// ---------------------------------------------------------------------------

void CreateMainControls(AppState& app, HWND hWnd);

// Place every control for the current client size.
void LayoutMainControls(AppState& app);

// Theme colours on every control (after startup and on a theme change).
void ApplyThemeToMainWindow(AppState& app);

// The big score, its caption, and the audit progress while one runs.
void UpdateScoreDisplay(AppState& app);

// Text colour for the score number (WM_CTLCOLORSTATIC).
COLORREF ScoreColor(const AppState& app);

// The "Current operation" panel and the progress bar, from AppState::progress.
void RefreshOperationLabel(AppState& app);

// "123 of 456 rows" next to the search box.
void UpdateResultCount(AppState& app);
