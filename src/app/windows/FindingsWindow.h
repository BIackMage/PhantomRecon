#pragma once

#include "AppState.h"

// ---------------------------------------------------------------------------
// FindingsWindow: every security check with its status, what it means, the
// exact fix and how to undo it. Shows problems first; a filter shows all
// checks. The five fixes that raise the score most (BiggestWins.h) are marked
// "#1 +7" in the Top fix column and come first among the problems. Before the
// first audit finishes it lists the whole catalog as
// "not run yet". Modeless and single. UI thread only.
// ---------------------------------------------------------------------------

// Create the window, or bring it to the front.
void ShowFindingsWindow(AppState& app);

// Reload from AppState::audit after a new audit. Does nothing when closed.
void RefreshFindingsWindow(AppState& app);
