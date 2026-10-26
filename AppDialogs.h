#pragma once

#include <windows.h>

// ---------------------------------------------------------------------------
// AppDialogs: the two small resource dialogs (About and Getting Started).
// ---------------------------------------------------------------------------

// Help > About.
void ShowAboutDialog(HWND hParent, HINSTANCE hInst);

struct GettingStartedResult {
    bool showAtStartup = true;     // the check box when the dialog closed
    bool createSamples = false;    // the user pressed Create Sample Pack
};

// Help > Getting Started, and the first-run window.
GettingStartedResult ShowGettingStarted(HWND hParent, HINSTANCE hInst, bool showAtStartup);
