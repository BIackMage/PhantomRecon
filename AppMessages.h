#pragma once

#include <windows.h>
#include <string>
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// AppMessages: the only way a background thread talks to the UI.
//
// A worker allocates a payload with new, then calls PostPayload(). The handler
// on the UI thread reads it and deletes it. If the post fails (window gone),
// PostPayload deletes it on the spot so nothing leaks. Never SendMessage these:
// a worker blocked in SendMessage while the UI thread joins workers at exit is
// a deadlock.
// ---------------------------------------------------------------------------

enum AppMessage : UINT {
    // Main window. No payload. Handler drains AppState::progress.pendingRows into the list view.
    WM_APP_SCAN_ROWS = WM_APP + 1,

    // Main window. No payload. Handler re-reads AppState::progress and repaints the label.
    WM_APP_SCAN_PROGRESS = WM_APP + 2,

    // Main window. lParam = ScanFinishedPayload*.
    WM_APP_SCAN_FINISHED = WM_APP + 3,

    // Main window. lParam = std::wstring* holding the full system info panel text.
    WM_APP_AUDIT_FINISHED = WM_APP + 4,

    // AI sidebar panel window. lParam = AiResponsePayload*.
    WM_APP_AI_RESPONSE = WM_APP + 5,

    // Any window with a status label. lParam = std::wstring*.
    WM_APP_STATUS_TEXT = WM_APP + 6,
};

// One finished row for the results list view.
struct ScanRow {
    BaselineEntry entry;
    std::wstring  status;   // BASELINE, MATCH, NEW, CHANGED, MISSING
};

// Sent once when a scan thread exits, for any reason.
struct ScanFinishedPayload {
    std::wstring finalState;                 // text for the "Current Scan State" line
    bool         showDialog = false;
    std::wstring dialogTitle;
    std::wstring dialogText;
    UINT         dialogIcon = MB_ICONINFORMATION;
};

// Sent once per LLM request when the response (or error) is in.
struct AiResponsePayload {
    std::wstring chatText;    // appended to the chat display
    std::wstring statusText;  // written to the status label
};

// Post a heap payload to a window. Deletes the payload if the post cannot happen.
template <typename T>
inline void PostPayload(HWND hWnd, UINT message, T* payload)
{
    if (!hWnd || !PostMessageW(hWnd, message, 0, reinterpret_cast<LPARAM>(payload))) {
        delete payload;
    }
}
