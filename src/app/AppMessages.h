#pragma once

#include <windows.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "AuditHistory.h"
#include "HardeningScore.h"
#include "ScanCore.h"
#include "ScanTypes.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// AppMessages: the only way a background thread talks to the UI.
//
// A worker allocates a payload with new, then calls PostPayload(). The handler
// on the UI thread takes it with TakePayload() and deletes it. If the post fails
// (window gone), PostPayload deletes it on the spot. If the post succeeds but the
// window is destroyed before the message is handled, Windows drops the message
// with the window; the PayloadTracker still holds the payload and frees it when
// that window gets WM_NCDESTROY, or at exit. Never SendMessage these: a worker
// blocked in SendMessage while the UI thread joins workers at exit is a deadlock.
// ---------------------------------------------------------------------------

enum AppMessage : UINT {
    // Main window. No payload. Handler drains AppState::progress.pendingRows into the results model.
    WM_APP_SCAN_ROWS = WM_APP + 1,

    // Main window. No payload. Handler re-reads AppState::progress and repaints the label and bar.
    WM_APP_SCAN_PROGRESS = WM_APP + 2,

    // Main window. lParam = ScanFinishedPayload*.
    WM_APP_SCAN_FINISHED = WM_APP + 3,

    // Main window. lParam = AuditFinishedPayload*.
    WM_APP_AUDIT_FINISHED = WM_APP + 4,

    // AI sidebar panel window. lParam = AiResponsePayload*.
    WM_APP_AI_RESPONSE = WM_APP + 5,

    // Any window with a status label. lParam = std::wstring*.
    WM_APP_STATUS_TEXT = WM_APP + 6,

    // Main window. No payload. Handler re-reads AppState::audit progress.
    WM_APP_AUDIT_PROGRESS = WM_APP + 7,

    // Main window. No payload. Posted once by CreateMainWindow so first-run UI
    // appears after the window is on screen and the message loop is running.
    WM_APP_STARTUP = WM_APP + 8,
};

// Sent once when a scan thread exits, for any reason.
struct ScanFinishedPayload {
    std::wstring finalState;                 // text for the "Current Scan State" line
    bool         showDialog = false;
    std::wstring dialogTitle;
    std::wstring dialogText;
    UINT         dialogIcon = MB_ICONINFORMATION;
    ScanSummary  summary;
    std::wstring title;                      // "Full Scan of C:\Program Files"
};

// Sent once when the posture audit finishes.
struct AuditFinishedPayload {
    std::vector<SecurityCheckResult> results;
    HardeningScore                   score;
    std::wstring                     panelText;   // system info + summary for the left panel
    std::wstring                     finishedAt;  // local time
    bool                             cancelled = false;
    std::wstring                     error;       // set when the audit stopped on an internal error

    // Audit history, compared on the audit thread (AuditHistory.h). hasHistory is false
    // when history is off, the audit was cancelled, or the file could not be read.
    bool                     hasHistory = false;
    AuditComparison          history;
    std::vector<AuditRecord> historyRecords;      // recent records for the report chart
    std::wstring             historyError;        // why the file could not be read or written
};

// Sent once per LLM request when the response (or error) is in.
struct AiResponsePayload {
    std::wstring chatText;    // appended to the chat display
    std::wstring statusText;  // written to the status label
};

// True for the messages above that carry a heap payload in lParam.
bool HasAppPayload(UINT message);

// Delete the payload of one of those messages, by its type.
void DeleteAppPayload(UINT message, LPARAM lParam);

// Every payload between its post and its handler. One instance lives in AppState;
// the AI panel and the Settings dialog get a pointer to it. Thread-safe.
class PayloadTracker {
public:
    PayloadTracker() = default;
    ~PayloadTracker();
    PayloadTracker(const PayloadTracker&) = delete;
    PayloadTracker& operator=(const PayloadTracker&) = delete;

    // The worker is about to post payload to target.
    void Posted(HWND target, UINT message, LPARAM payload);

    // Take ownership: true when the payload was still tracked, and the caller
    // must now delete it. False when it was already freed here.
    bool Claim(LPARAM payload);

    // The window is being destroyed (WM_NCDESTROY): messages already posted to it
    // will never be handled. Frees their payloads. Returns how many.
    int FreeFor(HWND target);

    // After the workers are joined: frees everything never handled. Returns how many.
    int FreeRemaining();

private:
    struct Entry { HWND target; UINT message; };
    std::mutex              m_mutex;
    std::map<LPARAM, Entry> m_live;
};

// Post a heap payload to a window. Deletes the payload if the post cannot happen.
template <typename T>
inline void PostPayload(HWND hWnd, UINT message, T* payload, PayloadTracker& tracker)
{
    LPARAM lp = reinterpret_cast<LPARAM>(payload);
    tracker.Posted(hWnd, message, lp);
    if (!hWnd || !PostMessageW(hWnd, message, 0, lp)) {
        // FreeFor may already have freed it if the window died in between.
        if (tracker.Claim(lp)) {
            OutputDebugStringW((L"[AppMessages] Post of message " + std::to_wstring(message) +
                                L" failed (window gone); payload freed\n").c_str());
            delete payload;
        }
    }
}

// In a handler: own the payload of the message being handled, or null when it
// was already freed. With no tracker the handler simply owns it.
template <typename T>
inline std::unique_ptr<T> TakePayload(PayloadTracker* tracker, LPARAM lParam)
{
    if (!lParam) return nullptr;
    if (tracker && !tracker->Claim(lParam)) return nullptr;
    return std::unique_ptr<T>(reinterpret_cast<T*>(lParam));
}
