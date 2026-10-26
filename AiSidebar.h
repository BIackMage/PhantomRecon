#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "BackgroundWorker.h"
#include "ScanCore.h"
#include "ScanTypes.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// AiSidebar: slide-out AI triage panel.
//
// The sidebar is a separate WS_EX_TOOLWINDOW popup that sits flush against the
// right edge of the main window. It slides out/in with animation and tracks the
// main window's position when it moves or resizes. A thin vertical toggle tab on
// the main window's right edge opens and closes it.
//
// Threading: every LLM call runs on the shared BackgroundWorker and posts a
// WM_APP_AI_RESPONSE to the panel window. Only AiPanelWndProc touches the
// controls. See CLAUDE.md.
//
// Privacy: before anything is sent to an endpoint that is not on this machine,
// the user is asked once per session. See ConfirmSendAllowed in AiSidebar.cpp.
// ---------------------------------------------------------------------------

struct AiSidebarState {
    bool expanded = false;          // starts collapsed
    int  panelWidth = 380;          // width of the slide-out panel
    HWND hMainWindow = NULL;        // parent / owner
    HWND hPanel = NULL;             // the popup tool window
    HWND hToggleTab = NULL;         // thin tab button on main window right edge
    HWND hChatDisplay = NULL;       // multi-line read-only chat area
    HWND hInputField = NULL;        // user text input
    HWND hSendButton = NULL;        // send button
    HWND hTriageButton = NULL;      // quick action: triage selected file
    HWND hSummaryButton = NULL;     // quick action: scan summary
    HWND hAuditButton = NULL;       // quick action: security audit analysis
    HWND hStatusLabel = NULL;       // connection status text
    HWND hTitleLabel = NULL;        // panel title label

    BackgroundWorker* worker = nullptr;  // owned by AppState; set by CreateAiSidebar
    bool remoteSendApproved = false;     // user said yes to a non-local endpoint this session
};

// Register the sidebar window class (call once at startup).
void RegisterAiSidebarClass(HINSTANCE hInst);

// Create the sidebar panel and the toggle tab on the main window.
void CreateAiSidebar(HWND hMainWindow, HINSTANCE hInst, AiSidebarState& state, BackgroundWorker& worker);

// Toggle the sidebar open/closed with slide animation.
void ToggleAiSidebar(AiSidebarState& state);

// Reposition the sidebar to stay flush with the main window. Call from WM_MOVE / WM_SIZE.
void RepositionAiSidebar(AiSidebarState& state);

// Append text to the chat display. UI thread only.
void AppendToChatDisplay(AiSidebarState& state, const std::wstring& text);

// Clear the chat display. UI thread only.
void ClearChatDisplay(AiSidebarState& state);

// Set the connection status text. UI thread only.
void SetAiStatusText(AiSidebarState& state, const std::wstring& text);

// Current width of the sidebar (0 if collapsed).
int GetAiSidebarWidth(const AiSidebarState& state);

// Send a typed message to the LLM and display the response when it arrives.
void SendUserMessage(AiSidebarState& state, const std::wstring& message);

// Quick action: triage one file from the scan results (every field on the row).
void TriageSelectedFile(AiSidebarState& state, const ScanRow& row);

// Quick action: summarise the last scan.
void RequestScanSummary(AiSidebarState& state, const ScanSummary& summary, const std::wstring& title);

// Quick action: explain every failed or warned audit check. Long findings are
// sent in parts of at most maxPartChars characters, one reply per part.
void RequestAuditAnalysis(AiSidebarState& state, const std::vector<SecurityCheckResult>& results, size_t maxPartChars);

// Re-colour the panel after a theme change.
void ApplyThemeToAiSidebar(AiSidebarState& state);

// Control IDs for sidebar widgets
#define ID_AI_TOGGLE     2001
#define ID_AI_SEND       2002
#define ID_AI_INPUT      2003
#define ID_AI_TRIAGE     2004
#define ID_AI_SUMMARY    2005
#define ID_AI_AUDIT      2006
#define ID_AI_CHAT       2007
#define ID_AI_STATUS     2008
#define ID_AI_TITLE      2009
