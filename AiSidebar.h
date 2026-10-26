#pragma once

#include <windows.h>
#include <string>
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// AiSidebar — modern slide-out AI triage panel.
//
// The sidebar is a separate WS_EX_TOOLWINDOW popup that sits flush against the
// right edge of the main window.  It slides out/in with animation and tracks
// the main window's position when it moves or resizes.
//
// A thin vertical toggle tab lives on the right edge of the main window's
// client area so the user always has a visible handle to open/close the panel.
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
};

// Register the sidebar window class (call once at startup)
void RegisterAiSidebarClass(HINSTANCE hInst);

// Create the sidebar panel and the toggle tab on the main window.
void CreateAiSidebar(HWND hMainWindow, HINSTANCE hInst, AiSidebarState& state);

// Toggle the sidebar open/closed with slide animation.
void ToggleAiSidebar(AiSidebarState& state);

// Reposition the sidebar to stay flush with the main window.
// Call this from WM_MOVE and WM_SIZE handlers.
void RepositionAiSidebar(AiSidebarState& state);

// Append text to the chat display
void AppendToChatDisplay(AiSidebarState& state, const std::wstring& text);

// Clear the chat display
void ClearChatDisplay(AiSidebarState& state);

// Set the connection status text
void SetAiStatusText(AiSidebarState& state, const std::wstring& text);

// Get the current width of the sidebar (0 if collapsed)
int GetAiSidebarWidth(const AiSidebarState& state);

// Send a user message to the LLM (async) and display the response
void SendUserMessage(AiSidebarState& state, const std::wstring& message);

// Quick action: triage a specific file from scan results
void TriageSelectedFile(AiSidebarState& state, const BaselineEntry& entry);

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
