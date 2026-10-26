#include "pch.h"
#include "AiSidebar.h"
#include "LLMClient.h"

#include <thread>
#include <sstream>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[AiSidebar] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// Convert std::string to std::wstring (UTF-8)
static std::wstring ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &result[0], size);
    return result;
}

static std::string ToUtf8(const std::wstring& s)
{
    if (s.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &result[0], size, NULL, NULL);
    return result;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const wchar_t* AI_PANEL_CLASS = L"PhantomRecon_AiPanel";
static const int TOGGLE_TAB_WIDTH = 28;
static const int SLIDE_STEP_MS = 10;   // timer interval for slide animation
static const int SLIDE_PX_STEP = 40;   // pixels per animation step
static const int PANEL_MARGIN = 8;     // inner margin inside the panel

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static LRESULT CALLBACK AiPanelWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static void LayoutPanelControls(AiSidebarState& state);
static RECT GetMainWindowScreenRect(HWND hMain);

// Timer ID for slide animation
#define IDT_SLIDE_ANIM 5001

// ---------------------------------------------------------------------------
// RegisterAiSidebarClass
// ---------------------------------------------------------------------------
void RegisterAiSidebarClass(HINSTANCE hInst)
{
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = AiPanelWndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 35));  // dark background
    wc.lpszClassName = AI_PANEL_CLASS;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    DebugLog(L"AI panel window class registered");
}

// ---------------------------------------------------------------------------
// Helper: get screen rect of the main window
// ---------------------------------------------------------------------------
static RECT GetMainWindowScreenRect(HWND hMain)
{
    RECT r = {};
    GetWindowRect(hMain, &r);
    return r;
}

// ---------------------------------------------------------------------------
// CreateAiSidebar
// ---------------------------------------------------------------------------
void CreateAiSidebar(HWND hMainWindow, HINSTANCE hInst, AiSidebarState& state)
{
    DebugLog(L"Creating AI sidebar");

    state.hMainWindow = hMainWindow;

    // --- Toggle tab: thin vertical button on the right edge of main window ---
    RECT clientRect;
    GetClientRect(hMainWindow, &clientRect);
    int tabX = clientRect.right - TOGGLE_TAB_WIDTH - 2;
    int tabY = clientRect.bottom / 2 - 50;  // centered vertically

    state.hToggleTab = CreateWindowW(L"BUTTON", L"AI\n>>",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_MULTILINE,
        tabX, tabY, TOGGLE_TAB_WIDTH, 100,
        hMainWindow, (HMENU)ID_AI_TOGGLE, hInst, NULL);

    DebugLog(L"Toggle tab created");

    // --- Slide-out panel: separate popup tool window ---
    RECT mainRect = GetMainWindowScreenRect(hMainWindow);
    int panelX = mainRect.right;   // starts hidden behind the right edge
    int panelY = mainRect.top;
    int panelH = mainRect.bottom - mainRect.top;

    state.hPanel = CreateWindowExW(
        WS_EX_TOOLWINDOW,          // no taskbar entry
        AI_PANEL_CLASS, L"",
        WS_POPUP | WS_BORDER,
        panelX, panelY, 0, panelH, // width 0 — hidden initially
        hMainWindow,                // owner
        NULL, hInst, NULL);

    if (!state.hPanel) {
        DebugLog(L"ERROR: Failed to create AI panel window");
        return;
    }

    // Store state pointer on the panel window for the WndProc
    SetWindowLongPtr(state.hPanel, GWLP_USERDATA, (LONG_PTR)&state);

    // --- Create child controls inside the panel ---
    int m = PANEL_MARGIN;
    int w = state.panelWidth - 2 * m;
    int btnH = 28;
    int y = m;

    // Title
    state.hTitleLabel = CreateWindowW(L"STATIC", L"  AI Assistant",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        m, y, w, 30,
        state.hPanel, (HMENU)ID_AI_TITLE, hInst, NULL);
    y += 34;

    // Status label
    state.hStatusLabel = CreateWindowW(L"STATIC", L"  Not connected",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        m, y, w, 18,
        state.hPanel, (HMENU)ID_AI_STATUS, hInst, NULL);
    y += 22;

    // Separator line (thin static)
    CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        m, y, w, 2,
        state.hPanel, NULL, hInst, NULL);
    y += 6;

    // Quick action buttons row
    int btnW = (w - 2 * 4) / 3;  // 3 buttons with 4px gaps
    state.hTriageButton = CreateWindowW(L"BUTTON", L"Triage",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        m, y, btnW, btnH,
        state.hPanel, (HMENU)ID_AI_TRIAGE, hInst, NULL);

    state.hSummaryButton = CreateWindowW(L"BUTTON", L"Summary",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        m + btnW + 4, y, btnW, btnH,
        state.hPanel, (HMENU)ID_AI_SUMMARY, hInst, NULL);

    state.hAuditButton = CreateWindowW(L"BUTTON", L"Audit",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        m + 2 * (btnW + 4), y, btnW, btnH,
        state.hPanel, (HMENU)ID_AI_AUDIT, hInst, NULL);
    y += btnH + 6;

    // Separator
    CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        m, y, w, 2,
        state.hPanel, NULL, hInst, NULL);
    y += 6;

    // Chat display — fills most of the remaining space
    // We'll compute height based on panel height later in LayoutPanelControls
    state.hChatDisplay = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN,
        m, y, w, 300,  // placeholder height, will be recalculated
        state.hPanel, (HMENU)ID_AI_CHAT, hInst, NULL);
    y += 300 + 4;

    // Input field + Send button at the bottom
    int sendW = 55;
    int inputW = w - sendW - 4;
    state.hInputField = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        m, y, inputW, btnH,
        state.hPanel, (HMENU)ID_AI_INPUT, hInst, NULL);

    state.hSendButton = CreateWindowW(L"BUTTON", L"Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        m + inputW + 4, y, sendW, btnH,
        state.hPanel, (HMENU)ID_AI_SEND, hInst, NULL);

    state.expanded = false;

    DebugLog(L"AI sidebar panel created (collapsed)");

    // Test LLM connection in background
    AiSidebarState* pState = &state;
    std::thread([pState]() {
        DebugLog(L"Testing LLM connection...");
        bool connected = GetLLMClient().TestConnection();
        if (connected) {
            SetAiStatusText(*pState, L"  Connected (Eva Qwen)");
            DebugLog(L"LLM connection successful");
        }
        else {
            std::string err = GetLLMClient().GetLastError();
            SetAiStatusText(*pState, L"  Connection failed");
            DebugLog((L"LLM connection failed: " + ToWide(err)).c_str());
        }
    }).detach();
}

// ---------------------------------------------------------------------------
// AiPanelWndProc — handles messages for the popup panel window
// ---------------------------------------------------------------------------
static LRESULT CALLBACK AiPanelWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    AiSidebarState* pState = (AiSidebarState*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

    switch (msg)
    {
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        // Forward button clicks to the main window so WndProc handles them
        if (pState && pState->hMainWindow) {
            SendMessageW(pState->hMainWindow, WM_COMMAND, wParam, lParam);
        }
        return 0;
    }

    case WM_TIMER:
    {
        if (wParam != IDT_SLIDE_ANIM || !pState) break;

        RECT mainRect = GetMainWindowScreenRect(pState->hMainWindow);
        RECT panelRect;
        GetWindowRect(hWnd, &panelRect);
        int currentW = panelRect.right - panelRect.left;

        if (pState->expanded) {
            // Expanding: grow width toward target
            int targetW = pState->panelWidth;
            int newW = currentW + SLIDE_PX_STEP;
            if (newW >= targetW) {
                newW = targetW;
                KillTimer(hWnd, IDT_SLIDE_ANIM);
                DebugLog(L"Slide-out animation complete");
            }
            SetWindowPos(hWnd, NULL,
                mainRect.right, mainRect.top,
                newW, mainRect.bottom - mainRect.top,
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        else {
            // Collapsing: shrink width toward 0
            int newW = currentW - SLIDE_PX_STEP;
            if (newW <= 0) {
                newW = 0;
                KillTimer(hWnd, IDT_SLIDE_ANIM);
                ShowWindow(hWnd, SW_HIDE);
                DebugLog(L"Slide-in animation complete");
            }
            SetWindowPos(hWnd, NULL,
                mainRect.right, mainRect.top,
                newW, mainRect.bottom - mainRect.top,
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    {
        // Dark theme for static controls
        HDC hdcStatic = (HDC)wParam;
        SetTextColor(hdcStatic, RGB(220, 220, 225));
        SetBkColor(hdcStatic, RGB(30, 30, 35));
        static HBRUSH hBrush = CreateSolidBrush(RGB(30, 30, 35));
        return (LRESULT)hBrush;
    }

    case WM_CTLCOLOREDIT:
    {
        // Dark theme for edit controls
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, RGB(210, 210, 215));
        SetBkColor(hdcEdit, RGB(45, 45, 50));
        static HBRUSH hBrushEdit = CreateSolidBrush(RGB(45, 45, 50));
        return (LRESULT)hBrushEdit;
    }
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// LayoutPanelControls — recalculate chat display height based on panel size
// ---------------------------------------------------------------------------
static void LayoutPanelControls(AiSidebarState& state)
{
    if (!state.hPanel) return;

    RECT panelClient;
    GetClientRect(state.hPanel, &panelClient);
    int panelH = panelClient.bottom;
    int m = PANEL_MARGIN;
    int w = state.panelWidth - 2 * m;
    int btnH = 28;

    // Calculate positions top-down to find where chat starts
    int y = m;
    y += 34;    // title
    y += 22;    // status
    y += 6;     // separator
    y += btnH + 6; // quick action buttons
    y += 6;     // separator
    int chatTop = y;

    // Bottom row: input + send
    int bottomY = panelH - m - btnH;
    int chatHeight = bottomY - chatTop - 4;
    if (chatHeight < 50) chatHeight = 50;

    // Reposition chat display
    SetWindowPos(state.hChatDisplay, NULL, m, chatTop, w, chatHeight, SWP_NOZORDER);

    // Reposition input field and send button
    int sendW = 55;
    int inputW = w - sendW - 4;
    SetWindowPos(state.hInputField, NULL, m, bottomY, inputW, btnH, SWP_NOZORDER);
    SetWindowPos(state.hSendButton, NULL, m + inputW + 4, bottomY, sendW, btnH, SWP_NOZORDER);
}

// ---------------------------------------------------------------------------
// ToggleAiSidebar
// ---------------------------------------------------------------------------
void ToggleAiSidebar(AiSidebarState& state)
{
    state.expanded = !state.expanded;
    DebugLog(state.expanded ? L"Sidebar expanding" : L"Sidebar collapsing");

    // Update toggle tab text
    SetWindowTextW(state.hToggleTab, state.expanded ? L"AI\n<<" : L"AI\n>>");

    if (state.expanded) {
        // Position at main window right edge, zero width, full height
        RECT mainRect = GetMainWindowScreenRect(state.hMainWindow);
        SetWindowPos(state.hPanel, NULL,
            mainRect.right, mainRect.top,
            0, mainRect.bottom - mainRect.top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        ShowWindow(state.hPanel, SW_SHOWNOACTIVATE);

        // Layout controls for the target height
        LayoutPanelControls(state);
    }

    // Start slide animation
    SetTimer(state.hPanel, IDT_SLIDE_ANIM, SLIDE_STEP_MS, NULL);
}

// ---------------------------------------------------------------------------
// RepositionAiSidebar — keep sidebar flush with main window right edge
// ---------------------------------------------------------------------------
void RepositionAiSidebar(AiSidebarState& state)
{
    if (!state.hPanel || !state.hMainWindow) return;

    // Reposition the toggle tab on the main window's right edge
    RECT clientRect;
    GetClientRect(state.hMainWindow, &clientRect);
    int tabX = clientRect.right - TOGGLE_TAB_WIDTH - 2;
    int tabY = clientRect.bottom / 2 - 50;
    SetWindowPos(state.hToggleTab, NULL, tabX, tabY, TOGGLE_TAB_WIDTH, 100, SWP_NOZORDER);

    if (!state.expanded) return;

    // Reposition the panel flush with the main window right edge
    RECT mainRect = GetMainWindowScreenRect(state.hMainWindow);
    RECT panelRect;
    GetWindowRect(state.hPanel, &panelRect);
    int currentW = panelRect.right - panelRect.left;

    SetWindowPos(state.hPanel, NULL,
        mainRect.right, mainRect.top,
        currentW, mainRect.bottom - mainRect.top,
        SWP_NOZORDER | SWP_NOACTIVATE);

    // Re-layout controls if panel height changed
    LayoutPanelControls(state);
}

// ---------------------------------------------------------------------------
// AppendToChatDisplay
// ---------------------------------------------------------------------------
void AppendToChatDisplay(AiSidebarState& state, const std::wstring& text)
{
    if (!state.hChatDisplay) return;

    int len = GetWindowTextLengthW(state.hChatDisplay);
    SendMessageW(state.hChatDisplay, EM_SETSEL, len, len);
    SendMessageW(state.hChatDisplay, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(state.hChatDisplay, EM_SCROLLCARET, 0, 0);
}

// ---------------------------------------------------------------------------
// ClearChatDisplay
// ---------------------------------------------------------------------------
void ClearChatDisplay(AiSidebarState& state)
{
    if (state.hChatDisplay) {
        SetWindowTextW(state.hChatDisplay, L"");
    }
}

// ---------------------------------------------------------------------------
// SetAiStatusText
// ---------------------------------------------------------------------------
void SetAiStatusText(AiSidebarState& state, const std::wstring& text)
{
    if (state.hStatusLabel) {
        SetWindowTextW(state.hStatusLabel, text.c_str());
    }
}

// ---------------------------------------------------------------------------
// GetAiSidebarWidth
// ---------------------------------------------------------------------------
int GetAiSidebarWidth(const AiSidebarState& state)
{
    return state.expanded ? state.panelWidth : 0;
}

// ---------------------------------------------------------------------------
// SendUserMessage
// ---------------------------------------------------------------------------
void SendUserMessage(AiSidebarState& state, const std::wstring& message)
{
    if (message.empty()) return;

    DebugLog((L"Sending user message: " + message).c_str());

    AppendToChatDisplay(state, L"\r\n[You]: " + message + L"\r\n");
    SetAiStatusText(state, L"  Thinking...");
    SetWindowTextW(state.hInputField, L"");

    std::string userMsg = ToUtf8(message);
    AiSidebarState* pState = &state;

    std::thread([pState, userMsg]() {
        std::vector<LLMMessage> messages = {
            { "system", "You are a cybersecurity threat analyst assistant integrated into "
              "Phantom Recon, an endpoint security scanner. You help triage scan results, "
              "analyze malware indicators, and provide actionable security recommendations. "
              "Be concise and technical. Focus on actionable intel." },
            { "user", userMsg }
        };

        std::string response = GetLLMClient().SendChatCompletion(messages);

        if (response.empty()) {
            std::string err = GetLLMClient().GetLastError();
            AppendToChatDisplay(*pState, L"\r\n[AI Error]: " + ToWide(err) + L"\r\n");
            SetAiStatusText(*pState, L"  Error");
        }
        else {
            AppendToChatDisplay(*pState, L"\r\n[AI]: " + ToWide(response) + L"\r\n");
            SetAiStatusText(*pState, L"  Ready");
        }
    }).detach();
}

// ---------------------------------------------------------------------------
// TriageSelectedFile
// ---------------------------------------------------------------------------
void TriageSelectedFile(AiSidebarState& state, const BaselineEntry& entry)
{
    DebugLog((L"Triaging file: " + entry.path).c_str());

    AppendToChatDisplay(state, L"\r\n[Triage]: Analyzing " + entry.path + L"...\r\n");
    SetAiStatusText(state, L"  Analyzing file...");

    std::string prompt = BuildTriagePrompt(entry.path, entry.malwareScore,
        entry.signature, entry.packingStatus, entry.suspiciousImports,
        entry.sigWarnings, entry.packIndicators, entry.entropy);

    AiSidebarState* pState = &state;

    std::thread([pState, prompt]() {
        std::vector<LLMMessage> messages = {
            { "system", "You are a cybersecurity threat analyst assistant. "
              "Analyze the following file scan result and provide a detailed threat assessment. "
              "Be technical, concise, and actionable." },
            { "user", prompt }
        };

        std::string response = GetLLMClient().SendChatCompletion(messages);

        if (response.empty()) {
            std::string err = GetLLMClient().GetLastError();
            AppendToChatDisplay(*pState, L"\r\n[AI Error]: " + ToWide(err) + L"\r\n");
            SetAiStatusText(*pState, L"  Error");
        }
        else {
            AppendToChatDisplay(*pState, L"\r\n[AI Triage]:\r\n" + ToWide(response) + L"\r\n");
            SetAiStatusText(*pState, L"  Ready");
        }
    }).detach();
}
