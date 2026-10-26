#include "pch.h"
#include "AiSidebar.h"

#include "AppMessages.h"
#include "DetailText.h"
#include "LLMClient.h"
#include "Redactor.h"
#include "StringConv.h"
#include "TextUtils.h"
#include "Theme.h"

#include <memory>
#include <sstream>
#include <vector>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[AiSidebar] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const wchar_t* AI_PANEL_CLASS = L"PhantomRecon_AiPanel";
static const int TOGGLE_TAB_WIDTH = 28;
static const int SLIDE_STEP_MS = 10;   // timer interval for slide animation
static const int SLIDE_PX_STEP = 40;   // pixels per animation step
static const int PANEL_MARGIN = 8;     // inner margin inside the panel

#define IDT_SLIDE_ANIM 5001

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static LRESULT CALLBACK AiPanelWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static void LayoutPanelControls(AiSidebarState& state);
static RECT GetMainWindowScreenRect(HWND hMain);

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
    wc.hbrBackground = NULL;   // WM_ERASEBKGND paints the theme colour
    wc.lpszClassName = AI_PANEL_CLASS;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    DebugLog(L"AI panel window class registered");
}

static RECT GetMainWindowScreenRect(HWND hMain)
{
    RECT r = {};
    GetWindowRect(hMain, &r);
    return r;
}

// ---------------------------------------------------------------------------
// Privacy gate
//
// The default endpoint is localhost, so nothing leaves the machine. If the user
// pointed Settings at another host, say so plainly and ask once per session.
// ---------------------------------------------------------------------------
static bool ConfirmSendAllowed(AiSidebarState& state)
{
    std::wstring endpoint = GetLLMClient().GetConfig().endpoint;
    if (IsLoopbackEndpoint(endpoint)) {
        return true;
    }
    if (state.remoteSendApproved) {
        return true;
    }

    std::wstring text =
        L"The AI endpoint is not on this machine:\n\n" + endpoint + L"\n\n"
        L"Scan data will be sent there. That includes file paths, which can contain "
        L"user names and other details about this host.\n\n"
        L"Send anyway? You will not be asked again this session.";
    int answer = MessageBoxW(state.hMainWindow, text.c_str(), L"Send scan data to a remote server?",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (answer != IDYES) {
        AppendToChatDisplay(state, L"\r\n[Info]: Not sent. Change the endpoint in File > Settings to a local server, or approve the remote one.\r\n");
        return false;
    }

    state.remoteSendApproved = true;
    DebugLog(L"User approved sending to a remote endpoint for this session");
    return true;
}

// ---------------------------------------------------------------------------
// Worker plumbing: run one chat completion, post the result to the panel
// ---------------------------------------------------------------------------
static void RunLlmRequest(AiSidebarState& state, const std::vector<LLMMessage>& messages,
                          const std::wstring& successPrefix)
{
    if (!state.worker) {
        AppendToChatDisplay(state, L"\r\n[AI Error]: background worker not available.\r\n");
        return;
    }

    HWND hPanel = state.hPanel;
    state.worker->Run([hPanel, messages, successPrefix]() {
        std::string response = GetLLMClient().SendChatCompletion(messages);

        AiResponsePayload* payload = new AiResponsePayload();
        if (response.empty()) {
            payload->chatText = L"\r\n[AI Error]: " + Utf8ToWide(GetLLMClient().GetLastError()) + L"\r\n";
            payload->statusText = L"  Error";
        }
        else {
            payload->chatText = successPrefix + ToWindowsLineEnds(Utf8ToWide(response)) + L"\r\n";
            payload->statusText = L"  Ready";
        }
        PostPayload(hPanel, WM_APP_AI_RESPONSE, payload);
    });
}

// Probe the endpoint once at startup. Sends no scan data, so no consent needed.
static void TestConnectionInBackground(AiSidebarState& state)
{
    if (!state.worker) return;

    HWND hPanel = state.hPanel;
    state.worker->Run([hPanel]() {
        DebugLog(L"Testing LLM connection...");
        bool connected = GetLLMClient().TestConnection();

        AiResponsePayload* payload = new AiResponsePayload();
        if (connected) {
            payload->statusText = L"  Connected (" + Utf8ToWide(GetLLMClient().GetConfig().model) + L")";
            DebugLog(L"LLM connection successful");
        }
        else {
            payload->statusText = L"  Connection failed";
            DebugLog((L"LLM connection failed: " + Utf8ToWide(GetLLMClient().GetLastError())).c_str());
        }
        PostPayload(hPanel, WM_APP_AI_RESPONSE, payload);
    });
}

// ---------------------------------------------------------------------------
// CreateAiSidebar
// ---------------------------------------------------------------------------
void CreateAiSidebar(HWND hMainWindow, HINSTANCE hInst, AiSidebarState& state, BackgroundWorker& worker)
{
    DebugLog(L"Creating AI sidebar");

    state.hMainWindow = hMainWindow;
    state.worker = &worker;

    // Toggle tab: thin vertical button on the right edge of the main window
    RECT clientRect;
    GetClientRect(hMainWindow, &clientRect);
    int tabX = clientRect.right - TOGGLE_TAB_WIDTH - 2;
    int tabY = clientRect.bottom / 2 - 50;

    state.hToggleTab = CreateWindowW(L"BUTTON", L"AI\n>>",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_MULTILINE,
        tabX, tabY, TOGGLE_TAB_WIDTH, 100,
        hMainWindow, (HMENU)ID_AI_TOGGLE, hInst, NULL);

    // Slide-out panel: separate popup tool window, zero width until opened
    RECT mainRect = GetMainWindowScreenRect(hMainWindow);
    int panelX = mainRect.right;
    int panelY = mainRect.top;
    int panelH = mainRect.bottom - mainRect.top;

    state.hPanel = CreateWindowExW(
        WS_EX_TOOLWINDOW,
        AI_PANEL_CLASS, L"",
        WS_POPUP | WS_BORDER,
        panelX, panelY, 0, panelH,
        hMainWindow,
        NULL, hInst, NULL);

    if (!state.hPanel) {
        DebugLog(L"ERROR: Failed to create AI panel window");
        return;
    }

    SetWindowLongPtrW(state.hPanel, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&state));

    int m = PANEL_MARGIN;
    int w = state.panelWidth - 2 * m;
    int btnH = 28;
    int y = m;

    state.hTitleLabel = CreateWindowW(L"STATIC", L"  AI Assistant",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        m, y, w, 30,
        state.hPanel, (HMENU)ID_AI_TITLE, hInst, NULL);
    y += 34;

    state.hStatusLabel = CreateWindowW(L"STATIC", L"  Not connected",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        m, y, w, 18,
        state.hPanel, (HMENU)ID_AI_STATUS, hInst, NULL);
    y += 22;

    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        m, y, w, 2, state.hPanel, NULL, hInst, NULL);
    y += 6;

    int btnW = (w - 2 * 4) / 3;
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

    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        m, y, w, 2, state.hPanel, NULL, hInst, NULL);
    y += 6;

    state.hChatDisplay = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN,
        m, y, w, 300,  // placeholder height, recalculated in LayoutPanelControls
        state.hPanel, (HMENU)ID_AI_CHAT, hInst, NULL);
    y += 300 + 4;

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

    TestConnectionInBackground(state);
}

// ---------------------------------------------------------------------------
// AiPanelWndProc
// ---------------------------------------------------------------------------
static LRESULT CALLBACK AiPanelWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    AiSidebarState* pState = reinterpret_cast<AiSidebarState*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_COMMAND:
        // Forward button clicks to the main window so DispatchCommand handles them.
        if (pState && pState->hMainWindow) {
            SendMessageW(pState->hMainWindow, WM_COMMAND, wParam, lParam);
        }
        return 0;

    case WM_APP_AI_RESPONSE: {
        std::unique_ptr<AiResponsePayload> payload(reinterpret_cast<AiResponsePayload*>(lParam));
        if (pState && payload) {
            if (!payload->chatText.empty()) {
                AppendToChatDisplay(*pState, payload->chatText);
            }
            if (!payload->statusText.empty()) {
                SetAiStatusText(*pState, payload->statusText);
            }
        }
        return 0;
    }

    case WM_TIMER: {
        if (wParam != IDT_SLIDE_ANIM || !pState) break;

        RECT mainRect = GetMainWindowScreenRect(pState->hMainWindow);
        RECT panelRect;
        GetWindowRect(hWnd, &panelRect);
        int currentW = panelRect.right - panelRect.left;

        if (pState->expanded) {
            int targetW = pState->panelWidth;
            int newW = currentW + SLIDE_PX_STEP;
            if (newW >= targetW) {
                newW = targetW;
                KillTimer(hWnd, IDT_SLIDE_ANIM);
                DebugLog(L"Slide-out animation complete");
            }
            SetWindowPos(hWnd, NULL, mainRect.right, mainRect.top,
                newW, mainRect.bottom - mainRect.top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        else {
            int newW = currentW - SLIDE_PX_STEP;
            if (newW <= 0) {
                newW = 0;
                KillTimer(hWnd, IDT_SLIDE_ANIM);
                ShowWindow(hWnd, SW_HIDE);
                DebugLog(L"Slide-in animation complete");
            }
            SetWindowPos(hWnd, NULL, mainRect.right, mainRect.top,
                newW, mainRect.bottom - mainRect.top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC:
        return reinterpret_cast<LRESULT>(ThemeCtlColorStatic(reinterpret_cast<HDC>(wParam)));

    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));

    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(ThemeCtlColorButton(reinterpret_cast<HDC>(wParam)));

    case WM_ERASEBKGND:
        return ThemeEraseBackground(reinterpret_cast<HDC>(wParam), hWnd);
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Layout
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

    int y = m;
    y += 34;        // title
    y += 22;        // status
    y += 6;         // separator
    y += btnH + 6;  // quick action buttons
    y += 6;         // separator
    int chatTop = y;

    int bottomY = panelH - m - btnH;
    int chatHeight = bottomY - chatTop - 4;
    if (chatHeight < 50) chatHeight = 50;

    SetWindowPos(state.hChatDisplay, NULL, m, chatTop, w, chatHeight, SWP_NOZORDER);

    int sendW = 55;
    int inputW = w - sendW - 4;
    SetWindowPos(state.hInputField, NULL, m, bottomY, inputW, btnH, SWP_NOZORDER);
    SetWindowPos(state.hSendButton, NULL, m + inputW + 4, bottomY, sendW, btnH, SWP_NOZORDER);
}

void ToggleAiSidebar(AiSidebarState& state)
{
    state.expanded = !state.expanded;
    DebugLog(state.expanded ? L"Sidebar expanding" : L"Sidebar collapsing");

    SetWindowTextW(state.hToggleTab, state.expanded ? L"AI\n<<" : L"AI\n>>");

    if (state.expanded) {
        RECT mainRect = GetMainWindowScreenRect(state.hMainWindow);
        SetWindowPos(state.hPanel, NULL, mainRect.right, mainRect.top,
            0, mainRect.bottom - mainRect.top, SWP_NOZORDER | SWP_NOACTIVATE);
        ShowWindow(state.hPanel, SW_SHOWNOACTIVATE);
        LayoutPanelControls(state);
    }

    SetTimer(state.hPanel, IDT_SLIDE_ANIM, SLIDE_STEP_MS, NULL);
}

void RepositionAiSidebar(AiSidebarState& state)
{
    if (!state.hPanel || !state.hMainWindow) return;

    RECT clientRect;
    GetClientRect(state.hMainWindow, &clientRect);
    int tabX = clientRect.right - TOGGLE_TAB_WIDTH - 2;
    int tabY = clientRect.bottom / 2 - 50;
    SetWindowPos(state.hToggleTab, NULL, tabX, tabY, TOGGLE_TAB_WIDTH, 100, SWP_NOZORDER);

    if (!state.expanded) return;

    RECT mainRect = GetMainWindowScreenRect(state.hMainWindow);
    RECT panelRect;
    GetWindowRect(state.hPanel, &panelRect);
    int currentW = panelRect.right - panelRect.left;

    SetWindowPos(state.hPanel, NULL, mainRect.right, mainRect.top,
        currentW, mainRect.bottom - mainRect.top, SWP_NOZORDER | SWP_NOACTIVATE);

    LayoutPanelControls(state);
}

// ---------------------------------------------------------------------------
// Display helpers (UI thread)
// ---------------------------------------------------------------------------
void AppendToChatDisplay(AiSidebarState& state, const std::wstring& text)
{
    if (!state.hChatDisplay) return;

    int len = GetWindowTextLengthW(state.hChatDisplay);
    SendMessageW(state.hChatDisplay, EM_SETSEL, len, len);
    SendMessageW(state.hChatDisplay, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(state.hChatDisplay, EM_SCROLLCARET, 0, 0);
}

void ClearChatDisplay(AiSidebarState& state)
{
    if (state.hChatDisplay) {
        SetWindowTextW(state.hChatDisplay, L"");
    }
}

void SetAiStatusText(AiSidebarState& state, const std::wstring& text)
{
    if (state.hStatusLabel) {
        SetWindowTextW(state.hStatusLabel, text.c_str());
    }
}

int GetAiSidebarWidth(const AiSidebarState& state)
{
    return state.expanded ? state.panelWidth : 0;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------
void SendUserMessage(AiSidebarState& state, const std::wstring& message)
{
    if (message.empty()) return;
    if (!ConfirmSendAllowed(state)) return;

    DebugLog((L"Sending user message: " + message).c_str());

    AppendToChatDisplay(state, L"\r\n[You]: " + message + L"\r\n");
    SetAiStatusText(state, L"  Thinking...");
    SetWindowTextW(state.hInputField, L"");

    std::vector<LLMMessage> messages = {
        { "system", "You are a cybersecurity threat analyst assistant integrated into "
          "Phantom Recon, an endpoint security scanner. You help triage scan results, "
          "analyze malware indicators, and provide actionable security recommendations. "
          "Be concise and technical. Focus on actionable intel." },
        { "user", WideToUtf8(message) }
    };
    RunLlmRequest(state, messages, L"\r\n[AI]: ");
}

void TriageSelectedFile(AiSidebarState& state, const ScanRow& row)
{
    if (!ConfirmSendAllowed(state)) return;

    DebugLog((L"Triaging file: " + row.entry.path).c_str());

    AppendToChatDisplay(state, L"\r\n[Triage]: Looking at " + row.entry.path + L"...\r\n");
    SetAiStatusText(state, L"  Analyzing file...");

    // The short legacy prompt plus every field the scan recorded, so the model
    // sees the same facts as the detail window.
    std::string prompt = BuildTriagePrompt(row.entry.path, row.entry.malwareScore,
        row.entry.signature, row.entry.packingStatus, row.entry.suspiciousImports,
        row.entry.sigWarnings, row.entry.packIndicators, row.entry.entropy);
    prompt += "\n\nEverything the scan recorded about this file:\n" + WideToUtf8(BuildRowDetailText(row));

    std::vector<LLMMessage> messages = {
        { "system", "You help a defender decide whether a file on their own Windows PC needs attention. "
          "Explain what the findings mean in plain words, say how worried to be, and list safe next steps "
          "such as checking the vendor's published hash. Do not guess beyond the facts given." },
        { "user", prompt }
    };
    RunLlmRequest(state, messages, L"\r\n[AI Triage]:\r\n");
}

void RequestScanSummary(AiSidebarState& state, const ScanSummary& summary, const std::wstring& title)
{
    if (!ConfirmSendAllowed(state)) return;

    AppendToChatDisplay(state, L"\r\n[Summary]: Summarising " + (title.empty() ? std::wstring(L"the last scan") : title) + L"...\r\n");
    SetAiStatusText(state, L"  Analyzing scan...");

    std::string prompt = BuildScanSummaryPrompt(summary.filesProcessed, summary.executables,
        summary.highRisk, summary.added, summary.changed, summary.missing);
    prompt += "\nAlso: " + std::to_string(summary.updated) + " files changed by signed Microsoft updates, " +
              std::to_string(summary.known) + " new files on the known-good list, " +
              std::to_string(summary.match) + " unchanged. Scan type: " + WideToUtf8(ScanModeName(summary.mode)) +
              (summary.cancelled ? " (cancelled, results are partial)." : ".");
    std::vector<LLMMessage> messages = {
        { "system", "You help a defender read the results of a file integrity scan of their own Windows PC. "
          "Be concise. Say what deserves a look first and why." },
        { "user", prompt }
    };
    RunLlmRequest(state, messages, L"\r\n[AI Summary]:\r\n");
}

void RequestAuditAnalysis(AiSidebarState& state, const std::vector<SecurityCheckResult>& results, size_t maxPartChars)
{
    if (results.empty()) {
        AppendToChatDisplay(state, L"\r\n[Info]: The security audit has not finished yet. Press F5 to run it.\r\n");
        return;
    }
    if (!ConfirmSendAllowed(state)) return;
    if (!state.worker) {
        AppendToChatDisplay(state, L"\r\n[AI Error]: background worker not available.\r\n");
        return;
    }

    // Leave room for the instructions that go with each part.
    size_t partChars = maxPartChars > 2000 ? maxPartChars - 1000 : 1000;
    std::vector<std::wstring> parts = SplitIntoParts(BuildAuditFindingsText(results), partChars);
    AppendToChatDisplay(state, L"\r\n[Audit]: Sending the audit findings in " + std::to_wstring(parts.size()) +
                               (parts.size() == 1 ? L" part" : L" parts") + L"...\r\n");
    SetAiStatusText(state, L"  Analyzing audit...");
    DebugLog((L"Audit analysis: " + std::to_wstring(parts.size()) + L" part(s)").c_str());

    HWND hPanel = state.hPanel;
    state.worker->Run([hPanel, parts]() {
        for (size_t i = 0; i < parts.size(); ++i) {
            std::string header = parts.size() == 1 ? std::string("Here are the findings.\n\n")
                : "This is part " + std::to_string(i + 1) + " of " + std::to_string(parts.size()) +
                  " of the findings. Answer for this part only.\n\n";
            std::vector<LLMMessage> messages = {
                { "system", "You help a defender harden their own Windows PC. For each finding, explain the risk "
                  "in plain words and the order to fix things in, most important first. Keep each item short." },
                { "user", header + BuildSecurityAuditPrompt(WideToUtf8(parts[i])) }
            };
            std::string response = GetLLMClient().SendChatCompletion(messages);

            AiResponsePayload* payload = new AiResponsePayload();
            std::wstring label = parts.size() == 1 ? L"\r\n[AI Audit Analysis]:\r\n"
                : L"\r\n[AI Audit Analysis, part " + std::to_wstring(i + 1) + L" of " + std::to_wstring(parts.size()) + L"]:\r\n";
            if (response.empty()) {
                payload->chatText = L"\r\n[AI Error]: " + Utf8ToWide(GetLLMClient().GetLastError()) + L"\r\n";
                payload->statusText = L"  Error";
                PostPayload(hPanel, WM_APP_AI_RESPONSE, payload);
                return;
            }
            payload->chatText = label + ToWindowsLineEnds(Utf8ToWide(response)) + L"\r\n";
            payload->statusText = (i + 1 == parts.size()) ? L"  Ready" : L"  Analyzing audit...";
            PostPayload(hPanel, WM_APP_AI_RESPONSE, payload);
        }
    });
}

void ApplyThemeToAiSidebar(AiSidebarState& state)
{
    if (state.hPanel) ApplyThemeToWindowTree(state.hPanel);
    if (state.hToggleTab) ApplyThemeToControl(state.hToggleTab);
}
