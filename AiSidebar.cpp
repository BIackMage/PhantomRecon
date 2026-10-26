#include "pch.h"
#include "AiSidebar.h"

#include "AiConsent.h"
#include "AppMessages.h"
#include "DetailText.h"
#include "GuiComponents.h"
#include "LLMClient.h"
#include "Redactor.h"
#include "StringConv.h"
#include "TextUtils.h"
#include "Theme.h"

#include <algorithm>
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

// The chat edit control would stop at 32,767 characters (its default limit).
// The limit is lifted; past kChatMaxChars the oldest text is dropped down to
// about kChatKeepChars so a long session stays responsive.
static const size_t kChatMaxChars = 2000000;
static const size_t kChatKeepChars = 1000000;

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

// Where the panel goes at a given width. Normally flush against the main
// window's right edge. When that would leave the monitor (main window maximized
// or pushed to the right edge), it opens inside the main window instead, just
// left of the toggle tab so the tab stays visible to close it again. Height is
// kept within the monitor's work area.
static RECT PanelRectFor(const AiSidebarState& state, int width)
{
    RECT mainRect = GetMainWindowScreenRect(state.hMainWindow);
    RECT work = mainRect;
    MONITORINFO mi = {};
    mi.cbSize = sizeof(mi);
    if (GetMonitorInfoW(MonitorFromWindow(state.hMainWindow, MONITOR_DEFAULTTONEAREST), &mi)) work = mi.rcWork;

    int top = (std::max)(mainRect.top, work.top);
    int bottom = (std::min)(mainRect.bottom, work.bottom);
    if (bottom - top < 100) {
        top = mainRect.top;
        bottom = mainRect.bottom;
    }

    int x = mainRect.right;
    if (x + width > work.right) {
        RECT tab = {};
        int rightEdge = work.right;
        if (state.hToggleTab && GetWindowRect(state.hToggleTab, &tab)) rightEdge = (std::min)(rightEdge, static_cast<int>(tab.left) - 2);
        x = rightEdge - width;
        if (x < work.left) x = work.left;
    }
    RECT r = { x, top, x + width, bottom };
    return r;
}

static void PlacePanel(AiSidebarState& state, int width)
{
    RECT r = PanelRectFor(state, width);
    SetWindowPos(state.hPanel, NULL, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
}

// ---------------------------------------------------------------------------
// Privacy gate
//
// The default endpoint is localhost, so nothing leaves the machine. If the user
// pointed Settings at another host, say so plainly and ask. The approval covers
// only that exact endpoint (AiConsent.h). config receives the settings this
// request must run with, captured together with the decision.
// ---------------------------------------------------------------------------
static bool ConfirmSendAllowed(AiSidebarState& state, LLMConfig& config)
{
    config = GetLLMClient().GetConfig();
    AiSendDecision decision = DecideAiSend(config.endpoint, state.approvedRemoteEndpoint);
    if (decision != AiSendDecision::NeedsApproval) return true;

    std::wstring text = BuildRemoteSendConsentText(config.endpoint);
    int answer = MessageBoxW(state.hMainWindow, text.c_str(), L"Send scan data to a remote server?",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (answer != IDYES) {
        AppendToChatDisplay(state, L"\r\n[Info]: Not sent. Change the endpoint in File > Settings to a local server, or approve the remote one.\r\n");
        DebugLog((L"User declined sending to " + config.endpoint).c_str());
        return false;
    }

    state.approvedRemoteEndpoint = config.endpoint;
    DebugLog((L"User approved sending to " + config.endpoint + L" for this session").c_str());
    return true;
}

// ---------------------------------------------------------------------------
// Worker plumbing: run one chat completion, post the result to the panel. Each
// request uses its own client built from the approved config, so the endpoint
// cannot change between the question and the send.
// ---------------------------------------------------------------------------
static void RunLlmRequest(AiSidebarState& state, const LLMConfig& config, const std::vector<LLMMessage>& messages,
                          const std::wstring& successPrefix)
{
    if (!state.worker) {
        AppendToChatDisplay(state, L"\r\n[AI Error]: background worker not available.\r\n");
        return;
    }

    HWND hPanel = state.hPanel;
    PayloadTracker* tracker = state.payloads;
    state.worker->Run([hPanel, tracker, config, messages, successPrefix]() {
        LLMClient client;
        client.SetConfig(config);
        std::string response = client.SendChatCompletion(messages);

        AiResponsePayload* payload = new AiResponsePayload();
        if (response.empty()) {
            payload->chatText = L"\r\n[AI Error]: " + Utf8ToWide(client.GetLastError()) + L"\r\n";
            payload->statusText = L"  Error";
        }
        else {
            payload->chatText = successPrefix + ToWindowsLineEnds(Utf8ToWide(response)) + L"\r\n";
            payload->statusText = L"  Ready";
        }
        PostPayload(hPanel, WM_APP_AI_RESPONSE, payload, *tracker);
    });
}

// Probe the endpoint at startup (and after Settings changes it). Only an endpoint
// on this PC is contacted without asking; for any other the panel says it was not
// tested and where the Test button is.
static void TestConnectionInBackground(AiSidebarState& state)
{
    if (!state.worker) return;

    LLMConfig config = GetLLMClient().GetConfig();
    if (!ShouldTestAiEndpointAtStartup(config.endpoint)) {
        SetAiStatusText(state, StartupTestSkippedStatus());
        AppendToChatDisplay(state, StartupTestSkippedChatText(config.endpoint));
        DebugLog((L"Startup connection test skipped for the remote endpoint " + config.endpoint).c_str());
        return;
    }

    SetAiStatusText(state, L"  Testing connection...");
    HWND hPanel = state.hPanel;
    PayloadTracker* tracker = state.payloads;
    state.worker->Run([hPanel, tracker, config]() {
        DebugLog(L"Testing LLM connection...");
        LLMClient client;
        client.SetConfig(config);
        bool connected = client.TestConnection();

        AiResponsePayload* payload = new AiResponsePayload();
        if (connected) {
            payload->statusText = L"  Connected (" + Utf8ToWide(config.model) + L")";
            DebugLog(L"LLM connection successful");
        }
        else {
            payload->statusText = L"  Connection failed";
            DebugLog((L"LLM connection failed: " + Utf8ToWide(client.GetLastError())).c_str());
        }
        PostPayload(hPanel, WM_APP_AI_RESPONSE, payload, *tracker);
    });
}

void OnAiSettingsChanged(AiSidebarState& state)
{
    DebugLog(L"AI settings changed; refreshing the connection status");
    TestConnectionInBackground(state);
}

// ---------------------------------------------------------------------------
// CreateAiSidebar
// ---------------------------------------------------------------------------
void CreateAiSidebar(HWND hMainWindow, HINSTANCE hInst, AiSidebarState& state, BackgroundWorker& worker,
                     PayloadTracker& payloads)
{
    DebugLog(L"Creating AI sidebar");

    state.hMainWindow = hMainWindow;
    state.worker = &worker;
    state.payloads = &payloads;

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
    SendMessageW(state.hChatDisplay, EM_SETLIMITTEXT, 0, 0);   // 0: the largest size the control allows
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

    case WM_NCDESTROY:
        // Replies already posted to this window are dropped with it; free them.
        if (pState && pState->payloads) pState->payloads->FreeFor(hWnd);
        break;

    case WM_APP_AI_RESPONSE: {
        std::unique_ptr<AiResponsePayload> payload =
            TakePayload<AiResponsePayload>(pState ? pState->payloads : nullptr, lParam);
        DebugLog(L"AI response handled by the panel");
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
            PlacePanel(*pState, newW);
        }
        else {
            int newW = currentW - SLIDE_PX_STEP;
            if (newW <= 0) {
                newW = 0;
                KillTimer(hWnd, IDT_SLIDE_ANIM);
                ShowWindow(hWnd, SW_HIDE);
                DebugLog(L"Slide-in animation complete");
            }
            PlacePanel(*pState, newW);
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
        PlacePanel(state, 0);
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

    RECT panelRect;
    GetWindowRect(state.hPanel, &panelRect);
    int currentW = panelRect.right - panelRect.left;
    PlacePanel(state, currentW);

    LayoutPanelControls(state);
}

// ---------------------------------------------------------------------------
// Display helpers (UI thread)
// ---------------------------------------------------------------------------
// Drop the oldest chat text once the display passes kChatMaxChars, cutting at a
// line start so no message is left half shown.
static void TrimChatDisplay(AiSidebarState& state, size_t incoming)
{
    size_t len = static_cast<size_t>(GetWindowTextLengthW(state.hChatDisplay));
    if (len + incoming <= kChatMaxChars) return;

    std::wstring all = GetWindowTextString(state.hChatDisplay);
    size_t cut = all.size() > kChatKeepChars ? all.size() - kChatKeepChars : 0;
    size_t lineStart = all.find(L"\r\n", cut);
    cut = lineStart == std::wstring::npos ? cut : lineStart + 2;
    std::wstring kept = L"[Older messages were removed to keep the panel fast.]\r\n" + all.substr(cut);
    SetWindowTextW(state.hChatDisplay, kept.c_str());
    DebugLog((L"Chat display trimmed from " + std::to_wstring(len) + L" to " + std::to_wstring(kept.size()) +
              L" characters").c_str());
}

void AppendToChatDisplay(AiSidebarState& state, const std::wstring& text)
{
    if (!state.hChatDisplay) return;

    TrimChatDisplay(state, text.size());
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
    LLMConfig config;
    if (!ConfirmSendAllowed(state, config)) return;

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
    RunLlmRequest(state, config, messages, L"\r\n[AI]: ");
}

void TriageSelectedFile(AiSidebarState& state, ScanRow row)
{
    LLMConfig config;
    if (!ConfirmSendAllowed(state, config)) return;

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
    RunLlmRequest(state, config, messages, L"\r\n[AI Triage]:\r\n");
}

void RequestScanSummary(AiSidebarState& state, const ScanSummary& summary, const std::wstring& title)
{
    LLMConfig config;
    if (!ConfirmSendAllowed(state, config)) return;

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
    RunLlmRequest(state, config, messages, L"\r\n[AI Summary]:\r\n");
}

void RequestAuditAnalysis(AiSidebarState& state, const std::vector<SecurityCheckResult>& results, size_t maxPartChars)
{
    if (results.empty()) {
        AppendToChatDisplay(state, L"\r\n[Info]: The security audit has not finished yet. Press F5 to run it.\r\n");
        return;
    }
    LLMConfig config;
    if (!ConfirmSendAllowed(state, config)) return;
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

    // Every part goes to the endpoint approved above, even if Settings changes it
    // while the parts are being sent.
    HWND hPanel = state.hPanel;
    PayloadTracker* tracker = state.payloads;
    state.worker->Run([hPanel, tracker, parts, config]() {
        LLMClient client;
        client.SetConfig(config);
        for (size_t i = 0; i < parts.size(); ++i) {
            std::string header = parts.size() == 1 ? std::string("Here are the findings.\n\n")
                : "This is part " + std::to_string(i + 1) + " of " + std::to_string(parts.size()) +
                  " of the findings. Answer for this part only.\n\n";
            std::vector<LLMMessage> messages = {
                { "system", "You help a defender harden their own Windows PC. For each finding, explain the risk "
                  "in plain words and the order to fix things in, most important first. Keep each item short." },
                { "user", header + BuildSecurityAuditPrompt(WideToUtf8(parts[i])) }
            };
            std::string response = client.SendChatCompletion(messages);

            AiResponsePayload* payload = new AiResponsePayload();
            std::wstring label = parts.size() == 1 ? L"\r\n[AI Audit Analysis]:\r\n"
                : L"\r\n[AI Audit Analysis, part " + std::to_wstring(i + 1) + L" of " + std::to_wstring(parts.size()) + L"]:\r\n";
            if (response.empty()) {
                payload->chatText = L"\r\n[AI Error]: " + Utf8ToWide(client.GetLastError()) + L"\r\n";
                payload->statusText = L"  Error";
                PostPayload(hPanel, WM_APP_AI_RESPONSE, payload, *tracker);
                return;
            }
            payload->chatText = label + ToWindowsLineEnds(Utf8ToWide(response)) + L"\r\n";
            payload->statusText = (i + 1 == parts.size()) ? L"  Ready" : L"  Analyzing audit...";
            PostPayload(hPanel, WM_APP_AI_RESPONSE, payload, *tracker);
        }
    });
}

void ApplyThemeToAiSidebar(AiSidebarState& state)
{
    if (state.hPanel) ApplyThemeToWindowTree(state.hPanel);
    if (state.hToggleTab) ApplyThemeToControl(state.hToggleTab);
}
