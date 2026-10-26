#include "pch.h"
#include "SettingsDialog.h"

#include "AppMessages.h"
#include "DarkMode.h"
#include "StringConv.h"

#include <iomanip>
#include <memory>
#include <sstream>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[Settings] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Settings file
// ---------------------------------------------------------------------------
static const wchar_t* SETTINGS_FILE = L"phantom_recon_settings.ini";

static std::wstring GetSettingsPath()
{
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring dir(exePath);
    size_t lastSlash = dir.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) dir = dir.substr(0, lastSlash + 1);
    return dir + SETTINGS_FILE;
}

static std::wstring ReadIniString(const wchar_t* section, const wchar_t* key,
    const wchar_t* defaultVal, const wchar_t* file)
{
    wchar_t buf[1024] = {};
    GetPrivateProfileStringW(section, key, defaultVal, buf, 1024, file);
    return buf;
}

static int ReadIniInt(const wchar_t* section, const wchar_t* key, int defaultVal, const wchar_t* file)
{
    return GetPrivateProfileIntW(section, key, defaultVal, file);
}

static void WriteIniString(const wchar_t* section, const wchar_t* key, const wchar_t* value, const wchar_t* file)
{
    WritePrivateProfileStringW(section, key, value, file);
}

static std::wstring FormatTemperature(double value)
{
    std::wstringstream ss;
    ss << std::fixed << std::setprecision(2) << value;
    return ss.str();
}

// ---------------------------------------------------------------------------
// Load / Save / Apply
// ---------------------------------------------------------------------------
AppSettings LoadAppSettings()
{
    AppSettings settings;
    std::wstring iniPath = GetSettingsPath();

    if (GetFileAttributesW(iniPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        DebugLog(L"Settings file not found, using defaults");
        return settings;
    }

    // Fallbacks come from the AppSettings defaults (which come from LLMConfig),
    // so there is exactly one place that defines them.
    settings.llmEndpoint = ReadIniString(L"LLM", L"Endpoint", settings.llmEndpoint.c_str(), iniPath.c_str());

    std::wstring defaultModel = Utf8ToWide(settings.llmModel);
    settings.llmModel = WideToUtf8(ReadIniString(L"LLM", L"Model", defaultModel.c_str(), iniPath.c_str()));

    settings.llmMaxTokens = ReadIniInt(L"LLM", L"MaxTokens", settings.llmMaxTokens, iniPath.c_str());

    std::wstring defaultTemp = FormatTemperature(settings.llmTemperature);
    std::wstring tempStr = ReadIniString(L"LLM", L"Temperature", defaultTemp.c_str(), iniPath.c_str());
    settings.llmTemperature = _wtof(tempStr.c_str());

    DebugLog((L"Settings loaded from: " + iniPath).c_str());
    return settings;
}

void SaveAppSettings(const AppSettings& settings)
{
    std::wstring iniPath = GetSettingsPath();

    WriteIniString(L"LLM", L"Endpoint", settings.llmEndpoint.c_str(), iniPath.c_str());
    WriteIniString(L"LLM", L"Model", Utf8ToWide(settings.llmModel).c_str(), iniPath.c_str());
    WriteIniString(L"LLM", L"MaxTokens", std::to_wstring(settings.llmMaxTokens).c_str(), iniPath.c_str());
    WriteIniString(L"LLM", L"Temperature", FormatTemperature(settings.llmTemperature).c_str(), iniPath.c_str());

    DebugLog((L"Settings saved to: " + iniPath).c_str());
}

void ApplySettingsToLLMClient(const AppSettings& settings)
{
    LLMConfig cfg;
    cfg.endpoint = settings.llmEndpoint;
    cfg.model = settings.llmModel;
    cfg.maxTokens = settings.llmMaxTokens;
    cfg.temperature = settings.llmTemperature;
    GetLLMClient().SetConfig(cfg);

    DebugLog(L"Settings applied to LLM client");
}

// ---------------------------------------------------------------------------
// Dialog
// ---------------------------------------------------------------------------
#define IDC_SETTINGS_ENDPOINT   3001
#define IDC_SETTINGS_MODEL      3002
#define IDC_SETTINGS_MAXTOKENS  3003
#define IDC_SETTINGS_TEMP       3004
#define IDC_SETTINGS_TEST       3005
#define IDC_SETTINGS_STATUS     3006
#define IDC_SETTINGS_SAVE       3007
#define IDC_SETTINGS_CANCEL     3008

static const int DLG_W = 480;
static const int DLG_H = 340;

static const wchar_t* SETTINGS_CLASS = L"PhantomRecon_Settings";

// Per-dialog state. Lives on ShowSettingsDialog's stack for the dialog's lifetime
// and is reached through GWLP_USERDATA. No file-scope mutable state.
struct SettingsDialogState {
    AppSettings       settings;
    HWND              hStatusLabel = NULL;
    bool              saved = false;
    BackgroundWorker* worker = nullptr;
};

static SettingsDialogState* GetDialogState(HWND hDlg)
{
    return reinterpret_cast<SettingsDialogState*>(GetWindowLongPtrW(hDlg, GWLP_USERDATA));
}

static std::wstring GetDlgItemString(HWND hDlg, int id)
{
    wchar_t buf[1024] = {};
    GetWindowTextW(GetDlgItem(hDlg, id), buf, 1024);
    return buf;
}

static void OnDialogCreate(HWND hDlg, SettingsDialogState& st, HINSTANCE hInst)
{
    const int m = 16;
    const int labelH = 18;
    const int editH = 24;
    const int btnH = 30;
    const int w = DLG_W - 2 * m;
    const int editW = w;
    int y = m;

    CreateWindowW(L"STATIC", L"LLM Connection Settings", WS_CHILD | WS_VISIBLE | SS_LEFT,
        m, y, w, 24, hDlg, NULL, hInst, NULL);
    y += 30;

    CreateWindowW(L"STATIC", L"Endpoint URL:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        m, y, w, labelH, hDlg, NULL, hInst, NULL);
    y += labelH + 2;
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", st.settings.llmEndpoint.c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        m, y, editW, editH, hDlg, (HMENU)IDC_SETTINGS_ENDPOINT, hInst, NULL);
    y += editH + 10;

    CreateWindowW(L"STATIC", L"Model Name:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        m, y, 100, labelH, hDlg, NULL, hInst, NULL);
    y += labelH + 2;
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", Utf8ToWide(st.settings.llmModel).c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        m, y, editW, editH, hDlg, (HMENU)IDC_SETTINGS_MODEL, hInst, NULL);
    y += editH + 10;

    const int halfW = (editW - 10) / 2;
    CreateWindowW(L"STATIC", L"Max Tokens:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        m, y, halfW, labelH, hDlg, NULL, hInst, NULL);
    CreateWindowW(L"STATIC", L"Temperature:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        m + halfW + 10, y, halfW, labelH, hDlg, NULL, hInst, NULL);
    y += labelH + 2;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", std::to_wstring(st.settings.llmMaxTokens).c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER,
        m, y, halfW, editH, hDlg, (HMENU)IDC_SETTINGS_MAXTOKENS, hInst, NULL);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", FormatTemperature(st.settings.llmTemperature).c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        m + halfW + 10, y, halfW, editH, hDlg, (HMENU)IDC_SETTINGS_TEMP, hInst, NULL);
    y += editH + 14;

    CreateWindowW(L"BUTTON", L"Test Connection", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        m, y, 140, btnH, hDlg, (HMENU)IDC_SETTINGS_TEST, hInst, NULL);
    st.hStatusLabel = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        m + 150, y, w - 150, btnH, hDlg, (HMENU)IDC_SETTINGS_STATUS, hInst, NULL);
    y += btnH + 20;

    const int saveBtnW = 100;
    const int cancelBtnW = 100;
    const int btnGap = 10;
    const int btnX = DLG_W - m - saveBtnW - btnGap - cancelBtnW;
    CreateWindowW(L"BUTTON", L"Save", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, y, saveBtnW, btnH, hDlg, (HMENU)IDC_SETTINGS_SAVE, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX + saveBtnW + btnGap, y, cancelBtnW, btnH, hDlg, (HMENU)IDC_SETTINGS_CANCEL, hInst, NULL);
}

// Test Connection: build a throwaway client from the field values so the live
// singleton is untouched until Save, then run it on the worker.
static void OnTestConnection(HWND hDlg, SettingsDialogState& st)
{
    SetWindowTextW(st.hStatusLabel, L"Testing connection...");
    DebugLog(L"Testing LLM connection from settings dialog");

    LLMConfig testCfg;
    testCfg.endpoint = GetDlgItemString(hDlg, IDC_SETTINGS_ENDPOINT);
    testCfg.model = WideToUtf8(GetDlgItemString(hDlg, IDC_SETTINGS_MODEL));
    testCfg.maxTokens = _wtoi(GetDlgItemString(hDlg, IDC_SETTINGS_MAXTOKENS).c_str());
    if (testCfg.maxTokens < 1) testCfg.maxTokens = LLMConfig{}.maxTokens;
    testCfg.temperature = _wtof(GetDlgItemString(hDlg, IDC_SETTINGS_TEMP).c_str());

    if (!st.worker) {
        SetWindowTextW(st.hStatusLabel, L"Failed: no background worker");
        return;
    }

    st.worker->Run([hDlg, testCfg]() {
        LLMClient testClient;
        testClient.SetConfig(testCfg);
        bool ok = testClient.TestConnection();

        std::wstring text = ok ? L"Connected successfully!"
                               : L"Failed: " + Utf8ToWide(testClient.GetLastError());
        DebugLog(ok ? L"Test connection: SUCCESS" : L"Test connection: FAILED");
        PostPayload(hDlg, WM_APP_STATUS_TEXT, new std::wstring(text));
    });
}

static void OnSave(HWND hDlg, SettingsDialogState& st)
{
    st.settings.llmEndpoint = GetDlgItemString(hDlg, IDC_SETTINGS_ENDPOINT);
    st.settings.llmModel = WideToUtf8(GetDlgItemString(hDlg, IDC_SETTINGS_MODEL));

    st.settings.llmMaxTokens = _wtoi(GetDlgItemString(hDlg, IDC_SETTINGS_MAXTOKENS).c_str());
    if (st.settings.llmMaxTokens < 1) st.settings.llmMaxTokens = LLMConfig{}.maxTokens;

    st.settings.llmTemperature = _wtof(GetDlgItemString(hDlg, IDC_SETTINGS_TEMP).c_str());
    if (st.settings.llmTemperature < 0.0) st.settings.llmTemperature = 0.0;
    if (st.settings.llmTemperature > 2.0) st.settings.llmTemperature = 2.0;

    SaveAppSettings(st.settings);
    ApplySettingsToLLMClient(st.settings);

    st.saved = true;
    DestroyWindow(hDlg);
    DebugLog(L"Settings saved and applied");
}

static LRESULT CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hDlg, msg, wParam, lParam);
    }

    SettingsDialogState* st = GetDialogState(hDlg);

    switch (msg)
    {
    case WM_CREATE:
        if (st) OnDialogCreate(hDlg, *st, reinterpret_cast<CREATESTRUCTW*>(lParam)->hInstance);
        return 0;

    case WM_COMMAND:
        if (!st) break;
        switch (LOWORD(wParam)) {
        case IDC_SETTINGS_TEST:   OnTestConnection(hDlg, *st); return 0;
        case IDC_SETTINGS_SAVE:   OnSave(hDlg, *st);           return 0;
        case IDC_SETTINGS_CANCEL: DestroyWindow(hDlg);         return 0;
        }
        break;

    case WM_APP_STATUS_TEXT: {
        std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(lParam));
        if (st && text) {
            SetWindowTextW(st->hStatusLabel, text->c_str());
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC:
        return reinterpret_cast<LRESULT>(HandleDarkCtlColorStatic(reinterpret_cast<HDC>(wParam)));

    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(HandleDarkCtlColorEdit(reinterpret_cast<HDC>(wParam)));

    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(HandleDarkCtlColorBtn(reinterpret_cast<HDC>(wParam)));

    case WM_ERASEBKGND:
        return HandleDarkEraseBkgnd(reinterpret_cast<HDC>(wParam), hDlg);

    case WM_CLOSE:
        DestroyWindow(hDlg);
        return 0;

    case WM_DESTROY:
        // Ends the local message loop in ShowSettingsDialog. The main loop never sees it.
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hDlg, msg, wParam, lParam);
}

static void EnsureSettingsClassRegistered(HINSTANCE hInst)
{
    WNDCLASSEXW existing = {};
    existing.cbSize = sizeof(existing);
    if (GetClassInfoExW(hInst, SETTINGS_CLASS, &existing)) {
        return;
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = SettingsDlgProc;
    wc.hInstance = hInst;
    wc.hbrBackground = CreateSolidBrush(DarkColors::Background);
    wc.lpszClassName = SETTINGS_CLASS;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
}

bool ShowSettingsDialog(HWND hParent, HINSTANCE hInst, BackgroundWorker& worker)
{
    EnsureSettingsClassRegistered(hInst);

    SettingsDialogState st;
    st.settings = LoadAppSettings();
    st.worker = &worker;

    RECT parentRect;
    GetWindowRect(hParent, &parentRect);
    int x = parentRect.left + (parentRect.right - parentRect.left - DLG_W) / 2;
    int y = parentRect.top + (parentRect.bottom - parentRect.top - DLG_H) / 2;

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        SETTINGS_CLASS, L"Settings",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x, y, DLG_W, DLG_H,
        hParent, NULL, hInst, &st);

    if (!hDlg) {
        DebugLog(L"ERROR: Failed to create settings window");
        return false;
    }

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    EnableWindow(hParent, FALSE);

    // Local message loop. WM_DESTROY posts WM_QUIT, which ends it.
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsWindow(hDlg)) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);

    DebugLog(st.saved ? L"Settings dialog closed (saved)" : L"Settings dialog closed (cancelled)");
    return st.saved;
}
