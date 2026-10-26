#include "pch.h"
#include "SettingsDialog.h"
#include "DarkMode.h"

#include <sstream>
#include <fstream>
#include <thread>
#include <iomanip>

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
// String conversion helpers
// ---------------------------------------------------------------------------
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
// Settings file path
// ---------------------------------------------------------------------------
static const wchar_t* SETTINGS_FILE = L"phantom_recon_settings.ini";

// ---------------------------------------------------------------------------
// INI read/write helpers
// ---------------------------------------------------------------------------
static std::wstring ReadIniString(const wchar_t* section, const wchar_t* key,
    const wchar_t* defaultVal, const wchar_t* file)
{
    wchar_t buf[1024] = {};
    GetPrivateProfileStringW(section, key, defaultVal, buf, 1024, file);
    return buf;
}

static int ReadIniInt(const wchar_t* section, const wchar_t* key,
    int defaultVal, const wchar_t* file)
{
    return GetPrivateProfileIntW(section, key, defaultVal, file);
}

static void WriteIniString(const wchar_t* section, const wchar_t* key,
    const wchar_t* value, const wchar_t* file)
{
    WritePrivateProfileStringW(section, key, value, file);
}

// ---------------------------------------------------------------------------
// LoadAppSettings
// ---------------------------------------------------------------------------
AppSettings LoadAppSettings()
{
    AppSettings settings;

    // Get full path relative to exe
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring dir(exePath);
    size_t lastSlash = dir.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) dir = dir.substr(0, lastSlash + 1);
    std::wstring iniPath = dir + SETTINGS_FILE;

    // Check if file exists
    if (GetFileAttributesW(iniPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        DebugLog(L"Settings file not found, using defaults");
        return settings;
    }

    settings.llmEndpoint = ReadIniString(L"LLM", L"Endpoint",
        settings.llmEndpoint.c_str(), iniPath.c_str());

    // Fallbacks come from the AppSettings defaults (which come from LLMConfig),
    // so there is exactly one place that defines them.
    std::wstring defaultModel(settings.llmModel.begin(), settings.llmModel.end());
    std::wstring model = ReadIniString(L"LLM", L"Model", defaultModel.c_str(), iniPath.c_str());
    settings.llmModel = ToUtf8(model);

    settings.llmMaxTokens = ReadIniInt(L"LLM", L"MaxTokens", settings.llmMaxTokens, iniPath.c_str());

    std::wstring defaultTemp = std::to_wstring(settings.llmTemperature);
    std::wstring tempStr = ReadIniString(L"LLM", L"Temperature", defaultTemp.c_str(), iniPath.c_str());
    settings.llmTemperature = _wtof(tempStr.c_str());

    DebugLog((L"Settings loaded from: " + iniPath).c_str());
    return settings;
}

// ---------------------------------------------------------------------------
// SaveAppSettings
// ---------------------------------------------------------------------------
void SaveAppSettings(const AppSettings& settings)
{
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring dir(exePath);
    size_t lastSlash = dir.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) dir = dir.substr(0, lastSlash + 1);
    std::wstring iniPath = dir + SETTINGS_FILE;

    WriteIniString(L"LLM", L"Endpoint", settings.llmEndpoint.c_str(), iniPath.c_str());
    WriteIniString(L"LLM", L"Model", ToWide(settings.llmModel).c_str(), iniPath.c_str());
    WriteIniString(L"LLM", L"MaxTokens", std::to_wstring(settings.llmMaxTokens).c_str(), iniPath.c_str());

    std::wstringstream tempSS;
    tempSS << std::fixed << std::setprecision(2) << settings.llmTemperature;
    WriteIniString(L"LLM", L"Temperature", tempSS.str().c_str(), iniPath.c_str());

    DebugLog((L"Settings saved to: " + iniPath).c_str());
}

// ---------------------------------------------------------------------------
// ApplySettingsToLLMClient
// ---------------------------------------------------------------------------
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
// Dialog control IDs
// ---------------------------------------------------------------------------
#define IDC_SETTINGS_ENDPOINT   3001
#define IDC_SETTINGS_MODEL      3002
#define IDC_SETTINGS_MAXTOKENS  3003
#define IDC_SETTINGS_TEMP       3004
#define IDC_SETTINGS_TEST       3005
#define IDC_SETTINGS_STATUS     3006
#define IDC_SETTINGS_SAVE       3007
#define IDC_SETTINGS_CANCEL     3008

// Dialog dimensions
static const int DLG_W = 480;
static const int DLG_H = 340;

// Global for dialog state
static AppSettings s_dialogSettings;
static HWND s_hStatusLabel = NULL;
static bool s_dialogSaved = false;

// ---------------------------------------------------------------------------
// Settings dialog WndProc
// ---------------------------------------------------------------------------
static LRESULT CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HINSTANCE hInst = ((CREATESTRUCT*)lParam)->hInstance;

        int m = 16;       // margin
        int labelH = 18;
        int editH = 24;
        int btnH = 30;
        int y = m;
        int w = DLG_W - 2 * m;
        int editW = w;

        // --- Title ---
        CreateWindowW(L"STATIC", L"LLM Connection Settings",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            m, y, w, 24,
            hDlg, NULL, hInst, NULL);
        y += 30;

        // --- Endpoint ---
        CreateWindowW(L"STATIC", L"Endpoint URL:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            m, y, w, labelH,
            hDlg, NULL, hInst, NULL);
        y += labelH + 2;
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            s_dialogSettings.llmEndpoint.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            m, y, editW, editH,
            hDlg, (HMENU)IDC_SETTINGS_ENDPOINT, hInst, NULL);
        y += editH + 10;

        // --- Model ---
        CreateWindowW(L"STATIC", L"Model Name:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            m, y, 100, labelH,
            hDlg, NULL, hInst, NULL);
        y += labelH + 2;
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            ToWide(s_dialogSettings.llmModel).c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            m, y, editW, editH,
            hDlg, (HMENU)IDC_SETTINGS_MODEL, hInst, NULL);
        y += editH + 10;

        // --- Max Tokens + Temperature on one row ---
        int halfW = (editW - 10) / 2;

        CreateWindowW(L"STATIC", L"Max Tokens:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            m, y, halfW, labelH,
            hDlg, NULL, hInst, NULL);
        CreateWindowW(L"STATIC", L"Temperature:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            m + halfW + 10, y, halfW, labelH,
            hDlg, NULL, hInst, NULL);
        y += labelH + 2;

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            std::to_wstring(s_dialogSettings.llmMaxTokens).c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER,
            m, y, halfW, editH,
            hDlg, (HMENU)IDC_SETTINGS_MAXTOKENS, hInst, NULL);

        std::wstringstream tempSS;
        tempSS << std::fixed << std::setprecision(2) << s_dialogSettings.llmTemperature;
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            tempSS.str().c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            m + halfW + 10, y, halfW, editH,
            hDlg, (HMENU)IDC_SETTINGS_TEMP, hInst, NULL);
        y += editH + 14;

        // --- Test Connection button + status ---
        CreateWindowW(L"BUTTON", L"Test Connection",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            m, y, 140, btnH,
            hDlg, (HMENU)IDC_SETTINGS_TEST, hInst, NULL);

        s_hStatusLabel = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
            m + 150, y, w - 150, btnH,
            hDlg, (HMENU)IDC_SETTINGS_STATUS, hInst, NULL);
        y += btnH + 20;

        // --- Save / Cancel buttons ---
        int saveBtnW = 100;
        int cancelBtnW = 100;
        int btnGap = 10;
        int btnX = DLG_W - m - saveBtnW - btnGap - cancelBtnW;

        CreateWindowW(L"BUTTON", L"Save",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            btnX, y, saveBtnW, btnH,
            hDlg, (HMENU)IDC_SETTINGS_SAVE, hInst, NULL);

        CreateWindowW(L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            btnX + saveBtnW + btnGap, y, cancelBtnW, btnH,
            hDlg, (HMENU)IDC_SETTINGS_CANCEL, hInst, NULL);

        return 0;
    }

    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDC_SETTINGS_TEST:
        {
            SetWindowTextW(s_hStatusLabel, L"Testing connection...");
            DebugLog(L"Testing LLM connection from settings dialog");

            // Read current values from fields
            wchar_t buf[1024] = {};
            GetWindowTextW(GetDlgItem(hDlg, IDC_SETTINGS_ENDPOINT), buf, 1024);
            std::wstring endpoint = buf;

            GetWindowTextW(GetDlgItem(hDlg, IDC_SETTINGS_MODEL), buf, 1024);
            std::string model = ToUtf8(buf);

            // Temporarily apply to test
            LLMConfig testCfg;
            testCfg.endpoint = endpoint;
            testCfg.model = model;
            GetLLMClient().SetConfig(testCfg);

            HWND hStatus = s_hStatusLabel;
            std::thread([hStatus]() {
                bool ok = GetLLMClient().TestConnection();
                if (ok) {
                    SetWindowTextW(hStatus, L"Connected successfully!");
                    DebugLog(L"Test connection: SUCCESS");
                }
                else {
                    std::string err = GetLLMClient().GetLastError();
                    std::wstring msg = L"Failed: " + ToWide(err);
                    SetWindowTextW(hStatus, msg.c_str());
                    DebugLog(L"Test connection: FAILED");
                }
            }).detach();
            return 0;
        }

        case IDC_SETTINGS_SAVE:
        {
            wchar_t buf[1024] = {};

            GetWindowTextW(GetDlgItem(hDlg, IDC_SETTINGS_ENDPOINT), buf, 1024);
            s_dialogSettings.llmEndpoint = buf;

            GetWindowTextW(GetDlgItem(hDlg, IDC_SETTINGS_MODEL), buf, 1024);
            s_dialogSettings.llmModel = ToUtf8(buf);

            GetWindowTextW(GetDlgItem(hDlg, IDC_SETTINGS_MAXTOKENS), buf, 1024);
            s_dialogSettings.llmMaxTokens = _wtoi(buf);
            if (s_dialogSettings.llmMaxTokens < 1) s_dialogSettings.llmMaxTokens = 2048;

            GetWindowTextW(GetDlgItem(hDlg, IDC_SETTINGS_TEMP), buf, 1024);
            s_dialogSettings.llmTemperature = _wtof(buf);
            if (s_dialogSettings.llmTemperature < 0.0) s_dialogSettings.llmTemperature = 0.0;
            if (s_dialogSettings.llmTemperature > 2.0) s_dialogSettings.llmTemperature = 2.0;

            SaveAppSettings(s_dialogSettings);
            ApplySettingsToLLMClient(s_dialogSettings);

            s_dialogSaved = true;
            DestroyWindow(hDlg);
            DebugLog(L"Settings saved and applied");
            return 0;
        }

        case IDC_SETTINGS_CANCEL:
            DestroyWindow(hDlg);
            return 0;
        }
        break;
    }

    case WM_CTLCOLORSTATIC:
        return (LRESULT)HandleDarkCtlColorStatic((HDC)wParam);

    case WM_CTLCOLOREDIT:
        return (LRESULT)HandleDarkCtlColorEdit((HDC)wParam);

    case WM_CTLCOLORBTN:
        return (LRESULT)HandleDarkCtlColorBtn((HDC)wParam);

    case WM_ERASEBKGND:
        return HandleDarkEraseBkgnd((HDC)wParam, hDlg);

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hDlg, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Window class for settings dialog
// ---------------------------------------------------------------------------
static const wchar_t* SETTINGS_CLASS = L"PhantomRecon_Settings";
static bool s_classRegistered = false;

static void EnsureSettingsClassRegistered(HINSTANCE hInst)
{
    if (s_classRegistered) return;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = SettingsDlgProc;
    wc.hInstance = hInst;
    wc.hbrBackground = CreateSolidBrush(DarkColors::Background);
    wc.lpszClassName = SETTINGS_CLASS;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    s_classRegistered = true;
}

// ---------------------------------------------------------------------------
// ShowSettingsDialog
// ---------------------------------------------------------------------------
bool ShowSettingsDialog(HWND hParent, HINSTANCE hInst)
{
    EnsureSettingsClassRegistered(hInst);

    // Load current settings
    s_dialogSettings = LoadAppSettings();
    s_dialogSaved = false;

    // Center on parent
    RECT parentRect;
    GetWindowRect(hParent, &parentRect);
    int x = parentRect.left + (parentRect.right - parentRect.left - DLG_W) / 2;
    int y = parentRect.top + (parentRect.bottom - parentRect.top - DLG_H) / 2;

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        SETTINGS_CLASS, L"Settings",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x, y, DLG_W, DLG_H,
        hParent, NULL, hInst, NULL);

    if (!hDlg) {
        DebugLog(L"ERROR: Failed to create settings window");
        return false;
    }

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    // Disable parent (modal behavior)
    EnableWindow(hParent, FALSE);

    // Run a local message loop for the dialog
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsWindow(hDlg)) break;
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Re-enable parent
    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);

    DebugLog(s_dialogSaved ? L"Settings dialog closed (saved)" : L"Settings dialog closed (cancelled)");
    return s_dialogSaved;
}
