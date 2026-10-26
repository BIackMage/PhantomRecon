#include "pch.h"
#include "SettingsDialog.h"

#include "AppMessages.h"
#include "AppPaths.h"
#include "GuiComponents.h"
#include "SettingsValues.h"
#include "StringConv.h"
#include "TextUtils.h"
#include "Theme.h"

#include <commctrl.h>
#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[Settings] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Settings file
// ---------------------------------------------------------------------------
static std::wstring GetSettingsPath()
{
    return AppFilePath(L"phantom_recon_settings.ini");
}

static std::wstring ReadIniString(const wchar_t* section, const wchar_t* key, const std::wstring& defaultVal,
                                  const std::wstring& file)
{
    std::vector<wchar_t> buf(8192, L'\0');
    GetPrivateProfileStringW(section, key, defaultVal.c_str(), buf.data(), static_cast<DWORD>(buf.size()), file.c_str());
    return buf.data();
}

static int ReadIniInt(const wchar_t* section, const wchar_t* key, int defaultVal, const std::wstring& file)
{
    return static_cast<int>(GetPrivateProfileIntW(section, key, defaultVal, file.c_str()));
}

static bool ReadIniBool(const wchar_t* section, const wchar_t* key, bool defaultVal, const std::wstring& file)
{
    return ReadIniInt(section, key, defaultVal ? 1 : 0, file) != 0;
}

static bool WriteIni(const wchar_t* section, const wchar_t* key, const std::wstring& value, const std::wstring& file)
{
    return WritePrivateProfileStringW(section, key, value.c_str(), file.c_str()) != FALSE;
}

static std::wstring FormatTemperature(double value)
{
    std::wstringstream ss;
    ss << std::fixed << std::setprecision(2) << value;
    return ss.str();
}

static int Clamp(int value, int low, int high)
{
    return value < low ? low : (value > high ? high : value);
}

// One line per entry in the dialog; ';' in the file.
static std::wstring ExclusionsForFile(const std::wstring& text)
{
    return JoinW(SplitAnyW(text, L";\r\n"), L";");
}

static std::wstring ExclusionsForDialog(const std::wstring& stored)
{
    return JoinW(SplitAnyW(stored, L";\r\n"), L"\r\n");
}

// ---------------------------------------------------------------------------
// Load / Save / Apply
// ---------------------------------------------------------------------------
AppSettings LoadAppSettings()
{
    AppSettings s;
    std::wstring ini = GetSettingsPath();
    if (!FileExists(ini)) {
        DebugLog(L"Settings file not found, using defaults");
        return s;
    }

    // Fallbacks come from the AppSettings defaults, so there is one place that defines them.
    s.llmEndpoint = ReadIniString(L"LLM", L"Endpoint", s.llmEndpoint, ini);
    s.llmModel = WideToUtf8(ReadIniString(L"LLM", L"Model", Utf8ToWide(s.llmModel), ini));
    s.llmMaxTokens = Clamp(ReadIniInt(L"LLM", L"MaxTokens", s.llmMaxTokens, ini), 1, 1000000);
    s.llmTemperature = ParseTemperatureText(ReadIniString(L"LLM", L"Temperature", FormatTemperature(s.llmTemperature), ini),
                                            LLMConfig{}.temperature);
    s.llmRedact = ReadIniBool(L"LLM", L"Redact", s.llmRedact, ini);
    s.llmMaxPromptChars = Clamp(ReadIniInt(L"LLM", L"MaxPromptChars", s.llmMaxPromptChars, ini), 1000, 1000000);

    s.scanExclusions = ReadIniString(L"Scan", L"Exclusions", s.scanExclusions, ini);
    s.defaultScanFolder = ReadIniString(L"Scan", L"DefaultFolder", s.defaultScanFolder, ini);
    s.baselinePath = ReadIniString(L"Scan", L"BaselineFile", s.baselinePath, ini);
    s.reportsDirectory = ReadIniString(L"Scan", L"ReportsFolder", s.reportsDirectory, ini);
    s.revocationMode = Clamp(ReadIniInt(L"Scan", L"Revocation", s.revocationMode, ini), 0, 2);
    s.fastScanDepth = Clamp(ReadIniInt(L"Scan", L"FastScanDepth", s.fastScanDepth, ini), 1, 8);
    s.fuzzyHashing = ReadIniBool(L"Scan", L"FuzzyHashing", s.fuzzyHashing, ini);

    s.theme = Clamp(ReadIniInt(L"Appearance", L"Theme", s.theme, ini), 0, 2);
    s.showGettingStarted = ReadIniBool(L"Appearance", L"ShowGettingStarted", s.showGettingStarted, ini);
    s.auditOnStartup = ReadIniBool(L"Appearance", L"AuditOnStartup", s.auditOnStartup, ini);
    s.redactReports = ReadIniBool(L"Reports", L"Redact", s.redactReports, ini);

    DebugLog(L"Settings loaded from: " + ini);
    return s;
}

bool SaveAppSettings(const AppSettings& s)
{
    std::wstring ini = GetSettingsPath();
    // Windows writes an INI file in the ANSI code page unless it already starts
    // with a UTF-16 BOM; Cyrillic or CJK paths would come back as "?".
    if (!EnsureUnicodeIniFile(ini)) DebugLog(L"Could not store the settings file as UTF-16: " + ini);
    bool ok = true;
    ok &= WriteIni(L"LLM", L"Endpoint", s.llmEndpoint, ini);
    ok &= WriteIni(L"LLM", L"Model", Utf8ToWide(s.llmModel), ini);
    ok &= WriteIni(L"LLM", L"MaxTokens", std::to_wstring(s.llmMaxTokens), ini);
    ok &= WriteIni(L"LLM", L"Temperature", FormatTemperature(s.llmTemperature), ini);
    ok &= WriteIni(L"LLM", L"Redact", s.llmRedact ? L"1" : L"0", ini);
    ok &= WriteIni(L"LLM", L"MaxPromptChars", std::to_wstring(s.llmMaxPromptChars), ini);

    ok &= WriteIni(L"Scan", L"Exclusions", ExclusionsForFile(s.scanExclusions), ini);
    ok &= WriteIni(L"Scan", L"DefaultFolder", s.defaultScanFolder, ini);
    ok &= WriteIni(L"Scan", L"BaselineFile", s.baselinePath, ini);
    ok &= WriteIni(L"Scan", L"ReportsFolder", s.reportsDirectory, ini);
    ok &= WriteIni(L"Scan", L"Revocation", std::to_wstring(s.revocationMode), ini);
    ok &= WriteIni(L"Scan", L"FastScanDepth", std::to_wstring(s.fastScanDepth), ini);
    ok &= WriteIni(L"Scan", L"FuzzyHashing", s.fuzzyHashing ? L"1" : L"0", ini);

    ok &= WriteIni(L"Appearance", L"Theme", std::to_wstring(s.theme), ini);
    ok &= WriteIni(L"Appearance", L"ShowGettingStarted", s.showGettingStarted ? L"1" : L"0", ini);
    ok &= WriteIni(L"Appearance", L"AuditOnStartup", s.auditOnStartup ? L"1" : L"0", ini);
    ok &= WriteIni(L"Reports", L"Redact", s.redactReports ? L"1" : L"0", ini);

    DebugLog((ok ? L"Settings saved to: " : L"Settings could NOT be fully saved to: ") + ini);
    return ok;
}

void ApplySettingsToLLMClient(const AppSettings& settings)
{
    LLMConfig cfg;
    cfg.endpoint = settings.llmEndpoint;
    cfg.model = settings.llmModel;
    cfg.maxTokens = settings.llmMaxTokens;
    cfg.temperature = SanitizeTemperature(settings.llmTemperature, LLMConfig{}.temperature);
    cfg.redact = settings.llmRedact;
    cfg.maxPromptChars = settings.llmMaxPromptChars;
    GetLLMClient().SetConfig(cfg);
    DebugLog(L"Settings applied to LLM client");
}

ScanOptions ScanOptionsFromSettings(const AppSettings& settings)
{
    ScanOptions options;
    ParseExclusions(settings.scanExclusions, options);
    RevocationMode mode = static_cast<RevocationMode>(Clamp(settings.revocationMode, 0, 2));
    if (mode == RevocationMode::Online && IsPortableMode()) mode = RevocationMode::CacheOnly;   // portable never goes online
    options.revocation = mode;
    options.fastScanDepth = Clamp(settings.fastScanDepth, 1, 8);
    options.computeFuzzyHash = settings.fuzzyHashing;
    options.redactCsv = settings.redactReports;   // "hide names" covers the scan CSV too
    return options;
}

std::wstring EffectiveBaselinePath(const AppSettings& settings)
{
    std::wstring p = TrimW(settings.baselinePath);
    return p.empty() ? AppFilePath(L"phantom_recon_baseline.prbl") : AbsolutePath(ExpandEnvironment(p));
}

std::wstring EffectiveReportsDirectory(const AppSettings& settings)
{
    std::wstring p = TrimW(settings.reportsDirectory);
    return p.empty() ? DefaultReportsDirectory() : AbsolutePath(ExpandEnvironment(p));
}

// ---------------------------------------------------------------------------
// Dialog layout
// ---------------------------------------------------------------------------
enum SettingsControlId {
    IDC_TABS = 3000,
    // AI
    IDC_ENDPOINT, IDC_MODEL, IDC_MAXTOKENS, IDC_TEMP, IDC_REDACT_AI, IDC_PROMPTCHARS, IDC_TEST, IDC_STATUS,
    // Scanning
    IDC_EXCLUSIONS, IDC_SCANFOLDER, IDC_SCANFOLDER_BROWSE, IDC_BASELINE, IDC_BASELINE_BROWSE,
    IDC_REPORTS, IDC_REPORTS_BROWSE, IDC_REVOCATION, IDC_DEPTH, IDC_FUZZY,
    // Appearance
    IDC_THEME, IDC_GETTING_STARTED, IDC_AUDIT_STARTUP, IDC_REDACT_REPORTS,
    // Buttons
    IDC_SAVE, IDC_CANCEL,
};

static const int DLG_W = 600;
static const int DLG_H = 560;
static const wchar_t* SETTINGS_CLASS = L"PhantomRecon_Settings";

enum SettingsTab { TabScanning = 0, TabAppearance = 1, TabAi = 2, TabCount = 3 };

// Per-dialog state. Lives on ShowSettingsDialog's stack for the dialog's lifetime
// and is reached through GWLP_USERDATA. No file-scope mutable state.
struct SettingsDialogState {
    AppSettings       settings;
    HWND              hTabs = NULL;
    HWND              hStatusLabel = NULL;
    HFONT             font = NULL;
    bool              saved = false;
    BackgroundWorker* worker = nullptr;
    PayloadTracker*   payloads = nullptr;
    std::vector<HWND> tabControls[TabCount];
};

static SettingsDialogState* GetDialogState(HWND hDlg)
{
    return reinterpret_cast<SettingsDialogState*>(GetWindowLongPtrW(hDlg, GWLP_USERDATA));
}

static std::wstring GetDlgItemString(HWND hDlg, int id)
{
    return GetWindowTextString(GetDlgItem(hDlg, id));
}

static bool IsChecked(HWND hDlg, int id)
{
    return SendMessageW(GetDlgItem(hDlg, id), BM_GETCHECK, 0, 0) == BST_CHECKED;
}

// Helper that creates controls on one tab and remembers them for show and hide.
struct Builder {
    HWND                 hDlg;
    HINSTANCE            hInst;
    SettingsDialogState& st;
    int                  tab;

    HWND Add(const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id, DWORD exStyle = 0)
    {
        HWND hwnd = CreateWindowExW(exStyle, cls, text, WS_CHILD | style, x, y, w, h, hDlg,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), hInst, NULL);
        SetControlFont(hwnd, st.font);
        if (tab >= 0) st.tabControls[tab].push_back(hwnd);
        return hwnd;
    }
    HWND Label(const wchar_t* text, int x, int y, int w, int h = 18)
    {
        return Add(L"STATIC", text, SS_LEFT, x, y, w, h, -1);
    }
    HWND Edit(const std::wstring& text, int x, int y, int w, int id, DWORD extra = 0, int h = 24)
    {
        return Add(L"EDIT", text.c_str(), WS_TABSTOP | ES_AUTOHSCROLL | extra, x, y, w, h, id, WS_EX_CLIENTEDGE);
    }
    HWND Button(const wchar_t* text, int x, int y, int w, int id, int h = 26)
    {
        return Add(L"BUTTON", text, WS_TABSTOP | BS_PUSHBUTTON, x, y, w, h, id);
    }
    HWND Check(const wchar_t* text, bool checked, int x, int y, int w, int id)
    {
        HWND hwnd = Add(L"BUTTON", text, WS_TABSTOP | BS_AUTOCHECKBOX, x, y, w, 22, id);
        SendMessageW(hwnd, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
        return hwnd;
    }
    HWND Combo(const std::vector<const wchar_t*>& items, int selected, int x, int y, int w, int id)
    {
        HWND hwnd = Add(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, x, y, w, 200, id);
        for (const wchar_t* item : items) SendMessageW(hwnd, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item));
        SendMessageW(hwnd, CB_SETCURSEL, static_cast<WPARAM>(selected), 0);
        return hwnd;
    }
};

static void BuildScanningTab(Builder b, const AppSettings& s, int left, int top, int width)
{
    int y = top;
    const int browseW = 90;
    const int fieldW = width - browseW - 8;

    b.Label(L"Skip these while scanning, one per line: folder names (node_modules), full paths (D:\\Games) or file types (*.log):",
        left, y, width, 34);
    y += 36;
    b.Edit(ExclusionsForDialog(s.scanExclusions), left, y, width, IDC_EXCLUSIONS,
        ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL, 84);
    y += 92;

    b.Label(L"Folders to scan by default, separated by ; (empty: ask every time):", left, y, width);
    y += 20;
    b.Edit(s.defaultScanFolder, left, y, fieldW, IDC_SCANFOLDER);
    b.Button(L"Browse...", left + fieldW + 8, y - 1, browseW, IDC_SCANFOLDER_BROWSE);
    y += 34;

    b.Label(L"Baseline file (empty: phantom_recon_baseline.prbl next to the program):", left, y, width);
    y += 20;
    b.Edit(s.baselinePath, left, y, fieldW, IDC_BASELINE);
    b.Button(L"Browse...", left + fieldW + 8, y - 1, browseW, IDC_BASELINE_BROWSE);
    y += 34;

    b.Label(L"Reports folder (empty: the reports folder next to the program):", left, y, width);
    y += 20;
    b.Edit(s.reportsDirectory, left, y, fieldW, IDC_REPORTS);
    b.Button(L"Browse...", left + fieldW + 8, y - 1, browseW, IDC_REPORTS_BROWSE);
    y += 36;

    b.Label(L"Certificate revocation check:", left, y + 4, 200);
    b.Combo({ L"Off", L"Windows cache only (no network)", L"Online (asks the certificate issuer)" },
        Clamp(s.revocationMode, 0, 2), left + 210, y, width - 210, IDC_REVOCATION);
    y += 34;

    b.Label(L"Fast Scan folder depth (1 to 8):", left, y + 4, 200);
    b.Edit(std::to_wstring(s.fastScanDepth), left + 210, y, 60, IDC_DEPTH, ES_NUMBER);
    y += 34;

    b.Check(L"Fuzzy hashing (finds near-copies of known files; a little slower)", s.fuzzyHashing, left, y, width, IDC_FUZZY);
}

static void BuildAppearanceTab(Builder b, const AppSettings& s, int left, int top, int width)
{
    int y = top;
    b.Label(L"Theme:", left, y + 4, 120);
    b.Combo({ L"Follow Windows", L"Dark", L"Light" }, Clamp(s.theme, 0, 2), left + 130, y, 200, IDC_THEME);
    y += 40;
    b.Check(L"Show the Getting Started window when the program starts", s.showGettingStarted, left, y, width, IDC_GETTING_STARTED);
    y += 30;
    b.Check(L"Run the security audit when the program starts", s.auditOnStartup, left, y, width, IDC_AUDIT_STARTUP);
    y += 30;
    b.Check(L"Hide user, computer and domain names in saved reports", s.redactReports, left, y, width, IDC_REDACT_REPORTS);
    y += 40;
    b.Label(L"Portable mode is on when the program runs from a USB drive, with --portable, or next to a file named "
            L"portable.flag. It keeps everything next to the program and never creates scheduled tasks.",
        left, y, width, 52);
    y += 56;
    b.Label(IsPortableMode() ? L"Portable mode: ON" : L"Portable mode: off", left, y, width);
}

static void BuildAiTab(Builder b, SettingsDialogState& st, int left, int top, int width)
{
    const AppSettings& s = st.settings;
    int y = top;
    b.Label(L"The AI panel is optional. Nothing is sent anywhere until you press one of its buttons. "
            L"The default address is a model running on this computer.", left, y, width, 36);
    y += 42;

    b.Label(L"Endpoint URL:", left, y, width);
    y += 20;
    b.Edit(s.llmEndpoint, left, y, width, IDC_ENDPOINT);
    y += 34;

    b.Label(L"Model name:", left, y, width);
    y += 20;
    b.Edit(Utf8ToWide(s.llmModel), left, y, width, IDC_MODEL);
    y += 34;

    const int halfW = (width - 10) / 2;
    b.Label(L"Max tokens in a reply:", left, y, halfW);
    b.Label(L"Temperature (0 to 2):", left + halfW + 10, y, halfW);
    y += 20;
    b.Edit(std::to_wstring(s.llmMaxTokens), left, y, halfW, IDC_MAXTOKENS, ES_NUMBER);
    b.Edit(FormatTemperature(s.llmTemperature), left + halfW + 10, y, halfW, IDC_TEMP);
    y += 36;

    b.Check(L"Hide user, computer and domain names before sending", s.llmRedact, left, y, width, IDC_REDACT_AI);
    y += 30;

    b.Label(L"Longest message sent, in characters (longer text goes in parts):", left, y + 4, 380);
    b.Edit(std::to_wstring(s.llmMaxPromptChars), left + 390, y, 90, IDC_PROMPTCHARS, ES_NUMBER);
    y += 40;

    b.Button(L"Test Connection", left, y, 140, IDC_TEST, 30);
    st.hStatusLabel = b.Add(L"STATIC", L"", SS_LEFT | SS_CENTERIMAGE, left + 150, y, width - 150, 30, IDC_STATUS);
}

static void ShowTab(SettingsDialogState& st, int tab)
{
    for (int t = 0; t < TabCount; ++t) {
        for (HWND h : st.tabControls[t]) ShowWindow(h, t == tab ? SW_SHOW : SW_HIDE);
    }
}

static void OnDialogCreate(HWND hDlg, SettingsDialogState& st, HINSTANCE hInst)
{
    st.font = CreateUiFont(hDlg, 0, false);
    const int m = 16;

    RECT rc;
    GetClientRect(hDlg, &rc);
    const int clientW = rc.right - rc.left;
    const int clientH = rc.bottom - rc.top;

    // Only the tab strip is shown. Its page area would paint white in dark mode,
    // so the controls sit on the dialog's own background below the strip.
    Builder common{ hDlg, hInst, st, -1 };
    const int stripH = 30;
    st.hTabs = common.Add(WC_TABCONTROLW, L"", WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP,
        m, m, clientW - 2 * m, stripH, IDC_TABS);
    const wchar_t* names[TabCount] = { L"Scanning", L"Appearance", L"AI panel" };
    for (int i = 0; i < TabCount; ++i) {
        TCITEMW item = {};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<LPWSTR>(names[i]);
        TabCtrl_InsertItem(st.hTabs, i, &item);
    }

    const int left = m + 4;
    const int top = m + stripH + 12;
    const int width = clientW - 2 * m - 8;

    BuildScanningTab(Builder{ hDlg, hInst, st, TabScanning }, st.settings, left, top, width);
    BuildAppearanceTab(Builder{ hDlg, hInst, st, TabAppearance }, st.settings, left, top, width);
    BuildAiTab(Builder{ hDlg, hInst, st, TabAi }, st, left, top, width);

    // Controls drawn over the tab control must sit above it in the Z order.
    for (int t = 0; t < TabCount; ++t) {
        for (HWND h : st.tabControls[t]) SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }

    const int btnW = 100;
    const int btnH = 30;
    const int btnY = clientH - m - btnH;
    common.Add(L"BUTTON", L"Save", WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, clientW - m - 2 * btnW - 10, btnY, btnW, btnH, IDC_SAVE);
    common.Add(L"BUTTON", L"Cancel", WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, clientW - m - btnW, btnY, btnW, btnH, IDC_CANCEL);

    ShowTab(st, TabScanning);
    ApplyThemeToWindowTree(hDlg);
}

// Test Connection: build a throwaway client from the field values so the live
// singleton is untouched until Save, then run it on the worker.
static void OnTestConnection(HWND hDlg, SettingsDialogState& st)
{
    SetWindowTextW(st.hStatusLabel, L"Testing connection...");
    DebugLog(L"Testing LLM connection from settings dialog");

    LLMConfig testCfg;
    testCfg.endpoint = GetDlgItemString(hDlg, IDC_ENDPOINT);
    testCfg.model = WideToUtf8(GetDlgItemString(hDlg, IDC_MODEL));
    testCfg.maxTokens = _wtoi(GetDlgItemString(hDlg, IDC_MAXTOKENS).c_str());
    if (testCfg.maxTokens < 1) testCfg.maxTokens = LLMConfig{}.maxTokens;
    testCfg.temperature = ParseTemperatureText(GetDlgItemString(hDlg, IDC_TEMP), LLMConfig{}.temperature);
    testCfg.redact = IsChecked(hDlg, IDC_REDACT_AI);

    if (!st.worker || !st.payloads) {
        SetWindowTextW(st.hStatusLabel, L"Failed: no background worker");
        return;
    }

    PayloadTracker* tracker = st.payloads;
    st.worker->Run([hDlg, tracker, testCfg]() {
        LLMClient testClient;
        testClient.SetConfig(testCfg);
        bool ok = testClient.TestConnection();
        std::wstring text = ok ? L"Connected." : L"Failed: " + Utf8ToWide(testClient.GetLastError());
        DebugLog(ok ? L"Test connection: SUCCESS" : L"Test connection: FAILED");
        PostPayload(hDlg, WM_APP_STATUS_TEXT, new std::wstring(text), *tracker);
    });
}

// Close the dialog. The owner is enabled first: destroying the active window
// while its owner is still disabled makes Windows activate some other program,
// and the main window flickers behind it before ShowSettingsDialog re-enables it.
static void CloseSettingsDialog(HWND hDlg)
{
    HWND owner = GetWindow(hDlg, GW_OWNER);
    if (owner) EnableWindow(owner, TRUE);
    DestroyWindow(hDlg);
    DebugLog(L"Settings dialog closed with the owner enabled first");
}

static void OnBrowse(HWND hDlg, int editId, bool folder)
{
    std::wstring current = GetDlgItemString(hDlg, editId);
    std::wstring picked;
    if (folder) {
        picked = BrowseForFolder(hDlg, L"Choose a folder", current);
    }
    else {
        picked = BrowseForSaveFile(hDlg, L"Baseline file", kFilterBaseline, L"prbl",
            current.empty() ? AppFilePath(L"phantom_recon_baseline.prbl") : current);
    }
    if (!picked.empty()) SetWindowTextW(GetDlgItem(hDlg, editId), picked.c_str());
}

static void OnSave(HWND hDlg, SettingsDialogState& st)
{
    AppSettings& s = st.settings;
    s.llmEndpoint = TrimW(GetDlgItemString(hDlg, IDC_ENDPOINT));
    if (s.llmEndpoint.empty()) s.llmEndpoint = LLMConfig{}.endpoint;
    s.llmModel = WideToUtf8(TrimW(GetDlgItemString(hDlg, IDC_MODEL)));
    s.llmMaxTokens = _wtoi(GetDlgItemString(hDlg, IDC_MAXTOKENS).c_str());
    if (s.llmMaxTokens < 1) s.llmMaxTokens = LLMConfig{}.maxTokens;
    s.llmTemperature = ParseTemperatureText(GetDlgItemString(hDlg, IDC_TEMP), LLMConfig{}.temperature);
    s.llmRedact = IsChecked(hDlg, IDC_REDACT_AI);
    s.llmMaxPromptChars = Clamp(_wtoi(GetDlgItemString(hDlg, IDC_PROMPTCHARS).c_str()), 1000, 1000000);

    s.scanExclusions = ExclusionsForFile(GetDlgItemString(hDlg, IDC_EXCLUSIONS));
    s.defaultScanFolder = TrimW(GetDlgItemString(hDlg, IDC_SCANFOLDER));
    s.baselinePath = TrimW(GetDlgItemString(hDlg, IDC_BASELINE));
    s.reportsDirectory = TrimW(GetDlgItemString(hDlg, IDC_REPORTS));
    s.revocationMode = Clamp(static_cast<int>(SendMessageW(GetDlgItem(hDlg, IDC_REVOCATION), CB_GETCURSEL, 0, 0)), 0, 2);
    s.fastScanDepth = Clamp(_wtoi(GetDlgItemString(hDlg, IDC_DEPTH).c_str()), 1, 8);
    s.fuzzyHashing = IsChecked(hDlg, IDC_FUZZY);

    s.theme = Clamp(static_cast<int>(SendMessageW(GetDlgItem(hDlg, IDC_THEME), CB_GETCURSEL, 0, 0)), 0, 2);
    s.showGettingStarted = IsChecked(hDlg, IDC_GETTING_STARTED);
    s.auditOnStartup = IsChecked(hDlg, IDC_AUDIT_STARTUP);
    s.redactReports = IsChecked(hDlg, IDC_REDACT_REPORTS);

    if (!SaveAppSettings(s)) {
        MessageBoxW(hDlg, (L"The settings could not be written to:\n" + GetSettingsPath() +
            L"\n\nThey apply until the program closes.").c_str(), L"Settings", MB_OK | MB_ICONWARNING);
    }
    ApplySettingsToLLMClient(s);

    st.saved = true;
    DebugLog(L"Settings saved and applied");
    CloseSettingsDialog(hDlg);
}

static LRESULT OnCommand(HWND hDlg, SettingsDialogState& st, int id)
{
    switch (id) {
    case IDC_TEST:              OnTestConnection(hDlg, st);             return 0;
    case IDC_SAVE:              OnSave(hDlg, st);                       return 0;
    case IDC_CANCEL:            CloseSettingsDialog(hDlg);              return 0;
    case IDCANCEL:              CloseSettingsDialog(hDlg);              return 0;
    case IDC_SCANFOLDER_BROWSE: OnBrowse(hDlg, IDC_SCANFOLDER, true);   return 0;
    case IDC_BASELINE_BROWSE:   OnBrowse(hDlg, IDC_BASELINE, false);    return 0;
    case IDC_REPORTS_BROWSE:    OnBrowse(hDlg, IDC_REPORTS, true);      return 0;
    default:                    return 1;
    }
}

static LRESULT CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hDlg, msg, wParam, lParam);
    }

    SettingsDialogState* st = GetDialogState(hDlg);

    switch (msg) {
    case WM_CREATE:
        if (st) OnDialogCreate(hDlg, *st, reinterpret_cast<CREATESTRUCTW*>(lParam)->hInstance);
        return 0;

    case WM_COMMAND:
        if (st && OnCommand(hDlg, *st, LOWORD(wParam)) == 0) return 0;
        break;

    case WM_NOTIFY: {
        NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (st && hdr->hwndFrom == st->hTabs && hdr->code == TCN_SELCHANGE) {
            ShowTab(*st, TabCtrl_GetCurSel(st->hTabs));
            return 0;
        }
        break;
    }

    case WM_APP_STATUS_TEXT: {
        std::unique_ptr<std::wstring> text = TakePayload<std::wstring>(st ? st->payloads : nullptr, lParam);
        if (st && text) SetWindowTextW(st->hStatusLabel, text->c_str());
        return 0;
    }

    case WM_NCDESTROY:
        // A test reply already posted to this dialog is dropped with it; free it.
        if (st && st->payloads) st->payloads->FreeFor(hDlg);
        break;

    case WM_CTLCOLORSTATIC:
        return reinterpret_cast<LRESULT>(ThemeCtlColorStatic(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLOREDIT:
        return reinterpret_cast<LRESULT>(ThemeCtlColorEdit(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORLISTBOX:
        return reinterpret_cast<LRESULT>(ThemeCtlColorListBox(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(ThemeCtlColorButton(reinterpret_cast<HDC>(wParam)));
    case WM_ERASEBKGND:
        return ThemeEraseBackground(reinterpret_cast<HDC>(wParam), hDlg);

    case WM_CLOSE:
        CloseSettingsDialog(hDlg);
        return 0;

    case WM_DESTROY:
        if (st && st->font) {
            DeleteObject(st->font);
            st->font = NULL;
        }
        return 0;
    }

    return DefWindowProcW(hDlg, msg, wParam, lParam);
}

static void EnsureSettingsClassRegistered(HINSTANCE hInst)
{
    WNDCLASSEXW existing = {};
    existing.cbSize = sizeof(existing);
    if (GetClassInfoExW(hInst, SETTINGS_CLASS, &existing)) return;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = SettingsDlgProc;
    wc.hInstance = hInst;
    wc.hbrBackground = NULL;   // WM_ERASEBKGND paints the theme colour
    wc.lpszClassName = SETTINGS_CLASS;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
}

bool ShowSettingsDialog(HWND hParent, HINSTANCE hInst, BackgroundWorker& worker, PayloadTracker& payloads,
                        AppSettings& settings)
{
    EnsureSettingsClassRegistered(hInst);

    SettingsDialogState st;
    st.settings = settings;
    st.worker = &worker;
    st.payloads = &payloads;

    RECT parentRect;
    GetWindowRect(hParent, &parentRect);
    int x = parentRect.left + (parentRect.right - parentRect.left - DLG_W) / 2;
    int y = parentRect.top + (parentRect.bottom - parentRect.top - DLG_H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;

    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, SETTINGS_CLASS, L"Settings",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, x, y, DLG_W, DLG_H, hParent, NULL, hInst, &st);
    if (!hDlg) {
        DebugLog(L"ERROR: Failed to create settings window");
        return false;
    }

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    EnableWindow(hParent, FALSE);

    // Local message loop until the dialog window is gone. IsDialogMessage gives
    // Tab and Enter their usual meaning. A WM_QUIT seen here is re-posted so the
    // main loop still ends.
    MSG msg;
    bool quit = false;
    int quitCode = 0;
    while (IsWindow(hDlg)) {
        BOOL got = GetMessageW(&msg, NULL, 0, 0);
        if (got == 0) {
            quit = true;
            quitCode = static_cast<int>(msg.wParam);
            break;
        }
        if (got == -1) break;
        if (IsDialogMessageW(hDlg, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (IsWindow(hDlg)) CloseSettingsDialog(hDlg);

    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);
    if (quit) PostQuitMessage(quitCode);

    if (st.saved) settings = st.settings;
    DebugLog(st.saved ? L"Settings dialog closed (saved)" : L"Settings dialog closed (cancelled)");
    return st.saved;
}
