#include "pch.h"
#include "MainCommands.h"

#include "AppDialogs.h"
#include "AppPaths.h"
#include "AuditController.h"
#include "CommandHelpers.h"
#include "FindingsWindow.h"
#include "FixScript.h"
#include "GuiComponents.h"
#include "MainLayout.h"
#include "Reports.h"
#include "SampleData.h"
#include "ScanEngine.h"
#include "resource.h"

#include <memory>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[ReportCommands] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Audit menu
// ---------------------------------------------------------------------------
static void CmdAuditRun(AppState& app, HWND)
{
    StartAuditInBackground(app);
}

static void CmdAuditFindings(AppState& app, HWND)
{
    ShowFindingsWindow(app);
}

static void CmdAuditSaveText(AppState& app, HWND hWnd)
{
    if (!app.audit.hasResults) {
        MessageBoxW(hWnd, L"The audit has not finished yet.", L"Save Audit", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring path = BrowseForSaveFile(hWnd, L"Save the audit as text", kFilterText, L"txt",
        DefaultReportPath(app, L"security-audit", L".txt"));
    if (path.empty()) return;
    if (!WriteSecurityReport(path, app.settings.redactReports ? RedactAuditResults(app.audit.results) : app.audit.results)) {
        MessageBoxW(hWnd, (L"Could not write:\n" + path).c_str(), L"Save Audit", MB_OK | MB_ICONERROR);
        return;
    }
    DebugLog(L"Audit text saved to " + path);
    OpenWithShell(path);
}

// ---------------------------------------------------------------------------
// Reports menu
// ---------------------------------------------------------------------------
enum class ReportKind { Html, Json, Navigator };

static void SaveReport(AppState& app, HWND hWnd, ReportKind kind)
{
    if (!app.audit.hasResults && app.results.TotalCount() == 0) {
        MessageBoxW(hWnd, L"There is nothing to report yet. Wait for the audit, or run a scan.", L"Report", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const wchar_t* title = kind == ReportKind::Html ? L"Save the HTML report"
                         : kind == ReportKind::Json ? L"Save the JSON report" : L"Save the ATT&CK Navigator layer";
    const wchar_t* filter = kind == ReportKind::Html ? kFilterHtml : kFilterJson;
    const wchar_t* ext = kind == ReportKind::Html ? L"html" : L"json";
    std::wstring stem = kind == ReportKind::Html ? L"phantom-recon-report"
                      : kind == ReportKind::Json ? L"phantom-recon-report" : L"phantom-recon-navigator";
    std::wstring path = BrowseForSaveFile(hWnd, title, filter, ext,
        DefaultReportPath(app, stem, kind == ReportKind::Html ? L".html" : L".json"));
    if (path.empty()) return;

    ReportData data = BuildReportData(app);
    std::wstring text = kind == ReportKind::Html ? BuildHtmlReport(data)
                      : kind == ReportKind::Json ? BuildJsonReport(data) : BuildNavigatorReport(data);
    if (!SaveReportFile(path, text)) {
        MessageBoxW(hWnd, (L"Could not write:\n" + path).c_str(), L"Report", MB_OK | MB_ICONERROR);
        return;
    }
    DebugLog(L"Report saved to " + path + (data.redacted ? L" (names hidden)" : L""));

    if (kind == ReportKind::Html) {
        OpenWithShell(path);
    }
    else if (kind == ReportKind::Navigator) {
        MessageBoxW(hWnd, (L"Saved:\n" + path + L"\n\nOpen MITRE ATT&CK Navigator, choose \"Open Existing Layer\", "
            L"then \"Upload from local\" and pick this file.").c_str(), L"ATT&CK Navigator Layer", MB_OK | MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(hWnd, (L"Saved:\n" + path).c_str(), L"JSON Report", MB_OK | MB_ICONINFORMATION);
    }
}

static const wchar_t kFilterPowerShell[] = L"PowerShell script (*.ps1)\0*.ps1\0All files (*.*)\0*.*\0";

void SaveFixScriptFiles(AppState& app, HWND owner)
{
    if (!app.audit.hasResults) {
        MessageBoxW(owner, L"The audit has not finished yet.", L"Fix Script", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring path = BrowseForSaveFile(owner, L"Save the fix script", kFilterPowerShell, L"ps1",
        DefaultReportPath(app, L"phantom-recon-fix", L".ps1"));
    if (path.empty()) return;
    if (!HasPs1Extension(path)) path += L".ps1";   // PowerShell's -File runs nothing else

    // The dialog asked about the fix script only; an older undo script may hold the
    // only way back from steps applied earlier, so it is not replaced without asking.
    std::wstring undoPath = UndoScriptPathFor(path);
    if (FileExists(undoPath)) {
        std::wstring ask = L"An undo script with this name already exists:\n" + undoPath +
            L"\n\nIt may be the only record of how to undo steps you applied from an earlier plan. Replace it?";
        if (MessageBoxW(owner, ask.c_str(), L"Fix Script", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
            DebugLog(L"Fix script not saved: the user kept the existing undo script " + undoPath);
            return;
        }
    }

    bool redact = app.settings.redactReports;
    FixScriptOptions options;
    options.redacted = redact;
    std::wstring error;
    if (!SaveFixScripts(path, redact ? RedactAuditResults(app.audit.results) : app.audit.results, options, undoPath, error)) {
        MessageBoxW(owner, (L"Could not save the fix script:\n" + error).c_str(), L"Fix Script", MB_OK | MB_ICONERROR);
        return;
    }
    DebugLog(L"Fix script saved to " + path + L" and " + undoPath + (redact ? L" (names hidden)" : L""));
    // Not opened with the shell: on some PCs the default action for .ps1 runs it.
    std::wstring text = L"Saved:\n" + path + L"\n" + undoPath +
        L"\n\nOpen the fix script in a text editor and read every step before you run it. Phantom Recon does not run it."
        L"\n\nTo see the steps without changing anything, in PowerShell:\n"
        L"powershell -NoProfile -ExecutionPolicy Bypass -File \"" + path + L"\" -ListOnly";
    if (redact) text += L"\n\nNames are hidden, so steps that name files, services or networks on this PC are done by hand.";
    MessageBoxW(owner, text.c_str(), L"Fix Script", MB_OK | MB_ICONINFORMATION);
}

static void CmdReportFixScript(AppState& app, HWND hWnd) { SaveFixScriptFiles(app, hWnd); }

static void CmdReportHtml(AppState& app, HWND hWnd)      { SaveReport(app, hWnd, ReportKind::Html); }
static void CmdReportJson(AppState& app, HWND hWnd)      { SaveReport(app, hWnd, ReportKind::Json); }
static void CmdReportNavigator(AppState& app, HWND hWnd) { SaveReport(app, hWnd, ReportKind::Navigator); }

static void CmdReportRedact(AppState& app, HWND)
{
    app.settings.redactReports = !app.settings.redactReports;
    SaveAppSettings(app.settings);
    DebugLog(app.settings.redactReports ? L"Reports will hide names" : L"Reports will show names");
}

static void CmdReportOpenFolder(AppState& app, HWND)
{
    std::wstring dir = EffectiveReportsDirectory(app.settings);
    EnsureDirectory(dir);
    OpenWithShell(dir);
}

// ---------------------------------------------------------------------------
// Help menu
// ---------------------------------------------------------------------------
static void CmdAbout(AppState& app, HWND hWnd)
{
    ShowAboutDialog(hWnd, app.hInstance);
}

static void CmdGettingStarted(AppState& app, HWND hWnd)
{
    GettingStartedResult r = ShowGettingStarted(hWnd, app.hInstance, app.settings.showGettingStarted);
    if (r.showAtStartup != app.settings.showGettingStarted) {
        app.settings.showGettingStarted = r.showAtStartup;
        SaveAppSettings(app.settings);
    }
    if (r.createSamples) CreateSamplePackAndScan(app, hWnd);
}

static void CmdSamples(AppState& app, HWND hWnd)
{
    CreateSamplePackAndScan(app, hWnd);
}

void CreateSamplePackAndScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"create the sample pack")) return;
    MessageBoxW(hWnd, L"Pick a folder. A new \"PhantomRecon Samples\" folder is created inside it with a few harmless demo "
        L"files and a demo baseline. Nothing in it runs anything.", L"Sample Pack", MB_OK | MB_ICONINFORMATION);
    std::wstring parent = BrowseForFolder(hWnd, L"Where should the sample pack go?", L"");
    if (parent.empty()) return;

    std::wstring folder = JoinPath(parent, L"PhantomRecon Samples");
    for (int n = 2; DirectoryExists(folder) && n < 100; ++n) {
        folder = JoinPath(parent, L"PhantomRecon Samples " + std::to_wstring(n));
    }
    CreateSamplePackInFolder(app, hWnd, folder, true);
}

void CreateSamplePackInFolder(AppState& app, HWND hWnd, const std::wstring& folder, bool askBeforeScan)
{
    if (RefuseWhileScanning(app, hWnd, L"create the sample pack")) return;
    SamplePackResult pack = CreateSamplePack(folder);
    if (!pack.ok) {
        MessageBoxW(hWnd, (L"The sample pack could not be created:\n" + pack.error).c_str(), L"Sample Pack", MB_OK | MB_ICONERROR);
        return;
    }
    DebugLog(L"Sample pack written to " + pack.folder);

    if (askBeforeScan) {
        std::wstring text = L"Sample pack written to:\n" + pack.folder +
            L"\n\nRun a Full Scan of it against its demo baseline now? Expect 1 NEW, 1 CHANGED and 1 MISSING file. "
            L"Your own baseline is not touched.";
        if (MessageBoxW(hWnd, text.c_str(), L"Sample Pack", MB_YESNO | MB_ICONQUESTION) != IDYES) {
            OpenWithShell(pack.folder);
            return;
        }
    }

    // The demo baseline belongs to this one scan only. The user's active baseline
    // (app.currentBaseline and app.baselineFilePath) is not touched, so later scans,
    // Take Baseline and the weekly task keep using the user's own file.
    std::shared_ptr<Baseline> demo = std::make_shared<Baseline>();
    if (!demo->LoadFromFile(pack.baselinePath)) {
        MessageBoxW(hWnd, L"The demo baseline could not be read.", L"Sample Pack", MB_OK | MB_ICONERROR);
        return;
    }
    demo->ResetSeenFlags();

    ScanRequest req;
    req.mode = ScanMode::FullScan;
    req.roots = { pack.folder };
    req.csvPath = JoinPath(pack.folder, L"sample-scan.csv");
    req.baselinePath = pack.baselinePath;
    req.comparisonBaseline = demo;
    req.options = ScanOptionsFromSettings(app.settings);
    req.options.excludeExtensions.push_back(L".csv");
    req.title = L"Full Scan of the sample pack";
    EnableWindow(app.controls.cancelButton, TRUE);
    StartScanInBackground(app, req);
    DebugLog(L"Sample scan started against its own demo baseline; active baseline stays " + app.baselineFilePath);
}

bool DispatchReportCommand(AppState& app, HWND hWnd, int commandId)
{
    typedef void (*CommandHandler)(AppState&, HWND);
    struct Entry { int id; CommandHandler handler; };
    static const Entry kTable[] = {
        { ID_AUDIT_RUN,            CmdAuditRun },
        { ID_AUDIT_FINDINGS,       CmdAuditFindings },
        { ID_FINDINGS_BUTTON,      CmdAuditFindings },
        { ID_AUDIT_SAVE_TEXT,      CmdAuditSaveText },
        { ID_REPORT_HTML,          CmdReportHtml },
        { ID_REPORT_JSON,          CmdReportJson },
        { ID_REPORT_NAVIGATOR,     CmdReportNavigator },
        { ID_REPORT_FIX_SCRIPT,    CmdReportFixScript },
        { ID_REPORT_REDACT,        CmdReportRedact },
        { ID_REPORT_OPEN_FOLDER,   CmdReportOpenFolder },
        { IDM_ABOUT,               CmdAbout },
        { ID_HELP_GETTING_STARTED, CmdGettingStarted },
        { ID_HELP_SAMPLES,         CmdSamples },
    };
    for (const Entry& entry : kTable) {
        if (entry.id == commandId) {
            entry.handler(app, hWnd);
            return true;
        }
    }
    return false;
}
