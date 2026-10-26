#include "pch.h"
#include "MainCommands.h"

#include "AppPaths.h"
#include "CommandHelpers.h"
#include "GuiComponents.h"
#include "MainLayout.h"
#include "ScanCsv.h"
#include "ScanEngine.h"
#include "ScheduledScan.h"
#include "SettingsDialog.h"
#include "Theme.h"
#include "resource.h"

#include <sstream>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[MainCommands] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

// Ask where to write the CSV for a scan. "" when cancelled.
static std::wstring PromptForCsvPath(AppState& app, HWND hWnd, const std::wstring& stem)
{
    return BrowseForSaveFile(hWnd, L"Where should the scan results (CSV) go?", kFilterCsv, L"csv",
        DefaultReportPath(app, stem, L".csv"));
}

// The folder to scan: the default from Settings, or ask.
static std::wstring ChooseScanFolder(AppState& app, HWND hWnd, const wchar_t* title)
{
    std::wstring start = app.settings.defaultScanFolder;
    if (!start.empty() && DirectoryExists(start)) {
        std::wstring text = L"Scan this folder?\n\n" + start + L"\n\nChoose No to pick a different folder.";
        int answer = MessageBoxW(hWnd, text.c_str(), title, MB_YESNOCANCEL | MB_ICONQUESTION);
        if (answer == IDYES) return start;
        if (answer == IDCANCEL) return L"";
    }
    return BrowseForFolder(hWnd, title, start);
}

// ---------------------------------------------------------------------------
// File menu
// ---------------------------------------------------------------------------
static void CmdExit(AppState&, HWND hWnd)
{
    SendMessageW(hWnd, WM_CLOSE, 0, 0);
}

static void CmdSettings(AppState& app, HWND hWnd)
{
    std::wstring oldBaselineSetting = app.settings.baselinePath;
    int oldTheme = app.settings.theme;
    if (!ShowSettingsDialog(hWnd, app.hInstance, app.worker, app.settings)) return;

    if (app.settings.baselinePath != oldBaselineSetting && !app.progress.running) {
        app.baselineFilePath = EffectiveBaselinePath(app.settings);
        DebugLog(L"Active baseline now " + app.baselineFilePath);
    }
    if (app.settings.theme != oldTheme) {
        SetThemeMode(static_cast<ThemeMode>(app.settings.theme));
        ApplyThemeToMainWindow(app);
        ApplyThemeToAiSidebar(app.aiSidebar);
        if (app.findingsWindow) ApplyThemeToWindowTree(app.findingsWindow);
        if (app.detailWindow) ApplyThemeToWindowTree(app.detailWindow);
    }
    RefreshOperationLabel(app);
}

bool OpenScanResultsFile(AppState& app, HWND hWnd, const std::wstring& csvPath)
{
    if (RefuseWhileScanning(app, hWnd, L"open old results")) return false;
    std::vector<ScanRow> rows;
    if (!LoadRowsFromCsv(csvPath, rows)) {
        MessageBoxW(hWnd, (L"This file could not be read as Phantom Recon scan results:\n" + csvPath).c_str(),
            L"Open Scan Results", MB_OK | MB_ICONERROR);
        return false;
    }
    size_t count = rows.size();
    app.lastScan = LastScan();
    ShowRows(app, std::move(rows));

    std::wstringstream ss;
    ss << L"Loaded " << count << L" results from:\n" << csvPath;
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());
    DebugLog(L"Loaded " + std::to_wstring(count) + L" rows from " + csvPath);
    return true;
}

static void CmdOpenScanResults(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"open old results")) return;
    std::wstring csvPath = BrowseForOpenFile(hWnd, L"Open scan results (CSV)", kFilterCsv);
    if (!csvPath.empty()) OpenScanResultsFile(app, hWnd, csvPath);
}

static void CmdExportRows(AppState& app, HWND hWnd)
{
    if (app.results.ViewCount() == 0) {
        MessageBoxW(hWnd, L"There are no rows to export. Run a scan or open results first.", L"Export", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring path = BrowseForSaveFile(hWnd, L"Export the rows you can see", kFilterCsv, L"csv",
        DefaultReportPath(app, L"phantom-recon-rows", L".csv"));
    if (path.empty()) return;
    std::vector<ScanRow> rows = app.results.VisibleRows();
    if (!ExportRowsToCsv(path, rows)) {
        MessageBoxW(hWnd, (L"Could not write:\n" + path).c_str(), L"Export", MB_OK | MB_ICONERROR);
        return;
    }
    MessageBoxW(hWnd, (L"Exported " + std::to_wstring(rows.size()) + L" rows to:\n" + path).c_str(), L"Export",
        MB_OK | MB_ICONINFORMATION);
}

static void SetActiveBaseline(AppState& app, const std::wstring& path, Baseline&& loaded)
{
    {
        std::lock_guard<std::mutex> lock(app.baselineMutex);
        app.currentBaseline = std::move(loaded);
    }
    app.baselineFilePath = path;
    RefreshOperationLabel(app);
}

bool OpenBaselineFile(AppState& app, HWND hWnd, const std::wstring& path, bool confirm)
{
    if (RefuseWhileScanning(app, hWnd, L"change the active baseline")) return false;
    Baseline loaded;
    if (!loaded.LoadFromFile(path)) {
        MessageBoxW(hWnd, (L"This baseline could not be read. It may be damaged or from a newer version:\n" + path).c_str(),
            L"Open Baseline", MB_OK | MB_ICONERROR);
        return false;
    }
    size_t count = loaded.Count();
    std::wstring created = loaded.GetCreationTimeString();
    int age = loaded.GetAgeDays();
    SetActiveBaseline(app, path, std::move(loaded));
    DebugLog(L"Active baseline set to " + path);

    if (confirm) {
        std::wstringstream ss;
        ss << L"This baseline is now active for Full Scan and Fast Scan until the program closes.\n\n"
           << L"Files: " << count << L"\nTaken: " << created << L" (" << age << L" days ago)\nFile: " << path
           << L"\n\nTo make it permanent, choose it in File > Settings.";
        MessageBoxW(hWnd, ss.str().c_str(), L"Baseline Opened", MB_OK | MB_ICONINFORMATION);
    }
    return true;
}

static void CmdOpenBaseline(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"change the active baseline")) return;
    std::wstring path = BrowseForOpenFile(hWnd, L"Open a baseline and use it for comparisons", kFilterBaseline);
    if (!path.empty()) OpenBaselineFile(app, hWnd, path, true);
}

static void CmdImportBaseline(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"import a baseline")) return;
    std::wstring sourcePath = BrowseForOpenFile(hWnd, L"Import a baseline as the default", kFilterBaseline);
    if (sourcePath.empty()) return;

    Baseline imported;
    if (!imported.LoadFromFile(sourcePath)) {
        MessageBoxW(hWnd, L"That baseline could not be read. It may be damaged or from a newer version.", L"Import Baseline",
            MB_OK | MB_ICONERROR);
        return;
    }
    std::wstring target = EffectiveBaselinePath(app.settings);
    if (FileExists(target)) {
        std::wstring text = L"This replaces the default baseline:\n" + target + L"\n\nContinue?";
        if (MessageBoxW(hWnd, text.c_str(), L"Import Baseline", MB_YESNO | MB_ICONQUESTION) != IDYES) return;
    }
    if (!CopyFileW(sourcePath.c_str(), target.c_str(), FALSE)) {
        MessageBoxW(hWnd, (L"Could not copy the baseline to:\n" + target).c_str(), L"Import Baseline", MB_OK | MB_ICONERROR);
        return;
    }
    size_t count = imported.Count();
    SetActiveBaseline(app, target, std::move(imported));
    MessageBoxW(hWnd, (L"Baseline imported (" + std::to_wstring(count) + L" files) and now active.").c_str(),
        L"Import Baseline", MB_OK | MB_ICONINFORMATION);
    DebugLog(L"Baseline imported from " + sourcePath);
}

static void CmdExportBaseline(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"export the baseline")) return;
    if (!FileExists(app.baselineFilePath)) {
        MessageBoxW(hWnd, L"There is no baseline yet. Run Scans > Take Baseline first.", L"Export Baseline", MB_OK | MB_ICONWARNING);
        return;
    }
    std::wstring exportPath = BrowseForSaveFile(hWnd, L"Export the baseline", kFilterBaseline, L"prbl",
        DefaultReportPath(app, L"baseline", L".prbl"));
    if (exportPath.empty()) return;

    Baseline copy;
    if (!copy.LoadFromFile(app.baselineFilePath) || !copy.SaveToFile(exportPath)) {
        MessageBoxW(hWnd, L"The baseline could not be exported.", L"Export Baseline", MB_OK | MB_ICONERROR);
        return;
    }
    MessageBoxW(hWnd, (L"Exported " + std::to_wstring(copy.Count()) + L" files to:\n" + exportPath).c_str(),
        L"Export Baseline", MB_OK | MB_ICONINFORMATION);
}

static void CmdCompareBaselines(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"compare baselines")) return;
    MessageBoxW(hWnd, L"Pick the OLDER baseline first, then the NEWER one.", L"Compare Two Baselines", MB_OK | MB_ICONINFORMATION);
    std::wstring olderPath = BrowseForOpenFile(hWnd, L"Older baseline", kFilterBaseline);
    if (olderPath.empty()) return;
    std::wstring newerPath = BrowseForOpenFile(hWnd, L"Newer baseline", kFilterBaseline);
    if (newerPath.empty()) return;

    Baseline older, newer;
    if (!older.LoadFromFile(olderPath) || !newer.LoadFromFile(newerPath)) {
        MessageBoxW(hWnd, L"One of the baselines could not be read.", L"Compare Two Baselines", MB_OK | MB_ICONERROR);
        return;
    }
    std::vector<ScanRow> rows = DiffBaselines(older, newer, false);

    ScanSummary s;
    s.mode = ScanMode::FullScan;
    for (const ScanRow& r : rows) {
        if (r.status == L"NEW") s.added++;
        else if (r.status == L"CHANGED") s.changed++;
        else if (r.status == L"MISSING") s.missing++;
        else if (r.status == L"UPDATED") s.updated++;
        else if (r.status == L"KNOWN") s.known++;
        if (r.entry.malwareScore >= 7.0) s.highRisk++;
    }
    s.match = static_cast<int>(newer.Count()) - s.added - s.changed - s.updated - s.known;
    if (s.match < 0) s.match = 0;
    s.executables = static_cast<int>(newer.Count());
    s.finalState = L"Baseline comparison";

    app.lastScan.has = true;
    app.lastScan.summary = s;
    app.lastScan.title = L"Baseline comparison: " + FileNameOf(olderPath) + L" vs " + FileNameOf(newerPath);
    ShowRows(app, std::move(rows));

    std::wstringstream ss;
    ss << app.lastScan.title << L"\n\nNew " << s.added << L", changed " << s.changed << L", missing " << s.missing
       << L", updated by Microsoft " << s.updated << L", known good " << s.known << L", unchanged " << s.match;
    SetWindowTextW(app.controls.operationInfoLabel, ss.str().c_str());
}

// ---------------------------------------------------------------------------
// Scans menu
// ---------------------------------------------------------------------------
static void StartScan(AppState& app, ScanMode mode, const std::wstring& root, const std::wstring& csvPath)
{
    ScanRequest req;
    req.mode = mode;
    req.root = root;
    req.csvPath = csvPath;
    req.baselinePath = app.baselineFilePath;
    req.options = ScanOptionsFromSettings(app.settings);
    if (mode == ScanMode::Baseline) req.title = L"Baseline of " + root;
    else if (mode == ScanMode::FullScan) req.title = L"Full Scan of " + root;
    else req.title = L"Fast Scan of installed programs";
    EnableWindow(app.controls.cancelButton, TRUE);
    StartScanInBackground(app, req);
}

static void CmdBaselineScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"start another scan")) return;
    std::wstring text = L"A baseline records every program and script in a folder as \"known\".\n\n"
                        L"Take it while you trust this PC, for example right after a clean install or a full "
                        L"antivirus scan. Later scans report what changed since.\n\nIt will be saved to:\n" +
                        app.baselineFilePath;
    if (FileExists(app.baselineFilePath)) text += L"\n\nThe existing baseline there will be replaced when the scan finishes.";
    if (MessageBoxW(hWnd, text.c_str(), L"Take Baseline", MB_OKCANCEL | MB_ICONINFORMATION) != IDOK) return;

    std::wstring folder = ChooseScanFolder(app, hWnd, L"Folder to record in the baseline");
    if (folder.empty()) return;
    std::wstring csv = PromptForCsvPath(app, hWnd, L"baseline-scan");
    if (csv.empty()) return;
    StartScan(app, ScanMode::Baseline, folder, csv);
}

static void CmdFullScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"start another scan")) return;
    if (!LoadBaselineForComparison(app, hWnd, L"Full Scan")) return;
    std::wstring folder = ChooseScanFolder(app, hWnd, L"Folder to compare with the baseline");
    if (folder.empty()) return;
    std::wstring csv = PromptForCsvPath(app, hWnd, L"full-scan");
    if (csv.empty()) return;
    StartScan(app, ScanMode::FullScan, folder, csv);
}

static void CmdFastScan(AppState& app, HWND hWnd)
{
    if (RefuseWhileScanning(app, hWnd, L"start another scan")) return;
    if (!LoadBaselineForComparison(app, hWnd, L"Fast Scan")) return;
    std::wstring csv = PromptForCsvPath(app, hWnd, L"fast-scan");
    if (csv.empty()) return;
    StartScan(app, ScanMode::FastScan, L"", csv);
}

static void CmdCancelScan(AppState& app, HWND)
{
    if (!app.progress.running) return;
    app.progress.cancelRequested = true;
    {
        std::lock_guard<std::mutex> lock(app.progress.textMutex);
        app.progress.state = L"Cancelling...";
    }
    RefreshOperationLabel(app);
    DebugLog(L"Cancel requested by user");
}

static void CmdWeeklyScan(AppState& app, HWND hWnd)
{
    if (IsPortableMode()) {
        MessageBoxW(hWnd, L"Portable mode never creates scheduled tasks.", L"Weekly Fast Scan", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring error;
    if (IsWeeklyScanRegistered()) {
        if (MessageBoxW(hWnd, L"Stop the weekly Fast Scan and remove its scheduled task?", L"Weekly Fast Scan",
                MB_YESNO | MB_ICONQUESTION) != IDYES) return;
        if (!RemoveWeeklyScan(error)) {
            MessageBoxW(hWnd, (L"The task could not be removed:\n" + error).c_str(), L"Weekly Fast Scan", MB_OK | MB_ICONERROR);
            return;
        }
        MessageBoxW(hWnd, L"The weekly Fast Scan is off.", L"Weekly Fast Scan", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (!FileExists(app.baselineFilePath)) {
        MessageBoxW(hWnd, L"Take a baseline first. The weekly scan compares against it.", L"Weekly Fast Scan", MB_OK | MB_ICONWARNING);
        return;
    }
    std::wstring cli = JoinPath(GetExeDirectory(), L"PhantomReconCli.exe");
    if (!FileExists(cli)) {
        MessageBoxW(hWnd, (L"The weekly scan runs the command-line program, which should be next to this one:\n" + cli).c_str(),
            L"Weekly Fast Scan", MB_OK | MB_ICONERROR);
        return;
    }
    std::wstring reports = EffectiveReportsDirectory(app.settings);
    std::wstring text = L"This creates one task in Task Scheduler, named \"" + WeeklyScanTaskName() + L"\".\n"
                        L"It runs as you every Sunday at 10:00, compares installed programs with your baseline and "
                        L"writes an HTML report to:\n" + reports + L"\n\nYou can turn it off here or in Task Scheduler. Create it?";
    if (MessageBoxW(hWnd, text.c_str(), L"Weekly Fast Scan", MB_YESNO | MB_ICONQUESTION) != IDYES) return;
    EnsureDirectory(reports);
    if (!RegisterWeeklyScan(cli, app.baselineFilePath, reports, error)) {
        MessageBoxW(hWnd, (L"The task could not be created:\n" + error).c_str(), L"Weekly Fast Scan", MB_OK | MB_ICONERROR);
        return;
    }
    MessageBoxW(hWnd, L"The weekly Fast Scan is on.", L"Weekly Fast Scan", MB_OK | MB_ICONINFORMATION);
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------
bool DispatchFileScanCommand(AppState& app, HWND hWnd, int commandId)
{
    typedef void (*CommandHandler)(AppState&, HWND);
    struct Entry { int id; CommandHandler handler; };
    static const Entry kTable[] = {
        { IDM_EXIT,                  CmdExit },
        { ID_SETTINGS,               CmdSettings },
        { ID_FILE_OPEN_SCAN,         CmdOpenScanResults },
        { ID_FILE_EXPORT_ROWS,       CmdExportRows },
        { ID_FILE_OPEN_BASELINE,     CmdOpenBaseline },
        { ID_FILE_IMPORT_BASELINE,   CmdImportBaseline },
        { ID_FILE_EXPORT_BASELINE,   CmdExportBaseline },
        { ID_FILE_COMPARE_BASELINES, CmdCompareBaselines },
        { ID_SCANS_BASELINE,         CmdBaselineScan },
        { ID_SCANS_FULLSCAN,         CmdFullScan },
        { ID_SCANS_FASTSCAN,         CmdFastScan },
        { ID_SCANS_CANCEL,           CmdCancelScan },
        { ID_BUTTON_CANCEL,          CmdCancelScan },
        { ID_SCANS_WEEKLY,           CmdWeeklyScan },
    };
    for (const Entry& entry : kTable) {
        if (entry.id == commandId) {
            entry.handler(app, hWnd);
            return true;
        }
    }
    return false;
}

bool DispatchCommand(AppState& app, HWND hWnd, int commandId, int notifyCode)
{
    if (DispatchResultsCommand(app, hWnd, commandId, notifyCode)) return true;
    if (DispatchFileScanCommand(app, hWnd, commandId)) return true;
    if (DispatchReportCommand(app, hWnd, commandId)) return true;
    return false;
}

void UpdateMenuState(AppState& app, HMENU menu)
{
    if (!menu) return;
    bool scanning = app.progress.running.load();
    bool hasRows = app.results.ViewCount() > 0;
    bool hasSelection = SelectedRow(app) != nullptr;
    bool hasAudit = app.audit.hasResults;
    bool hasReport = hasAudit || app.results.TotalCount() > 0;

    auto enable = [&](UINT id, bool on) { EnableMenuItem(menu, id, MF_BYCOMMAND | (on ? MF_ENABLED : MF_GRAYED)); };
    auto check = [&](UINT id, bool on) { CheckMenuItem(menu, id, MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED)); };

    enable(ID_SCANS_BASELINE, !scanning);
    enable(ID_SCANS_FULLSCAN, !scanning);
    enable(ID_SCANS_FASTSCAN, !scanning);
    enable(ID_SCANS_CANCEL, scanning);
    enable(ID_FILE_OPEN_SCAN, !scanning);
    enable(ID_FILE_OPEN_BASELINE, !scanning);
    enable(ID_FILE_IMPORT_BASELINE, !scanning);
    enable(ID_FILE_EXPORT_BASELINE, !scanning);
    enable(ID_FILE_COMPARE_BASELINES, !scanning);
    enable(ID_FILE_EXPORT_ROWS, hasRows);
    enable(ID_SCANS_WEEKLY, !IsPortableMode());
    check(ID_SCANS_WEEKLY, !IsPortableMode() && IsWeeklyScanRegistered());

    enable(ID_AUDIT_RUN, !app.audit.running);
    enable(ID_AUDIT_SAVE_TEXT, hasAudit);
    enable(ID_REPORT_HTML, hasReport);
    enable(ID_REPORT_JSON, hasReport);
    enable(ID_REPORT_NAVIGATOR, hasReport);
    check(ID_REPORT_REDACT, app.settings.redactReports);

    enable(ID_RESULTS_DETAILS, hasSelection);
    enable(ID_RESULTS_COPY_PATH, hasSelection);
    enable(ID_RESULTS_COPY_SHA, hasSelection);
    enable(ID_RESULTS_OPEN_LOCATION, hasSelection);
    enable(ID_RESULTS_TRIAGE, hasSelection);
    enable(ID_RESULTS_CLEAR, hasRows && !scanning);
    enable(ID_HELP_SAMPLES, !scanning);
}
