#include "pch.h"
#include "CommandHelpers.h"

#include "AppPaths.h"
#include "GuiComponents.h"
#include "MainLayout.h"

#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[CommandHelpers] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

bool RefuseWhileScanning(AppState& app, HWND hWnd, const wchar_t* what)
{
    if (!app.progress.running) return false;
    std::wstring text = std::wstring(L"A scan is running. Cancel it or wait for it to finish before you ") + what + L".";
    MessageBoxW(hWnd, text.c_str(), L"Scan In Progress", MB_OK | MB_ICONINFORMATION);
    return true;
}

// The file is read into a local Baseline and the questions are asked with no lock
// held (a message box runs a message loop). The lock is taken only for the swap.
bool LoadBaselineForComparison(AppState& app, HWND hWnd, const wchar_t* scanName)
{
    std::wstring path = app.baselineFilePath;
    Baseline loaded;
    if (!loaded.LoadFromFile(path)) {
        std::wstring text = FileExists(path)
            ? L"The baseline file could not be read. It may be damaged or from a newer version:\n" + path
            : L"There is no baseline yet. Run Scans > Take Baseline first, on a PC you trust.\n\nExpected at:\n" + path;
        MessageBoxW(hWnd, text.c_str(), scanName, MB_OK | MB_ICONWARNING);
        return false;
    }
    DebugLog(std::wstring(scanName) + L": loaded baseline with " + std::to_wstring(loaded.Count()) + L" entries");

    if (loaded.IsOlderThan(30)) {
        std::wstringstream ageMsg;
        ageMsg << L"The baseline is " << loaded.GetAgeDays()
               << L" days old (taken " << loaded.GetCreationTimeString() << L").\n\n"
               << L"Programs updated since then will show as CHANGED. Taking a fresh baseline on a PC you trust "
               << L"keeps the list short.\n\nCompare against this baseline anyway?";
        if (MessageBoxW(hWnd, ageMsg.str().c_str(), L"Old Baseline", MB_YESNO | MB_ICONWARNING) != IDYES) {
            return false;
        }
    }
    loaded.ResetSeenFlags();
    {
        std::lock_guard<std::mutex> lock(app.baselineMutex);
        app.currentBaseline = std::move(loaded);
    }
    DebugLog(std::wstring(scanName) + L": baseline swapped in without holding the lock across any dialog");
    return true;
}

void ShowRows(AppState& app, std::vector<ScanRow> rows)
{
    app.results.SetRows(std::move(rows));
    RefreshResultsList(app.controls.resultsListView, app.results);
    UpdateSortArrow(app.controls.resultsListView, app.results);
    UpdateResultCount(app);
}

const ScanRow* SelectedRow(AppState& app)
{
    int sel = SelectedResultIndex(app.controls.resultsListView);
    if (sel < 0 || static_cast<size_t>(sel) >= app.results.ViewCount()) return nullptr;
    return &app.results.ViewRow(static_cast<size_t>(sel));
}

ReportData BuildReportData(AppState& app)
{
    ReportData data;
    FillReportHost(data, false);
    if (app.audit.hasResults) {
        data.hasAudit = true;
        data.audit = app.audit.results;
        data.score = app.audit.score;
        if (app.audit.hasHistory) {
            data.hasHistory = true;
            data.history = app.audit.history;
            data.historyRecords = app.audit.historyRecords;
            DebugLog(L"Report includes the audit history (" + std::to_wstring(data.historyRecords.size()) + L" records)");
        }
    }
    if (app.results.TotalCount() > 0) {
        data.hasScan = true;
        data.rows = app.results.AllRows();
        if (app.lastScan.has) {
            data.scan = app.lastScan.summary;
            data.scanTitle = app.lastScan.title;
        }
        else {
            data.scanTitle = L"Loaded results";
            for (const ScanRow& r : data.rows) {
                if (r.status == L"NEW") data.scan.added++;
                else if (r.status == L"CHANGED") data.scan.changed++;
                else if (r.status == L"MISSING") data.scan.missing++;
                else if (r.status == L"UPDATED") data.scan.updated++;
                else if (r.status == L"KNOWN") data.scan.known++;
                else if (r.status == L"MATCH") data.scan.match++;
                if (r.entry.malwareScore >= 7.0) data.scan.highRisk++;
            }
            data.scan.executables = static_cast<int>(data.rows.size());
            data.scan.finalState = L"Loaded from a file";
        }
    }
    if (app.settings.redactReports) {
        data = RedactReport(data);
        data.redacted = true;
    }
    return data;
}

std::wstring DefaultReportPath(AppState& app, const std::wstring& stem, const std::wstring& extension)
{
    std::wstring dir = EffectiveReportsDirectory(app.settings);
    EnsureDirectory(dir);
    return JoinPath(dir, stem + L"-" + FileTimeStamp() + extension);
}
