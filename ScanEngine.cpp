#include "pch.h"
#include "ScanEngine.h"

#include "GuiComponents.h"
#include "TextUtils.h"

#include <sstream>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[ScanEngine] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

std::wstring ScanStateLabel(ScanMode mode)
{
    return ScanModeName(mode) + L" Running...";
}

// ---------------------------------------------------------------------------
// Progress plumbing: scan thread -> UI thread, never the other way
// ---------------------------------------------------------------------------
static void SetCurrentFile(AppState& app, const std::wstring& fileName, const std::wstring& fullPath)
{
    std::lock_guard<std::mutex> lock(app.progress.textMutex);
    app.progress.currentFileName = fileName;
    app.progress.currentFilePath = fullPath;
}

static void SetScanState(AppState& app, const std::wstring& state)
{
    std::lock_guard<std::mutex> lock(app.progress.textMutex);
    app.progress.state = state;
}

// Ask the UI to repaint the operation label. Coalesced: one message in flight.
static void NotifyProgress(AppState& app)
{
    if (!app.progress.progressPosted.exchange(true)) {
        if (!PostMessageW(app.hMainWindow, WM_APP_SCAN_PROGRESS, 0, 0)) {
            app.progress.progressPosted = false;
        }
    }
}

// Queue a finished row for the results list. Coalesced: one message in flight.
static void QueueRow(AppState& app, const ScanRow& row)
{
    {
        std::lock_guard<std::mutex> lock(app.progress.rowsMutex);
        app.progress.pendingRows.push_back(row);
    }
    if (!app.progress.rowsPosted.exchange(true)) {
        if (!PostMessageW(app.hMainWindow, WM_APP_SCAN_ROWS, 0, 0)) {
            app.progress.rowsPosted = false;
        }
    }
}

// The dialog shown when a scan ends. Only Baseline scans and failures get one;
// comparison results speak for themselves in the list.
static void DescribeOutcome(const ScanRequest& request, ScanFinishedPayload& p)
{
    const ScanSummary& s = p.summary;
    std::wstringstream text;
    if (s.mode == ScanMode::Baseline) {
        if (s.cancelled) {
            p.showDialog = true;
            p.dialogTitle = L"Baseline Scan Cancelled";
            p.dialogText = L"Baseline Scan cancelled.\n\nNo baseline was written. Any existing baseline file is unchanged.";
            p.dialogIcon = MB_ICONINFORMATION;
        }
        else if (s.baselineSaved) {
            p.showDialog = true;
            p.dialogTitle = L"Baseline Scan Complete";
            text << L"Baseline saved: " << s.baselineEntries << L" programs and scripts.\n"
                 << L"File: " << request.baselinePath << L"\n\n"
                 << L"Full Scan and Fast Scan now compare against this baseline.";
            p.dialogText = text.str();
            p.dialogIcon = MB_ICONINFORMATION;
        }
        else {
            p.showDialog = true;
            p.dialogTitle = L"Baseline Not Saved";
            p.dialogText = L"The scan finished but the baseline file could not be written:\n" + request.baselinePath +
                           L"\n\nPick a folder you can write to in File > Settings.";
            p.dialogIcon = MB_ICONERROR;
        }
    }
    if (s.csvFailed) {
        p.showDialog = true;
        p.dialogTitle = L"CSV Not Written";
        p.dialogText = (p.dialogText.empty() ? L"" : p.dialogText + L"\n\n") +
                       L"The results CSV could not be written:\n" + request.csvPath;
        p.dialogIcon = MB_ICONWARNING;
    }
}

// ---------------------------------------------------------------------------
// StartScanInBackground: UI thread entry point
// ---------------------------------------------------------------------------
void StartScanInBackground(AppState& app, const ScanRequest& request)
{
    ScanProgress& progress = app.progress;
    if (progress.running.exchange(true)) {
        DebugLog(L"StartScanInBackground ignored: a scan is already running");
        return;
    }

    progress.cancelRequested = false;
    progress.filesProcessed = 0;
    progress.executablesFound = 0;
    progress.totalFiles = 0;
    progress.walkStartTick = 0;
    progress.progressPosted = false;
    progress.rowsPosted = false;
    {
        std::lock_guard<std::mutex> lock(progress.textMutex);
        progress.state = ScanStateLabel(request.mode);
        progress.currentFileName.clear();
        progress.currentFilePath.clear();
    }
    {
        std::lock_guard<std::mutex> lock(progress.rowsMutex);
        progress.pendingRows.clear();
    }

    app.results.Clear();
    RefreshResultsList(app.controls.resultsListView, app.results);
    SetProgressPosition(app.controls.progressBar, 0);
    SetProgressMarquee(app.controls.progressBar, true);
    NotifyProgress(app);
    app.outputCsvPath = request.csvPath;

    DebugLog(L"StartScanInBackground: " + request.title + L", csv=" + request.csvPath + L", baseline=" + request.baselinePath);

    // Copy everything the thread needs. It must not read request fields from app later,
    // because the UI thread may change them for the next scan.
    AppState* appPtr = &app;
    ScanRequest req = request;

    app.worker.Run([appPtr, req]() {
        AppState& a = *appPtr;

        ScanCallbacks callbacks;
        callbacks.isCancelled = [appPtr]() { return appPtr->progress.cancelRequested.load(); };
        callbacks.onTotal = [appPtr](int total) {
            appPtr->progress.totalFiles = total;
            appPtr->progress.walkStartTick = GetTickCount64();   // the time-left estimate starts after counting
            NotifyProgress(*appPtr);
        };
        callbacks.onPhase = [appPtr](const std::wstring& phase) {
            SetScanState(*appPtr, phase);
            NotifyProgress(*appPtr);
        };
        callbacks.onFile = [appPtr](const std::wstring& fileName, const std::wstring& fullPath, bool isExecutable) {
            appPtr->progress.filesProcessed++;
            if (isExecutable) appPtr->progress.executablesFound++;
            SetCurrentFile(*appPtr, fileName, fullPath);
            NotifyProgress(*appPtr);
        };
        callbacks.onRow = [appPtr](const ScanRow& row) { QueueRow(*appPtr, row); };

        // The UI thread loaded currentBaseline before starting us and will not swap
        // it while progress.running is set, so a plain pointer is safe here.
        Baseline* comparison = req.mode == ScanMode::Baseline ? nullptr : &a.currentBaseline;
        std::wstring savePath = req.mode == ScanMode::Baseline ? req.baselinePath : L"";

        ScanFinishedPayload* payload = new ScanFinishedPayload();
        payload->summary = RunScan(req.mode, req.roots, req.csvPath, comparison, savePath, req.options, callbacks);
        payload->summary.baselinePath = req.baselinePath;
        payload->finalState = payload->summary.finalState;
        payload->title = req.title;
        DescribeOutcome(req, *payload);

        SetScanState(a, payload->finalState);
        DebugLog(L"Scan thread done: " + payload->finalState);
        PostPayload(a.hMainWindow, WM_APP_SCAN_FINISHED, payload);
    });
}
