#include "pch.h"
#include "ScanEngine.h"

#include "GuiComponents.h"
#include "StringConv.h"
#include "TextUtils.h"

#include <exception>
#include <memory>
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

// The scan threw. Whatever rows arrived stay in the list; the summary is marked
// partial and the user is told plainly. No baseline is written in this case:
// RunScan saves only at the very end, through a temporary file.
static void DescribeFailure(const ScanRequest& request, const std::wstring& what, ScanFinishedPayload& p)
{
    p.summary = ScanSummary();
    p.summary.mode = request.mode;
    p.summary.cancelled = true;
    p.summary.baselinePath = request.baselinePath;
    p.summary.finalState = ScanModeName(request.mode) + L" stopped by an internal error";
    p.finalState = p.summary.finalState;
    p.showDialog = true;
    p.dialogTitle = L"Scan Stopped";
    p.dialogText = L"The scan stopped because of an internal error:\n" + what +
                   L"\n\nThe rows found so far are in the list but the results are incomplete." +
                   (request.mode == ScanMode::Baseline ? L" No baseline was written." : L"");
    p.dialogIcon = MB_ICONERROR;
    DebugLog(L"Scan failed: " + what);
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
        // it while progress.running is set, so a plain pointer is safe here. A
        // request with its own baseline (the sample pack) owns it through req.
        Baseline* comparison = nullptr;
        if (req.mode != ScanMode::Baseline) {
            comparison = req.comparisonBaseline ? req.comparisonBaseline.get() : &a.currentBaseline;
        }
        std::wstring savePath = req.mode == ScanMode::Baseline ? req.baselinePath : L"";

        std::unique_ptr<ScanFinishedPayload> payload(new ScanFinishedPayload());
        std::wstring failure;
        try {
            payload->summary = RunScan(req.mode, req.roots, req.csvPath, comparison, savePath, req.options, callbacks);
        }
        catch (const std::exception& e) {
            failure = Utf8ToWide(e.what());
        }
        catch (...) {
            failure = L"unknown error";
        }

        payload->summary.baselinePath = req.baselinePath;
        payload->title = req.title;
        if (failure.empty()) {
            payload->finalState = payload->summary.finalState;
            DescribeOutcome(req, *payload);
        }
        else {
            DescribeFailure(req, failure, *payload);
        }

        SetScanState(a, payload->finalState);
        DebugLog(L"Scan thread done: " + payload->finalState);
        PostPayload(a.hMainWindow, WM_APP_SCAN_FINISHED, payload.release(), a.payloads);
    });
}
