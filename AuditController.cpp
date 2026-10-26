#include "pch.h"
#include "AuditController.h"

#include "AppPaths.h"
#include "DetailText.h"
#include "FindingsWindow.h"
#include "MainLayout.h"
#include "StringConv.h"
#include "SystemInfo.h"

#include <exception>
#include <memory>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[AuditController] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

static std::wstring NowText()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}

void StartAuditInBackground(AppState& app)
{
    AuditState& audit = app.audit;
    if (audit.running.exchange(true)) {
        DebugLog(L"Audit already running, request ignored");
        return;
    }
    audit.cancelRequested = false;
    audit.done = 0;
    audit.total = 0;
    audit.progressPosted = false;
    {
        std::lock_guard<std::mutex> lock(audit.textMutex);
        audit.currentTitle = L"Starting...";
    }
    UpdateScoreDisplay(app);
    if (!audit.hasResults) {
        SetWindowTextW(app.controls.systemInfoLabel,
            ToWindowsLineEnds(BuildSystemInfoText() + L"\nSecurity audit: running. The score appears on the right when it is done.").c_str());
    }

    // Everything the thread needs is copied now.
    AppState* appPtr = &app;
    HWND hMain = app.hMainWindow;
    AuditContext context;
    std::wstring baselinePath = app.baselineFilePath;
    context.baselinePath = FileExists(baselinePath) ? baselinePath : L"";
    // WM_CLOSE sets audit.cancelRequested so the exit does not wait for every check.
    context.isCancelled = [appPtr]() { return appPtr->audit.cancelRequested.load(); };
    context.onProgress = [appPtr, hMain](int done, int total, const std::wstring& title) {
        appPtr->audit.done = done;
        appPtr->audit.total = total;
        {
            std::lock_guard<std::mutex> lock(appPtr->audit.textMutex);
            appPtr->audit.currentTitle = title;
        }
        if (!appPtr->audit.progressPosted.exchange(true)) {
            if (!PostMessageW(hMain, WM_APP_AUDIT_PROGRESS, 0, 0)) appPtr->audit.progressPosted = false;
        }
    };

    DebugLog(L"Starting audit, baseline=" + (context.baselinePath.empty() ? std::wstring(L"(none)") : context.baselinePath));
    app.worker.Run([appPtr, hMain, context]() {
        // The finished message is posted whatever happens, so the window never
        // stays in "auditing" after an exception in a check.
        std::unique_ptr<AuditFinishedPayload> payload(new AuditFinishedPayload());
        try {
            payload->results = RunAllSecurityChecks(context);
            payload->cancelled = appPtr->audit.cancelRequested.load();
            payload->score = ComputeHardeningScore(payload->results);
            payload->finishedAt = NowText();
            payload->panelText = BuildSystemInfoText() + L"\n" + GetSecuritySummary(payload->results);

            // Keep the plain-text report next to the program, as earlier versions did.
            std::wstring reportPath = AppFilePath(L"security_audit_report.txt");
            if (!WriteSecurityReport(reportPath, payload->results)) {
                DebugLog(L"Could not write " + reportPath);
            }
            DebugLog(L"Audit finished: " + std::to_wstring(payload->results.size()) + L" checks, score " +
                     std::to_wstring(payload->score.score));
        }
        catch (const std::exception& e) {
            payload.reset(new AuditFinishedPayload());
            payload->error = Utf8ToWide(e.what());
        }
        catch (...) {
            payload.reset(new AuditFinishedPayload());
            payload->error = L"unknown error";
        }
        if (!payload->error.empty()) DebugLog(L"Audit stopped by an internal error: " + payload->error);
        PostPayload(hMain, WM_APP_AUDIT_FINISHED, payload.release(), appPtr->payloads);
    });
}

void OnAuditProgressMessage(AppState& app)
{
    app.audit.progressPosted = false;
    UpdateScoreDisplay(app);
}

void OnAuditFinishedMessage(AppState& app, AuditFinishedPayload* rawPayload)
{
    std::unique_ptr<AuditFinishedPayload> payload(rawPayload);
    app.audit.running = false;
    if (!payload) return;

    if (!payload->error.empty()) {
        // Keep any earlier results; say what happened where the audit text goes.
        std::wstring text = BuildSystemInfoText() + L"\nSecurity audit stopped by an internal error: " + payload->error +
                            (app.audit.hasResults ? L"\nThe score on the right is from the previous audit (" +
                                                    app.audit.finishedAt + L"). Press F5 to try again."
                                                  : L"\nPress F5 to try again.");
        SetWindowTextW(app.controls.systemInfoLabel, ToWindowsLineEnds(text).c_str());
        UpdateScoreDisplay(app);
        return;
    }

    if (payload->cancelled && payload->results.empty()) {
        DebugLog(L"Audit cancelled before any check finished");
        UpdateScoreDisplay(app);
        return;
    }
    app.audit.results = std::move(payload->results);
    app.audit.score = payload->score;
    app.audit.finishedAt = payload->finishedAt;
    app.audit.hasResults = true;

    SetWindowTextW(app.controls.systemInfoLabel, ToWindowsLineEnds(payload->panelText).c_str());
    UpdateScoreDisplay(app);
    RefreshFindingsWindow(app);
}
