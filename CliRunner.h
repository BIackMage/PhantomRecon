#pragma once

#include <functional>
#include <string>
#include <vector>

#include "ScanCore.h"

// ---------------------------------------------------------------------------
// CliRunner: everything PhantomReconCli.exe can do, with no console code of
// its own. Output goes through CliEnvironment::out so tests can capture it.
//
// Exit codes:
//   0  finished, nothing needs attention
//   1  finished, something needs attention (an audit FAIL, or a scan with
//      NEW / CHANGED / MISSING files, or any file scoring 7 or more)
//   2  bad arguments or an error stopped the run
//
// Arguments: an option's value is never empty and never another option. Options
// with nothing to do (no --audit, scan, --make-samples, --findings-md or
// schedule change) are an error; only a run with no arguments shows the help.
// A failed scan step does not stop the audit reports from being written, and
// --notify fires on every finished run, failed ones included. --notify-on-change
// fires only on a failed run or when something got worse (CliNotification.h).
// Both need --audit or a scan, so there is something to report.
// ---------------------------------------------------------------------------

struct CliOptions {
    bool help = false;
    bool version = false;
    bool audit = false;
    std::wstring baselineScanRoot;    // --baseline-scan <root>
    std::wstring fullScanRoot;        // --full <root>
    bool fastScan = false;            // --fast
    std::wstring diffOlder;           // --diff <older> <newer>
    std::wstring diffNewer;
    std::wstring baselinePath;        // --baseline <file>
    std::wstring csvPath;             // --csv <file>
    std::wstring htmlPath;            // --report <file>
    std::wstring jsonPath;            // --json <file>
    std::wstring navigatorPath;       // --navigator <file>
    std::wstring textReportPath;      // --text <file>
    std::wstring fixScriptPath;       // --fix-script <file.ps1> (and <file>-undo.ps1 next to it)
    std::wstring findingsMdPath;      // --findings-md <file>
    std::wstring samplesDir;          // --make-samples <dir>
    std::wstring exclusions;          // --exclude "<list>"
    std::wstring knownGoodPath;       // --known-good <file>
    std::wstring revocation = L"cache";  // --revocation off|cache|online
    bool noFuzzy = false;             // --no-fuzzy
    bool redact = false;              // --redact
    bool notify = false;              // --notify: always notify when done
    bool notifyOnChange = false;      // --notify-on-change: notify only when worse or failed
    bool quiet = false;               // --quiet
    bool scheduleWeekly = false;      // --schedule-weekly
    bool unscheduleWeekly = false;    // --unschedule-weekly
    bool showHistory = false;         // --history: print the recent audit history
    bool noHistory = false;           // --no-history: neither read nor write the audit history
    std::wstring error;               // set when parsing failed
};

CliOptions ParseCliArguments(const std::vector<std::wstring>& args);

std::wstring CliUsageText();

struct CliEnvironment {
    std::function<void(const std::wstring& text)> out;                          // progress and results
    std::function<void(const std::wstring& title, const std::wstring& text)> notify;   // optional desktop notification
    std::wstring exePathForSchedule;    // program the weekly task should run
    std::wstring defaultBaselinePath;
    std::wstring defaultReportsDir;
    std::wstring historyPath;           // audit history file (AuditHistory.h); empty: history off
};

int RunCli(const CliOptions& options, const CliEnvironment& env);
