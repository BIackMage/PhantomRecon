#pragma once

#include <string>

#include "AuditHistory.h"

// ---------------------------------------------------------------------------
// CliNotification: the desktop notification at the end of a console run
// (--notify, --notify-on-change, the weekly task). Pure: facts about the run in,
// the words and the show-or-stay-quiet decision out. No files, no windows.
//
// The text leads with what changed since the last audit (CompareWithPrevious):
//   "2 new problems since 20 Oct (score 61, down 4). Open Phantom Recon to see them."
//   "No change since 20 Oct (score 65)."
// then the scan result. Checks that report activity and are not scored get one
// short sentence. With history off, or no earlier record, only the score is given.
// A failed run starts with "Error: <reason>.".
//
// "Got worse" (what --notify-on-change waits for) means any of:
//   - a check that had no known problem now FAILs or WARNs (newProblems)
//   - a WARNING became a FAIL (worse)
//   - a lower hardening score than the last audit
//   - a scan that is not a baseline found NEW or CHANGED files against the baseline
// A failed run is always shown. Fixed checks, a higher score, checks new in this
// version and activity-only changes are never "worse".
// ---------------------------------------------------------------------------

// The balloon's limits (NOTIFYICONDATAW szInfoTitle and szInfo, without the null).
const size_t kNotificationTitleMaxChars = 63;
const size_t kNotificationTextMaxChars = 255;

struct NotificationFacts {
    int          exitCode = 0;          // RunCli's exit code: 0, 1 or 2
    std::wstring error;                 // the run's first error ("" when none), already redacted when asked

    bool            hasAudit = false;
    int             score = 0;          // hardening score of this audit
    bool            hasHistory = false; // history on and read; false: comparison is ignored
    AuditComparison comparison;         // hasPrevious false: the first audit recorded

    bool hasScan = false;
    bool baselineScan = false;          // the scan took a baseline: nothing was compared
    int  scanPrograms = 0;              // files analysed (used for a baseline scan)
    int  scanAdded = 0, scanChanged = 0, scanMissing = 0;
    int  scanHighRisk = 0;              // files scoring 7 or more
};

struct CliNotification {
    std::wstring title;
    std::wstring text;
};

// Exit code 2 or an error message.
bool RunFailed(const NotificationFacts& facts);

// See "Got worse" above.
bool RunGotWorse(const NotificationFacts& facts);

// --notify (onlyWhenWorse false): always. --notify-on-change (true): only when the
// run failed or something got worse.
bool ShouldShowNotification(const NotificationFacts& facts, bool onlyWhenWorse);

// Title and text, each within the balloon's limits, ASCII apart from the error text.
CliNotification BuildCliNotification(const NotificationFacts& facts);

// The audit part on its own ("" without an audit), for tests and the console line.
std::wstring NotificationAuditSentence(const NotificationFacts& facts);

// The scan part on its own ("" without a scan).
std::wstring NotificationScanSentence(const NotificationFacts& facts);
