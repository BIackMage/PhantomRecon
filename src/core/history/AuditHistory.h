#pragma once

#include <windows.h>
#include <map>
#include <string>
#include <vector>

#include "HardeningScore.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// AuditHistory: past audits on this PC, so a report can say what changed.
//
// File: phantom_recon_history.jsonl through AppFilePath (next to the program, or
// the test data folder). One JSON object per line, written with JsonWriter and read
// back with the strict JsonReader. A broken or unknown line is skipped and logged;
// it never stops the program.
//
// A record is one distinct audit state:
//   firstSeen, lastSeen   UTC ISO 8601 ("2026-10-26T21:04:05Z")
//   version               program version that first saw this state
//   score, label          the hardening score
//   pass, warn, fail, info, error   counts (info includes N/A)
//   statuses              check id -> PASS / WARNING / FAIL / INFO / ERROR / N/A
// Nothing else, on purpose: no evidence, no paths, no user, computer or domain
// names, no file names. The file says how the settings scored over time and
// nothing about what is on the PC, so it is safe to keep and safe to share.
//
// After an audit: when the newest record has exactly the same statuses and score,
// only its lastSeen moves (the window program audits at every start; this keeps the
// file small). Otherwise a new record is appended. At most kAuditHistoryMaxRecords
// are kept, the oldest dropped first. The file is written to a temporary file that
// then replaces it, so a crash never leaves half a file.
//
// When history is off (setting or --no-history) none of these functions is
// called: nothing is read and nothing is written.
// ---------------------------------------------------------------------------

const size_t kAuditHistoryMaxRecords = 500;
const size_t kAuditHistoryChartRecords = 20;   // records in the report chart and --history
const bool   kAuditHistoryDefaultOn = true;    // AppSettings copies this

// "phantom_recon_history.jsonl"
std::wstring AuditHistoryFileName();

// AppFilePath(AuditHistoryFileName()).
std::wstring DefaultAuditHistoryPath();

struct AuditRecord {
    std::wstring firstSeen;
    std::wstring lastSeen;
    std::wstring version;
    int          score = 0;
    std::wstring label;
    int          pass = 0, warn = 0, fail = 0, info = 0, error = 0;
    std::map<std::wstring, std::wstring> statuses;   // check id -> status
};

// The current UTC time as "YYYY-MM-DDTHH:MM:SSZ".
std::wstring NowUtcIso();

// True for "YYYY-MM-DDTHH:MM:SSZ" with a real date and time. utcOut gets the parts.
bool ParseUtcIso(const std::wstring& text, SYSTEMTIME* utcOut);

// The date of an ISO UTC time in this PC's local time zone: "20 Oct 2026", or
// "20 Oct" when withYear is false and the year is the current one. "" when the text
// is not a valid time.
std::wstring HistoryDateText(const std::wstring& isoUtc, bool withYear);

// Local "2026-10-20 14:05" for the --history table. "" when invalid.
std::wstring HistoryDateTimeText(const std::wstring& isoUtc);

// A record from finished results. firstSeen and lastSeen are both nowUtc.
AuditRecord MakeAuditRecord(const std::vector<SecurityCheckResult>& results, const HardeningScore& score,
                            const std::wstring& nowUtc);

// One line of JSON (no line break at the end).
std::wstring AuditRecordToJsonLine(const AuditRecord& record);

// Parse one line. False with a reason when the line is not a usable record. Status
// values the program does not know are dropped from the map, the rest is kept.
bool AuditRecordFromJsonLine(const std::string& utf8Line, AuditRecord& out, std::string& why);

// Every usable record in the file text, in file order. skipped (optional) counts the
// lines that were not.
std::vector<AuditRecord> ParseAuditHistoryText(const std::string& utf8Text, int* skipped = nullptr);

// Read the file. A missing file is an empty history (true). False only when the file
// exists but cannot be read.
bool LoadAuditHistory(const std::wstring& path, std::vector<AuditRecord>& records, int* skipped = nullptr);

// Write every record, one per line, through a temporary file. False on failure (the
// old file is then left as it was).
bool SaveAuditHistory(const std::wstring& path, const std::vector<AuditRecord>& records);

// Same score and the same status for every check.
bool SameAuditState(const AuditRecord& a, const AuditRecord& b);

// Add the current audit: update the newest record's lastSeen when the state is the
// same, else append. Then drop the oldest records past maxRecords. True when appended.
bool AddAuditRecord(std::vector<AuditRecord>& records, const AuditRecord& current,
                    size_t maxRecords = kAuditHistoryMaxRecords);

// One check whose status moved.
struct AuditChange {
    std::wstring id;
    std::wstring before;   // "" for a check new in this version
    std::wstring after;
};

// What changed between the previous record and this audit. Lists are in catalog order.
//   fixed        FAIL or WARNING before, now PASS or N/A
//   newProblems  PASS, N/A, INFO or ERROR before (no problem known), now FAIL or WARNING
//   worse        WARNING before, now FAIL
//   better       FAIL before, now WARNING
//   newChecks    not in the previous record at all: new in this version, whatever
//                the status (never counted as new problems)
//   activity     checks the catalog marks as not scored (they report events), any
//                status change; they never appear in the lists above
struct AuditComparison {
    bool         hasPrevious = false;     // false: this is the first audit recorded
    bool         sameState = false;       // nothing changed at all
    std::wstring previousFirstSeen;       // when the previous state was first seen
    std::wstring previousDate;            // previous record's lastSeen: the last audit before this one
    int          previousScore = 0;
    int          currentScore = 0;
    int          scoreChange = 0;
    std::vector<AuditChange> fixed, newProblems, worse, better, newChecks, activity;
};

AuditComparison CompareWithPrevious(const AuditRecord& current, const AuditRecord& previous);

// The ids of a change list, for the JSON report.
std::vector<std::wstring> AuditChangeIds(const std::vector<AuditChange>& changes);

// What RecordAuditInHistory did.
struct AuditHistoryUpdate {
    AuditComparison          comparison;
    std::vector<AuditRecord> recent;      // the last records (up to kAuditHistoryChartRecords), oldest first, this audit last
    bool                     loaded = false;   // the file was read (or did not exist yet); false: comparison is empty
    bool                     saved = false;
    int                      skippedLines = 0;
    std::wstring             error;       // why the file could not be read or written
};

// Load the file, compare with the newest record, add this audit, save.
AuditHistoryUpdate RecordAuditInHistory(const std::wstring& path, const AuditRecord& current);

// --- Text for people (pure) ---

// Next to the score in the window: "+6 since 20 Oct", "-3 since 20 Oct",
// "same score as 20 Oct", "no change since 20 Oct" or "first audit".
std::wstring HistoryScoreLine(const AuditComparison& comparison);

// One paragraph for the text report and the console.
std::wstring BuildHistoryParagraph(const AuditComparison& comparison);

// One line for a check in the findings window ("New since the last audit (20 Oct 2026):
// it was PASS."), or "" when the check did not change.
std::wstring HistoryNoteForCheck(const AuditComparison& comparison, const std::wstring& id);

// The --history table: the last maxRows records, oldest first.
std::wstring BuildHistoryTable(const std::vector<AuditRecord>& records, size_t maxRows = kAuditHistoryChartRecords);
