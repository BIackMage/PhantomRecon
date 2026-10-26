#pragma once

#include <string>
#include <vector>

#include "AttackMapping.h"
#include "HardeningScore.h"
#include "ScanCore.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// Reports: the same facts in three formats.
//   HTML  one self-contained page for people (no external files, prints well)
//   JSON  a versioned schema ("phantomrecon.report/1") for other tools
//   ATT&CK Navigator layer  for mapping coverage in MITRE's Navigator
// ---------------------------------------------------------------------------

struct ReportData {
    std::wstring generatedAt;      // local time, ISO 8601
    std::wstring hostName;
    std::wstring osText;
    std::wstring userName;
    bool         redacted = false; // user, host and domain names replaced

    bool                             hasAudit = false;
    std::vector<SecurityCheckResult> audit;
    HardeningScore                   score;

    bool                 hasScan = false;
    ScanSummary          scan;
    std::vector<ScanRow> rows;
    std::wstring         scanTitle;    // e.g. "Full Scan of C:\Program Files" or "Baseline comparison"
    std::wstring         scanModeName; // shown instead of ScanModeName(scan.mode) when set ("Baseline comparison")
};

// Fill time, host, OS and user. When redact is true the copy is redacted.
void FillReportHost(ReportData& data, bool redact);

// Apply redaction to every string in the report (names, titles, check details, every
// text field of every row). Safe to apply more than once.
ReportData RedactReport(const ReportData& data);

// The same redaction for output that is not a ReportData: the CSV and the text report.
std::vector<ScanRow> RedactRows(const std::vector<ScanRow>& rows);
std::vector<SecurityCheckResult> RedactAuditResults(const std::vector<SecurityCheckResult>& results);

std::wstring BuildJsonReport(const ReportData& data);
std::wstring BuildHtmlReport(const ReportData& data);

// Techniques seen: audit findings that FAILED or WARNED, plus every scanned file.
std::vector<TechniqueCount> CollectTechniques(const ReportData& data);
std::wstring BuildNavigatorReport(const ReportData& data);

// Write UTF-8 (HTML and JSON get no BOM). False on failure.
bool SaveReportFile(const std::wstring& path, const std::wstring& text);
