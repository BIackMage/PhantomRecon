#pragma once

#include <string>
#include <vector>

#include "AuditHistory.h"

class JsonWriter;

// ---------------------------------------------------------------------------
// ReportHistory: the "Since your last audit" parts of the HTML and JSON reports.
// Pure functions of the comparison and the recent records (AuditHistory.h).
// ---------------------------------------------------------------------------

// The HTML section: score change, fixed and new problem lists, and the chart of
// the recent scores (two or more records). For the first audit it says so.
std::wstring BuildHistoryHtmlSection(const AuditComparison& comparison, const std::vector<AuditRecord>& records);

// An inline SVG line chart of the records' scores, oldest first. Drawn with the
// report's CSS colours (light and dark), no script, with a title and a description
// that read out every point. "" when there are fewer than two records.
std::wstring BuildHistoryChartSvg(const std::vector<AuditRecord>& records);

// The JSON report's "history" member value (the caller writes the key).
void WriteHistoryJson(JsonWriter& w, const AuditComparison& comparison);
