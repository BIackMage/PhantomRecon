#pragma once

#include <string>
#include <vector>

#include "CheckCatalog.h"
#include "ScanTypes.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// DetailText: the plain-text explanations shown in the row detail window, the
// findings window and the AI prompts. Pure functions (no UI), so the GUI, the
// AI panel and the tests all get the same words. Lines end with "\n".
// ---------------------------------------------------------------------------

// Every finding code on a row (signature, packing, origin, header and script
// indicators), first occurrence order, no duplicates.
std::vector<std::wstring> RowIndicatorCodes(const ScanRow& row);

// Everything known about one scanned file, grouped, with a plain explanation of
// each finding code and the name of each ATT&CK technique.
std::wstring BuildRowDetailText(const ScanRow& row);

// One check: status, severity, mappings, the evidence, what it means, the fix
// and how to undo it. result may be null (check not run yet).
std::wstring BuildFindingDetailText(const CheckInfo& info, const SecurityCheckResult* result);

// Every FAIL and WARNING with severity, evidence and meaning, worst first.
// Used for the AI audit request and the clipboard.
std::wstring BuildAuditFindingsText(const std::vector<SecurityCheckResult>& results);

// Windows edit controls need "\r\n".
std::wstring ToWindowsLineEnds(const std::wstring& text);

// "About 4 minutes left" from progress so far (ticks in milliseconds). "" until at
// least 20 files and 3 seconds have passed, or when there is nothing left.
std::wstring TimeLeftText(int processed, int total, unsigned long long startTick, unsigned long long nowTick);
