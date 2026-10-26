#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// CheckCatalog: the self-describing table of every security check.
//
// One row per check id. The audit report, the HTML report, the findings
// window, the hardening score and docs/FINDINGS.md all read from here, so
// adding a check means adding one row and one function.
//
// Mappings are honest: a check lists an ATT&CK technique only when the finding
// enables or hides that technique, and lists CIS Controls v8 safeguards only
// where the safeguard is about the same thing. cisBenchmark names the CIS
// Microsoft Windows Benchmark recommendation by title, not number, because the
// numbers change between benchmark versions.
// ---------------------------------------------------------------------------

enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

struct CheckInfo {
    std::wstring id;
    std::wstring title;
    std::wstring category;
    Severity     severity = Severity::Medium;
    std::vector<std::wstring> attack;        // ATT&CK technique ids
    std::vector<std::wstring> cisControls;   // CIS Controls v8 safeguard ids
    std::wstring cisBenchmark;               // benchmark recommendation title, may be empty
    std::wstring explanation;                // what it is and why it matters, plain words
    std::wstring fix;                        // exact steps or commands
    std::wstring undo;                       // how to reverse the fix
};

// Every check in report order.
const std::vector<CheckInfo>& GetCheckCatalog();

// Lookup by id. nullptr when unknown.
const CheckInfo* FindCheckInfo(const std::wstring& id);

std::wstring SeverityName(Severity severity);

// Score weight per severity (used by the hardening score).
int SeverityWeight(Severity severity);

// Category names in display order.
const std::vector<std::wstring>& GetCheckCategories();

// Markdown document describing every check (docs/FINDINGS.md).
std::wstring BuildFindingsMarkdown();
