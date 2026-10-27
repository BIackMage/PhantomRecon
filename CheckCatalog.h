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

// A registry value a fix step's commands set or remove. The fix plan saves its state
// before the step runs, so the undo plan can put back exactly what was there
// (FixScriptBackup.h). Declared in CheckScripts.cpp next to the commands; a test makes
// sure every registry-writing command line has its value declared here.
struct RegistryValueRef {
    std::wstring key;                 // PowerShell path as the commands write it: HKLM:\SOFTWARE\...
    std::wstring name;                // value name
    bool         eachSubkey = false;  // the commands set the value in every direct subkey of key
    bool         neverSaved = false;  // it can hold a secret (a stored password): never backed up, never restored
};

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
    bool         scored = true;              // false: reports events, not a setting, so it never moves the hardening score

    // --- Fix plan (FixScript.cpp) ---
    // Set by name in CheckScripts.cpp after the rows above are built, never by position
    // in a row, so these must stay after every field the rows fill in order.
    // PowerShell, one complete statement per line, copied from the fix and undo text.
    // Empty: the plan shows the prose as a step the user does by hand.
    std::wstring fixScript;
    std::wstring undoScript;
    bool         scriptPerTarget = false;     // the lines use $target, once per SecurityCheckResult::targets entry
    bool         scriptNeedsAdmin = true;     // the commands need an elevated PowerShell
    bool         scriptNeedsRestart = false;  // the change takes effect after a restart
    std::wstring fixScriptNote;               // one line shown before the fix step's question, may be empty
    std::wstring undoScriptNote;              // the same for the undo step
    std::vector<RegistryValueRef> scriptRegistry;   // every registry value the fixScript sets or removes
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
