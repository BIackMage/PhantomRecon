#pragma once

#include <functional>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Security check results and the audit runner.
//
// Every check has a stable id (for example "net.llmnr"). Title, severity,
// ATT&CK and CIS mappings, plain explanation and fix text live in the check
// catalog (CheckCatalog.cpp), keyed by that id. A check function only decides
// status and writes the evidence into detail.
// ---------------------------------------------------------------------------

// Status strings. Kept as text because every report prints them verbatim.
#define CHECK_PASS    L"PASS"
#define CHECK_FAIL    L"FAIL"
#define CHECK_WARNING L"WARNING"
#define CHECK_INFO    L"INFO"
#define CHECK_ERROR   L"ERROR"
#define CHECK_NA      L"N/A"

struct SecurityCheckResult {
    std::wstring id;         // catalog id, e.g. "net.llmnr"
    std::wstring name;       // display title (from the catalog)
    std::wstring status;     // one of the CHECK_* strings
    std::wstring detail;     // human-readable evidence

    // The exact things the finding is about, as read from Windows (for net.wifiopen the
    // profile names), when a fix command can name them one by one. Only checks whose
    // catalog row has scriptPerTarget fill it. Untrusted text: the fix plan puts each
    // value into PowerShell only as a single-quoted literal (FixScript.cpp).
    std::vector<std::wstring> targets;
};

class Baseline;

// What the audit is allowed to use. Every field is optional.
struct AuditContext {
    std::wstring baselinePath;     // active baseline, for cross-checking processes and persistence
    std::wstring snapshotPath;     // where the persistence snapshot is kept between runs
    std::function<void(int done, int total, const std::wstring& title)> onProgress;
    std::function<bool()> isCancelled;

    // Filled by RunAllSecurityChecks from baselinePath (loaded once, shared by checks).
    const Baseline* baseline = nullptr;
};

// A result with id and title filled from the catalog and status INFO.
SecurityCheckResult MakeCheckResult(const std::wstring& id);

// The registry of checks: every check the audit runs, in report order.
struct RegisteredCheck {
    std::wstring id;
    std::function<SecurityCheckResult(const AuditContext&)> run;
};
const std::vector<RegisteredCheck>& GetRegisteredChecks();

// Every id that has a check function, whether or not the catalog lists it.
// GetRegisteredChecks only keeps ids the catalog knows, so tests use this to
// find a function that has no catalog row.
std::vector<std::wstring> GetCheckFunctionIds();

// Run every registered check. Exceptions inside a check become an ERROR result.
std::vector<SecurityCheckResult> RunAllSecurityChecks(const AuditContext& context);
std::vector<SecurityCheckResult> RunAllSecurityChecks();

// Cut evidence longer than 20,000 characters at a line end, saying how much was cut.
std::wstring LimitDetail(const std::wstring& detail);

// Compact multi-line summary for the UI panel.
std::wstring GetSecuritySummary(const std::vector<SecurityCheckResult>& results);

// Full plain-text report (UTF-8) with explanation and fix for every finding.
bool WriteSecurityReport(const std::wstring& outputPath, const std::vector<SecurityCheckResult>& results);

// The same with one paragraph after the score line (the audit history paragraph,
// BuildHistoryParagraph in AuditHistory.h). An empty paragraph adds nothing.
bool WriteSecurityReport(const std::wstring& outputPath, const std::vector<SecurityCheckResult>& results,
                         const std::wstring& historyParagraph);

// --- Core checks (SecurityChecks.cpp) ---
SecurityCheckResult CheckUnquotedServicePaths();
SecurityCheckResult CheckWritableServiceExes();
SecurityCheckResult CheckAlwaysInstallElevated();
SecurityCheckResult CheckUnattendedInstallFiles();
SecurityCheckResult CheckCredentialGuard();
SecurityCheckResult CheckLLMNR();
SecurityCheckResult CheckNBTNS();
SecurityCheckResult CheckMDNS();
SecurityCheckResult CheckSMBSigning();
SecurityCheckResult CheckProxyAutoDetect();
