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

// Run every registered check. Exceptions inside a check become an ERROR result.
std::vector<SecurityCheckResult> RunAllSecurityChecks(const AuditContext& context);
std::vector<SecurityCheckResult> RunAllSecurityChecks();

// Compact multi-line summary for the UI panel.
std::wstring GetSecuritySummary(const std::vector<SecurityCheckResult>& results);

// Full plain-text report (UTF-8) with explanation and fix for every finding.
bool WriteSecurityReport(const std::wstring& outputPath, const std::vector<SecurityCheckResult>& results);

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
