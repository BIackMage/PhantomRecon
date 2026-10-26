#pragma once

#include <string>
#include <vector>

#include "RegistryEnumerator.h"

// ---------------------------------------------------------------------------
// CheckHelpers: the pure decision logic behind several checks. No system
// calls, so the tests can feed them crafted input and check the verdict.
// ---------------------------------------------------------------------------

// --- Long evidence lists ---

// Collects report lines but keeps only the first maxItems, so one check cannot
// bury the report (a PC can have thousands of autostart entries). Text() ends
// with "... and N more" when lines were left out.
class CappedList {
public:
    explicit CappedList(size_t maxItems) : m_max(maxItems) {}
    void Add(const std::wstring& item)
    {
        if (m_items.size() < m_max) m_items.push_back(item);
        ++m_total;
    }
    size_t Total() const { return m_total; }
    bool Empty() const { return m_total == 0; }
    std::wstring Text() const
    {
        std::wstring out;
        for (const std::wstring& s : m_items) out += s;
        if (m_total > m_items.size()) {
            out += L"  ... and " + std::to_wstring(m_total - m_items.size()) + L" more not listed here.\n";
        }
        return out;
    }

private:
    size_t                    m_max;
    size_t                    m_total = 0;
    std::vector<std::wstring> m_items;
};

// --- Command lines (scheduled tasks, Run keys, WMI consumers, services) ---

// True when a command line shows a classic abuse pattern: encoded PowerShell,
// download cradles, mshta / regsvr32 / rundll32 script tricks, certutil decode,
// bitsadmin transfer. reason receives a short description.
bool IsSuspiciousCommandLine(const std::wstring& commandLine, std::wstring* reason);

// Same rules with a strength: 0 nothing, 1 weak (hidden window, temp folder),
// 2 strong (encoded command, download and run, script-runner tricks).
int CommandLineSuspicion(const std::wstring& commandLine, std::wstring* reason);

// Split an AppInit_DLLs value into DLL paths. Entries are separated by commas or
// spaces, but a path may itself contain spaces, so tokens are joined until one
// ends in ".dll".
std::vector<std::wstring> SplitAppInitList(const std::wstring& value);

// Extract the program path from a command line ("\"C:\a b\x.exe\" -y" -> "C:\a b\x.exe").
// Expands environment variables. Bare names (no folder) are returned as given.
std::wstring ProgramFromCommandLine(const std::wstring& commandLine);

// --- Hosts file ---
struct HostsEntry {
    std::wstring address;
    std::wstring host;
    int          line = 0;
};
std::vector<HostsEntry> ParseHostsFile(const std::wstring& text);

// True for domains malware likes to redirect: Microsoft and Windows Update,
// security vendors, browsers' update sites, and common banking / payment sites.
bool IsWatchedDomain(const std::wstring& host);

// --- DNS ---
bool IsPrivateOrLocalAddress(const std::wstring& address);
bool IsWellKnownPublicResolver(const std::wstring& address);

// --- Outdated software ---
struct SoftwareRule {
    std::wstring namePrefix;     // matched case-insensitively against DisplayName
    std::wstring minimumVersion; // versions below this are flagged; empty = any version (end of life)
    std::wstring reason;
};
const std::vector<SoftwareRule>& GetBuiltInSoftwareRules();

struct SoftwareFinding {
    std::wstring name;
    std::wstring version;
    std::wstring minimumVersion;
    std::wstring reason;
};
std::vector<SoftwareFinding> FindOutdatedSoftware(const std::vector<InstalledProgram>& programs,
                                                  const std::vector<SoftwareRule>& rules);

// Extra rules from a user file: "name prefix|minimum version|reason" per line.
std::vector<SoftwareRule> ParseSoftwareRules(const std::wstring& text);

// --- LSA packages ---
// kind: L"Authentication Packages", L"Notification Packages", L"Security Packages"
bool IsExpectedLsaPackage(const std::wstring& kind, const std::wstring& name);

// --- Processes ---
// Expected folder (lowercase, under %SystemRoot%) for a protected Windows process
// name such as "lsass.exe"; empty when the name is not one we track.
std::wstring ExpectedSystemProcessFolder(const std::wstring& exeNameLower);

// Expected parent for core Windows processes ("lsass.exe" -> "wininit.exe"); empty when not tracked.
std::wstring ExpectedParentProcess(const std::wstring& exeNameLower);

// True when the process is a JIT host (browsers, .NET, Java, Node, Electron) where
// private executable memory is expected.
bool IsJitHost(const std::wstring& exeNameLower, const std::vector<std::wstring>& loadedModulesLower);

// True for Office programs, script hosts and shells, used for the "Office started a shell" rule.
bool IsOfficeProcess(const std::wstring& exeNameLower);
bool IsShellOrScriptHost(const std::wstring& exeNameLower);

// --- Audit policy ---
struct AuditSubcategory {
    const wchar_t* guid;         // "{0CCE922B-69AE-11D9-BED3-505054503030}"
    const wchar_t* name;         // English name for reports
    bool           wantSuccess;
    bool           wantFailure;
};
const std::vector<AuditSubcategory>& GetRecommendedAuditSubcategories();
