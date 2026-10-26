#pragma once

#include <string>
#include <vector>

#include "RegistryEnumerator.h"

// ---------------------------------------------------------------------------
// CheckHelpers: the pure decision logic behind several checks. No system
// calls, so the tests can feed them crafted input and check the verdict.
// ---------------------------------------------------------------------------

// --- Command lines (scheduled tasks, Run keys, WMI consumers, services) ---

// True when a command line shows a classic abuse pattern: encoded PowerShell,
// download cradles, mshta / regsvr32 / rundll32 script tricks, certutil decode,
// bitsadmin transfer. reason receives a short description.
bool IsSuspiciousCommandLine(const std::wstring& commandLine, std::wstring* reason);

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
