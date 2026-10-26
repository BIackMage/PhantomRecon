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
    std::wstring namePrefix;     // matched case-insensitively against DisplayName; with '*', a whole-name pattern
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

// ---------------------------------------------------------------------------
// Audit checks B: network, paths, persistence, processes, software, tasks.
// ---------------------------------------------------------------------------

// The file a Windows host program really runs: the DLL of rundll32 or regsvr32, the
// script of wscript, cscript, mshta, powershell -File or pwsh, the target of cmd /c
// (followed through "start" and nested hosts) and of conhost --headless. Expanded.
// "" when the command does not go through one of these hosts or names no file.
std::wstring ScriptHostPayload(const std::wstring& commandLine);

// True when an Authenticode signature is normal for this kind of file (programs,
// DLLs, drivers, installers). False for scripts, shortcuts and manifests (.url,
// .vsto, .bat, .ps1 and so on), where "unsigned" says nothing about the file.
bool SignatureExpected(const std::wstring& path);

// A file URL, as in Office add-in Manifest values and Internet shortcuts, to a path:
// "file:///C:/Program%20Files/x/a.vsto|vstolocal" -> "C:\Program Files\x\a.vsto".
// Text that is not a file URL comes back trimmed, without any "|" suffix.
std::wstring FileUrlToPath(const std::wstring& manifestValue);

// Message key of a localized browser extension name ("__MSG_appName__" -> "appName").
// "" when the name is not a complete message reference with a non-empty key.
std::wstring ExtensionMessageKey(const std::wstring& name);

// Text of an autostart snapshot key: lowercase, every run of whitespace (spaces, tabs,
// line breaks) turned into one space, trimmed. A key always reads back as written.
std::wstring NormalizeSnapshotKey(const std::wstring& text);

// A task author that names Microsoft: contains "Microsoft", or is a resource string
// from Windows' own folder ("$(@%SystemRoot%\system32\x.dll,-101)"). Empty is not.
bool IsMicrosoftTaskAuthor(const std::wstring& author);

// One entry of a PATH-style list with spaces, quotes and trailing backslashes
// removed. The backslash of a drive root stays: "C:\" is never cut to "C:", which
// would mean the current folder of drive C.
std::wstring CleanPathListEntry(const std::wstring& entry);

// DNS server text: "fe80::1%12" -> "fe80::1" (the zone id names a local interface).
std::wstring StripAddressZone(const std::wstring& address);

// A NameServer registry value ("192.0.2.1,192.0.2.2" or space separated) as a list,
// zone ids removed.
std::vector<std::wstring> ParseNameServerList(const std::wstring& value);

// Canonical text of an IP address so two spellings of one IPv6 address compare
// equal. Not an address: the input in lowercase.
std::wstring CanonicalAddress(const std::wstring& address);

// The hosts file Windows reads: <DataBasePath>\hosts, or <defaultFolder>\hosts when
// the value is empty. dataBasePath must already be expanded.
std::wstring HostsFilePath(const std::wstring& dataBasePath, const std::wstring& defaultFolder);

// True for the SHA-1 thumbprint (hex, any case) of a root certificate Windows ships
// outside Microsoft's root program list: the old Microsoft, Microsoft timestamping
// and identity roots, Thawte and VeriSign timestamping and the Symantec mobile root.
// Matched by thumbprint only, so a look-alike with the same name does not pass.
bool IsBuiltInWindowsRootThumbprint(const std::wstring& sha1Hex);

// Is the PID a process snapshot names as parent still the real parent? Windows reuses
// PIDs, so a "parent" that started after the child is another process.
// Times are FILETIME values; 0 means unknown.
// 1 = parent started first, -1 = parent started later (PID reused), 0 = cannot tell.
int ParentStartOrder(unsigned long long parentCreated, unsigned long long childCreated);

// True for kernel pseudo-processes whose image name is not a file path (Registry,
// MemCompression, Secure System, vmmem): there is no file to sign or locate.
bool IsPseudoProcessImage(const std::wstring& image);
