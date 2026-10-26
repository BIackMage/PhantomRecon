#include "pch.h"
#include "CheckHelpers.h"

#include "AppPaths.h"
#include "TextUtils.h"

#include <windows.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------------------
// Command lines
// ---------------------------------------------------------------------------
bool IsSuspiciousCommandLine(const std::wstring& commandLine, std::wstring* reason)
{
    return CommandLineSuspicion(commandLine, reason) > 0;
}

std::vector<std::wstring> SplitAppInitList(const std::wstring& value)
{
    std::vector<std::wstring> out;
    std::wstring current;
    for (const std::wstring& token : SplitAnyW(value, L", \t")) {
        current += current.empty() ? token : L" " + token;
        if (EndsWithI(current, L".dll")) {
            out.push_back(current);
            current.clear();
        }
    }
    if (!TrimW(current).empty()) out.push_back(current);
    return out;
}

int CommandLineSuspicion(const std::wstring& commandLine, std::wstring* reason)
{
    std::wstring c = ToLowerW(commandLine);
    // Undo the simplest escaping tricks before matching.
    std::wstring flat;
    for (wchar_t ch : c) {
        if (ch != L'^' && ch != L'`' && ch != L'"') flat += ch;
    }

    struct Rule { const wchar_t* needle; const wchar_t* why; int strength; };
    static const Rule rules[] = {
        { L" -encodedcommand ", L"encoded PowerShell command", 2 },
        { L" -enc ",            L"encoded PowerShell command", 2 },
        { L" -ec ",             L"encoded PowerShell command", 2 },
        { L"frombase64string",  L"decodes base64 at run time", 2 },
        { L"downloadstring(",   L"downloads and runs code", 2 },
        { L"downloadfile(",     L"downloads a file", 2 },
        { L"net.webclient",     L"downloads with Net.WebClient", 2 },
        { L"invoke-webrequest", L"downloads with Invoke-WebRequest", 1 },
        { L"iwr http",          L"downloads with Invoke-WebRequest", 1 },
        { L"invoke-expression", L"runs text as code", 2 },
        { L"iex(",              L"runs text as code", 2 },
        { L"iex (",             L"runs text as code", 2 },
        { L"mshta http",        L"mshta runs a remote HTML application", 2 },
        { L"mshta.exe http",    L"mshta runs a remote HTML application", 2 },
        { L"mshta vbscript:",   L"mshta runs inline script", 2 },
        { L"mshta javascript:", L"mshta runs inline script", 2 },
        { L"javascript:",       L"inline JavaScript in a command line", 2 },
        { L"/i:http",           L"regsvr32 loads a remote scriptlet", 2 },
        { L"scrobj.dll",        L"regsvr32 scriptlet loader", 2 },
        { L"certutil -urlcache", L"certutil used as a downloader", 2 },
        { L"certutil.exe -urlcache", L"certutil used as a downloader", 2 },
        { L"certutil -decode",  L"certutil decodes a file", 2 },
        { L"bitsadmin /transfer", L"bitsadmin used as a downloader", 2 },
        { L"process call create", L"WMIC starts a process", 1 },
        { L"-windowstyle hidden", L"hidden PowerShell window", 1 },
        { L"-w hidden",         L"hidden PowerShell window", 1 },
        { L"\\appdata\\local\\temp\\", L"runs from the Temp folder", 1 },
        { L"\\users\\public\\", L"runs from the Public folder", 1 },
    };
    int best = 0;
    for (const Rule& r : rules) {
        if (r.strength > best && flat.find(r.needle) != std::wstring::npos) {
            best = r.strength;
            if (reason) *reason = r.why;
        }
    }
    return best;
}

std::wstring ProgramFromCommandLine(const std::wstring& commandLineIn)
{
    std::wstring cmd = TrimW(commandLineIn);
    if (cmd.empty()) return L"";
    std::wstring program;
    if (cmd[0] == L'"') {
        size_t end = cmd.find(L'"', 1);
        program = end == std::wstring::npos ? cmd.substr(1) : cmd.substr(1, end - 1);
    }
    else {
        std::wstring lower = ToLowerW(cmd);
        size_t best = std::wstring::npos;
        size_t bestLen = 0;
        const wchar_t* exts[] = { L".exe", L".com", L".bat", L".cmd", L".dll", L".vbs", L".js", L".ps1", L".scr" };
        for (const wchar_t* ext : exts) {
            size_t pos = lower.find(ext);
            while (pos != std::wstring::npos) {
                size_t after = pos + wcslen(ext);
                if (after == lower.size() || lower[after] == L' ' || lower[after] == L',' || lower[after] == L'"') {
                    if (best == std::wstring::npos || pos < best) {
                        best = pos;
                        bestLen = wcslen(ext);
                    }
                    break;
                }
                pos = lower.find(ext, pos + 1);
            }
        }
        if (best != std::wstring::npos) {
            program = cmd.substr(0, best + bestLen);
        }
        else {
            size_t space = cmd.find(L' ');
            program = space == std::wstring::npos ? cmd : cmd.substr(0, space);
        }
    }
    return ExpandEnvironment(TrimW(program));
}

// ---------------------------------------------------------------------------
// Hosts file
// ---------------------------------------------------------------------------
std::vector<HostsEntry> ParseHostsFile(const std::wstring& text)
{
    std::vector<HostsEntry> entries;
    int lineNo = 0;
    std::wstring line;
    auto flush = [&](const std::wstring& raw) {
        lineNo++;
        std::wstring l = raw;
        size_t hash = l.find(L'#');
        if (hash != std::wstring::npos) l = l.substr(0, hash);
        std::vector<std::wstring> parts = SplitAnyW(l, L" \t");
        if (parts.size() < 2) return;
        for (size_t i = 1; i < parts.size(); ++i) {
            HostsEntry e;
            e.address = parts[0];
            e.host = ToLowerW(parts[i]);
            e.line = lineNo;
            if (e.host == L"localhost" || e.host == L"localhost.localdomain") continue;
            entries.push_back(e);
        }
    };
    for (wchar_t c : text) {
        if (c == L'\n') {
            if (!line.empty() && line.back() == L'\r') line.pop_back();
            flush(line);
            line.clear();
        }
        else {
            line += c;
        }
    }
    if (!line.empty()) flush(line);
    return entries;
}

bool IsWatchedDomain(const std::wstring& hostIn)
{
    std::wstring host = ToLowerW(hostIn);
    static const wchar_t* const watched[] = {
        L"microsoft.com", L"windowsupdate.com", L"windows.com", L"windows.net", L"live.com", L"office.com",
        L"msftncsi.com", L"msftconnecttest.com", L"bing.com", L"microsoftonline.com", L"azure.com",
        L"google.com", L"googleapis.com", L"gstatic.com", L"apple.com", L"mozilla.org", L"mozilla.net",
        L"virustotal.com", L"malwarebytes.com", L"kaspersky.com", L"eset.com", L"avast.com", L"avg.com",
        L"norton.com", L"mcafee.com", L"bitdefender.com", L"sophos.com", L"trendmicro.com", L"crowdstrike.com",
        L"sentinelone.com", L"symantec.com", L"f-secure.com", L"webroot.com", L"paypal.com", L"chase.com",
        L"bankofamerica.com", L"wellsfargo.com", L"citi.com", L"hsbc.com", L"barclays.co.uk",
    };
    for (const wchar_t* w : watched) {
        std::wstring domain = w;
        if (host == domain) return true;
        if (host.size() > domain.size() && host.compare(host.size() - domain.size(), domain.size(), domain) == 0 &&
            host[host.size() - domain.size() - 1] == L'.') {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------
bool IsPrivateOrLocalAddress(const std::wstring& address)
{
    IN_ADDR v4 = {};
    if (InetPtonW(AF_INET, address.c_str(), &v4) == 1) {
        unsigned char a = v4.S_un.S_un_b.s_b1;
        unsigned char b = v4.S_un.S_un_b.s_b2;
        if (a == 10 || a == 127) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 169 && b == 254) return true;
        if (a == 100 && b >= 64 && b <= 127) return true;   // carrier-grade NAT
        return false;
    }
    IN6_ADDR v6 = {};
    if (InetPtonW(AF_INET6, address.c_str(), &v6) == 1) {
        if (IN6_IS_ADDR_LOOPBACK(&v6) || IN6_IS_ADDR_LINKLOCAL(&v6) || IN6_IS_ADDR_SITELOCAL(&v6)) return true;
        if ((v6.u.Byte[0] & 0xFE) == 0xFC) return true;   // unique local fc00::/7
        // fec0::/10 site-local DNS defaults Windows uses
        if (v6.u.Byte[0] == 0xFE && (v6.u.Byte[1] & 0xC0) == 0xC0) return true;
        return false;
    }
    return false;
}

bool IsWellKnownPublicResolver(const std::wstring& address)
{
    static const wchar_t* const resolvers[] = {
        L"1.1.1.1", L"1.0.0.1", L"1.1.1.2", L"1.0.0.2", L"1.1.1.3", L"1.0.0.3",
        L"8.8.8.8", L"8.8.4.4",
        L"9.9.9.9", L"149.112.112.112", L"9.9.9.10", L"9.9.9.11",
        L"208.67.222.222", L"208.67.220.220", L"208.67.222.123", L"208.67.220.123",
        L"94.140.14.14", L"94.140.15.15",
        L"76.76.2.0", L"76.76.10.0",
        L"2606:4700:4700::1111", L"2606:4700:4700::1001",
        L"2001:4860:4860::8888", L"2001:4860:4860::8844",
        L"2620:fe::fe", L"2620:fe::9",
    };
    std::wstring a = ToLowerW(address);
    for (const wchar_t* r : resolvers) {
        if (a == r) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Outdated software
// ---------------------------------------------------------------------------
const std::vector<SoftwareRule>& GetBuiltInSoftwareRules()
{
    // Reviewed October 2026. Each minimum version fixes a widely publicised,
    // actively exploited or easily exploitable flaw. Empty minimum = end of life.
    static const std::vector<SoftwareRule> rules = {
        { L"7-Zip",                     L"24.09",  L"CVE-2025-0411: Mark of the Web is not passed to extracted files" },
        { L"WinRAR",                    L"7.13",   L"CVE-2025-8088: path traversal exploited in the wild" },
        { L"PuTTY",                     L"0.81",   L"CVE-2024-31497: NIST P-521 private keys can be recovered" },
        { L"WinSCP",                    L"6.3.3",  L"Bundles PuTTY code affected by CVE-2024-31497" },
        { L"FileZilla",                 L"3.67.0", L"Bundles PuTTY code affected by CVE-2024-31497" },
        { L"Notepad++",                 L"8.8.2",  L"CVE-2025-49144: installer privilege escalation" },
        { L"VLC media player",          L"3.0.21", L"Memory-safety fixes for crafted media files" },
        { L"Adobe Flash Player",        L"",       L"End of life since December 2020; no fixes at all" },
        { L"Microsoft Silverlight",     L"",       L"End of life since October 2021; no fixes at all" },
        { L"QuickTime",                 L"",       L"QuickTime for Windows is end of life with unpatched flaws" },
        { L"Python 2.",                 L"",       L"Python 2 is end of life since January 2020" },
        { L"Python 3.8",                L"",       L"Python 3.8 is end of life since October 2024" },
        { L"Python 3.9",                L"",       L"Python 3.9 is end of life since October 2025" },
        { L"Python 3.10",               L"",       L"Python 3.10 reaches end of life in October 2026" },
        { L"Node.js",                   L"22.0.0", L"Node.js releases before 22 are end of life (20 ended April 2026)" },
        { L"Java 6",                    L"",       L"Java 6 is end of life" },
        { L"Java 7",                    L"",       L"Java 7 is end of life" },
        { L"Java(TM) 6",                L"",       L"Java 6 is end of life" },
        { L"Java(TM) 7",                L"",       L"Java 7 is end of life" },
        { L"Microsoft Office 2010",     L"",       L"Office 2010 is end of life since October 2020" },
        { L"Microsoft Office 2013",     L"",       L"Office 2013 is end of life since April 2023" },
        { L"Microsoft Office 2016",     L"",       L"Office 2016 support ended October 2025" },
        { L"Microsoft Office 2019",     L"",       L"Office 2019 support ended October 2025" },
    };
    return rules;
}

std::vector<SoftwareRule> ParseSoftwareRules(const std::wstring& text)
{
    std::vector<SoftwareRule> rules;
    for (const std::wstring& raw : SplitAnyW(text, L"\r\n")) {
        std::wstring line = TrimW(raw);
        if (line.empty() || line[0] == L'#') continue;
        std::vector<std::wstring> parts = SplitW(line, L'|', false);
        if (parts.empty() || parts[0].empty()) continue;
        SoftwareRule r;
        r.namePrefix = parts[0];
        if (parts.size() > 1) r.minimumVersion = parts[1];
        if (parts.size() > 2) r.reason = parts[2];
        rules.push_back(r);
    }
    return rules;
}

std::vector<SoftwareFinding> FindOutdatedSoftware(const std::vector<InstalledProgram>& programs,
                                                  const std::vector<SoftwareRule>& rules)
{
    std::vector<SoftwareFinding> findings;
    for (const InstalledProgram& p : programs) {
        for (const SoftwareRule& r : rules) {
            if (!StartsWithI(p.displayName, r.namePrefix)) continue;
            bool flagged = false;
            if (r.minimumVersion.empty()) {
                flagged = true;
            }
            else if (!p.displayVersion.empty()) {
                flagged = CompareVersions(p.displayVersion, r.minimumVersion) < 0;
            }
            else {
                // Some installers put the version in the name ("7-Zip 23.01 (x64)")
                std::wstring tail = p.displayName.substr(r.namePrefix.size());
                std::wstring digits;
                for (wchar_t c : tail) {
                    if (iswdigit(c) || c == L'.') digits += c;
                    else if (!digits.empty()) break;
                }
                if (!digits.empty()) flagged = CompareVersions(digits, r.minimumVersion) < 0;
            }
            if (flagged) {
                findings.push_back({ p.displayName, p.displayVersion, r.minimumVersion, r.reason });
                break;
            }
        }
    }
    return findings;
}

// ---------------------------------------------------------------------------
// LSA packages
// ---------------------------------------------------------------------------
bool IsExpectedLsaPackage(const std::wstring& kind, const std::wstring& nameIn)
{
    std::wstring name = ToLowerW(TrimW(nameIn));
    if (name.empty() || name == L"\"\"") return true;
    if (ExtensionOf(name) == L".dll") name = name.substr(0, name.size() - 4);

    if (kind == L"Authentication Packages") {
        return name == L"msv1_0";
    }
    if (kind == L"Notification Packages") {
        return name == L"scecli" || name == L"rassfm";
    }
    if (kind == L"Security Packages") {
        const wchar_t* known[] = { L"kerberos", L"msv1_0", L"schannel", L"wdigest", L"tspkg", L"pku2u",
                                   L"cloudap", L"livessp", L"negoexts", L"negotiate" };
        for (const wchar_t* k : known) {
            if (name == k) return true;
        }
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------
std::wstring ExpectedSystemProcessFolder(const std::wstring& exeNameLower)
{
    std::wstring windir = ToLowerW(ExpandEnvironment(L"%SystemRoot%"));
    const wchar_t* system32Names[] = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"services.exe", L"winlogon.exe", L"smss.exe",
        L"wininit.exe", L"spoolsv.exe", L"taskhostw.exe", L"lsaiso.exe", L"fontdrvhost.exe",
        L"dwm.exe", L"sihost.exe", L"ctfmon.exe", L"searchindexer.exe", L"runtimebroker.exe",
    };
    for (const wchar_t* n : system32Names) {
        if (exeNameLower == n) return windir + L"\\system32";
    }
    if (exeNameLower == L"explorer.exe") return windir;
    return L"";
}

std::wstring ExpectedParentProcess(const std::wstring& exeNameLower)
{
    if (exeNameLower == L"lsass.exe") return L"wininit.exe";
    if (exeNameLower == L"services.exe") return L"wininit.exe";
    if (exeNameLower == L"lsaiso.exe") return L"wininit.exe";
    if (exeNameLower == L"svchost.exe") return L"services.exe";
    if (exeNameLower == L"spoolsv.exe") return L"services.exe";
    return L"";
}

bool IsJitHost(const std::wstring& exeNameLower, const std::vector<std::wstring>& modules)
{
    const wchar_t* jitProcesses[] = {
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"opera.exe", L"brave.exe", L"vivaldi.exe",
        L"msedgewebview2.exe", L"node.exe", L"java.exe", L"javaw.exe", L"code.exe", L"teams.exe",
        L"ms-teams.exe", L"slack.exe", L"discord.exe", L"spotify.exe", L"electron.exe", L"powershell.exe",
        L"pwsh.exe", L"dotnet.exe", L"devenv.exe", L"searchapp.exe", L"searchhost.exe", L"widgets.exe",
        L"steamwebhelper.exe", L"acrobat.exe", L"acrord32.exe", L"outlook.exe", L"olk.exe",
    };
    for (const wchar_t* p : jitProcesses) {
        if (exeNameLower == p) return true;
    }
    const wchar_t* jitModules[] = {
        L"clr.dll", L"coreclr.dll", L"clrjit.dll", L"mscorwks.dll", L"jscript9.dll", L"chakra.dll",
        L"v8.dll", L"libcef.dll", L"jvm.dll", L"mono-2.0-bdwgc.dll", L"edgehtml.dll", L"msedge.dll",
        L"chrome.dll", L"xul.dll", L"libmonosgen-2.0.dll", L"luajit.dll", L"embeddedbrowserwebview.dll",
    };
    for (const std::wstring& m : modules) {
        for (const wchar_t* j : jitModules) {
            if (m == j) return true;
        }
    }
    return false;
}

bool IsOfficeProcess(const std::wstring& n)
{
    return n == L"winword.exe" || n == L"excel.exe" || n == L"powerpnt.exe" || n == L"outlook.exe" ||
           n == L"msaccess.exe" || n == L"mspub.exe" || n == L"onenote.exe" || n == L"visio.exe";
}

bool IsShellOrScriptHost(const std::wstring& n)
{
    return n == L"cmd.exe" || n == L"powershell.exe" || n == L"pwsh.exe" || n == L"wscript.exe" ||
           n == L"cscript.exe" || n == L"mshta.exe" || n == L"rundll32.exe" || n == L"regsvr32.exe" ||
           n == L"certutil.exe" || n == L"bitsadmin.exe";
}

// ---------------------------------------------------------------------------
// Audit policy
// ---------------------------------------------------------------------------
const std::vector<AuditSubcategory>& GetRecommendedAuditSubcategories()
{
    // The subset of Microsoft's and CIS's recommended audit settings that matters
    // most for finding out what happened after an incident.
    static const std::vector<AuditSubcategory> subcategories = {
        { L"{0CCE923F-69AE-11D9-BED3-505054503030}", L"Credential Validation",       true,  true  },
        { L"{0CCE9237-69AE-11D9-BED3-505054503030}", L"Security Group Management",   true,  false },
        { L"{0CCE9235-69AE-11D9-BED3-505054503030}", L"User Account Management",     true,  true  },
        { L"{0CCE922B-69AE-11D9-BED3-505054503030}", L"Process Creation",            true,  false },
        { L"{0CCE9217-69AE-11D9-BED3-505054503030}", L"Account Lockout",             false, true  },
        { L"{0CCE9215-69AE-11D9-BED3-505054503030}", L"Logon",                       true,  true  },
        { L"{0CCE921B-69AE-11D9-BED3-505054503030}", L"Special Logon",               true,  false },
        { L"{0CCE922F-69AE-11D9-BED3-505054503030}", L"Audit Policy Change",         true,  false },
        { L"{0CCE9228-69AE-11D9-BED3-505054503030}", L"Sensitive Privilege Use",     true,  true  },
        { L"{0CCE9211-69AE-11D9-BED3-505054503030}", L"Security System Extension",   true,  false },
    };
    return subcategories;
}
