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

    // Encoded PowerShell. PowerShell accepts any unambiguous start of a parameter
    // name, with "-", "/" or a typographic dash in front: -e, -en, -enc, -enco ...
    // -encodedcommand, plus the alias -ec. The long forms always count. The short
    // ones (-e, -en, -ec) also mean other things in other programs (node -e,
    // xcopy /e), so they count only on a PowerShell command line or when the next
    // word is base64 text.
    if (best < 2) {
        const bool powershell = flat.find(L"powershell") != std::wstring::npos || flat.find(L"pwsh") != std::wstring::npos;
        auto isDash = [](wchar_t ch) {
            return ch == L'-' || ch == L'/' || ch == L'\x2013' || ch == L'\x2014' || ch == L'\x2015';
        };
        auto looksBase64 = [](const std::wstring& s) {
            if (s.size() < 8) return false;
            for (wchar_t ch : s) {
                bool ok = (ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') || ch == L'+' || ch == L'/' || ch == L'=';
                if (!ok) return false;
            }
            return true;
        };
        static const std::wstring encoded = L"encodedcommand";
        std::vector<std::wstring> words = SplitAnyW(flat, L" \t\r\n");
        // On a PowerShell command line only PowerShell's own options count: start after
        // the powershell / pwsh word and stop at -Command or -File, where the script
        // text (with its own -e style options) begins.
        size_t from = 0;
        if (powershell) {
            for (size_t i = 0; i < words.size(); ++i) {
                if (words[i].find(L"powershell") != std::wstring::npos || words[i].find(L"pwsh") != std::wstring::npos) {
                    from = i + 1;
                    break;
                }
            }
        }
        auto startsName = [](const std::wstring& full, const std::wstring& part) {
            return !part.empty() && part.size() <= full.size() && full.compare(0, part.size(), part) == 0;
        };
        for (size_t i = from; i < words.size(); ++i) {
            const std::wstring& word = words[i];
            size_t start = 0;
            while (start < word.size() && start < 2 && isDash(word[start])) ++start;
            if (start == 0 || start >= word.size()) continue;
            std::wstring name = word.substr(start);
            size_t colon = name.find(L':');
            if (colon != std::wstring::npos) name = name.substr(0, colon);
            if (name.empty()) continue;
            if (powershell && (startsName(L"command", name) || startsName(L"file", name))) break;
            bool isEncodedFlag = name == L"ec" || startsName(encoded, name);
            if (!isEncodedFlag) continue;
            bool longForm = name == L"enc" || name == encoded;
            bool nextIsBase64 = i + 1 < words.size() && looksBase64(words[i + 1]);
            if (longForm || powershell || nextIsBase64) {
                best = 2;
                if (reason) *reason = L"encoded PowerShell command";
                break;
            }
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
    // A name with '*' is a whole-name pattern (see FindOutdatedSoftware).
    static const std::vector<SoftwareRule> rules = [] {
        std::vector<SoftwareRule> r = {
        { L"7-Zip",                     L"24.09",  L"CVE-2025-0411: Mark of the Web is not passed to extracted files" },
        { L"WinRAR",                    L"7.13",   L"CVE-2025-8088: path traversal exploited in the wild" },
        { L"PuTTY",                     L"0.81",   L"CVE-2024-31497: NIST P-521 private keys can be recovered" },
        { L"WinSCP",                    L"6.3.3",  L"Bundles PuTTY code affected by CVE-2024-31497" },
        // The FileZilla client and Pro bundle PuTTY code; FileZilla Server is a different
        // product with its own 1.x versions and must not match.
        { L"FileZilla Client",          L"3.67.0", L"Bundles PuTTY code affected by CVE-2024-31497" },
        { L"FileZilla Pro",             L"3.67.0", L"Bundles PuTTY code affected by CVE-2024-31497" },
        { L"FileZilla 3*",              L"3.67.0", L"Bundles PuTTY code affected by CVE-2024-31497" },
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
        };
        // Office suites register as "Microsoft Office <edition> <year>" ("Microsoft Office
        // Professional Plus 2016", "Microsoft Office Home and Student 2019 - en-us").
        // Matching the edition keeps out the many parts each suite also registers
        // ("Microsoft Office Proofing Tools 2016 - English", "... MUI (English) 2016").
        struct OfficeYear { const wchar_t* year; const wchar_t* reason; };
        static const OfficeYear years[] = {
            { L"2010", L"Office 2010 is end of life since October 2020" },
            { L"2013", L"Office 2013 is end of life since April 2023" },
            { L"2016", L"Office 2016 support ended October 2025" },
            { L"2019", L"Office 2019 support ended October 2025" },
        };
        static const wchar_t* const editions[] = {
            L"Professional*", L"Standard", L"Home and *", L"Small Business*", L"Starter", L"Enterprise", L"Ultimate",
        };
        for (const OfficeYear& y : years) {
            for (const wchar_t* edition : editions) {
                r.push_back({ std::wstring(L"Microsoft Office ") + edition + L" " + y.year + L"*", L"", y.reason });
            }
        }
        return r;
    }();
    return rules;
}

std::vector<SoftwareRule> ParseSoftwareRules(const std::wstring& text)
{
    std::vector<SoftwareRule> rules;
    for (const std::wstring& raw : SplitAnyW(text, L"\r\n")) {
        std::wstring line = TrimW(raw);
        if (line.empty() || line[0] == L'#') continue;
        // A line needs at least "name|version". Without the bar it is a typo, not an
        // end-of-life rule that would flag every program starting with that text.
        std::vector<std::wstring> parts = SplitW(line, L'|', false);
        if (parts.size() < 2 || parts[0].empty()) continue;
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
    // A rule name with '*' must match the whole display name, '*' standing for any
    // run of characters ("Microsoft Office Professional* 2016*"). Without '*' it is
    // a prefix, as before. Both ignore case.
    auto wildcardMatch = [](const std::wstring& textIn, const std::wstring& patternIn) {
        std::wstring text = ToLowerW(textIn);
        std::wstring pattern = ToLowerW(patternIn);
        size_t t = 0, p = 0;
        size_t starP = std::wstring::npos, starT = 0;
        while (t < text.size()) {
            if (p < pattern.size() && pattern[p] == L'*') {
                starP = p++;
                starT = t;
            }
            else if (p < pattern.size() && pattern[p] == text[t]) {
                ++p;
                ++t;
            }
            else if (starP != std::wstring::npos) {
                p = starP + 1;
                t = ++starT;
            }
            else {
                return false;
            }
        }
        while (p < pattern.size() && pattern[p] == L'*') ++p;
        return p == pattern.size();
    };

    std::vector<SoftwareFinding> findings;
    for (const InstalledProgram& p : programs) {
        for (const SoftwareRule& r : rules) {
            bool pattern = r.namePrefix.find(L'*') != std::wstring::npos;
            if (pattern ? !wildcardMatch(p.displayName, r.namePrefix) : !StartsWithI(p.displayName, r.namePrefix)) continue;
            bool flagged = false;
            if (r.minimumVersion.empty()) {
                flagged = true;
            }
            else if (!p.displayVersion.empty()) {
                flagged = CompareVersions(p.displayVersion, r.minimumVersion) < 0;
            }
            else {
                // Some installers put the version in the name ("7-Zip 23.01 (x64)").
                // For a pattern, read from the end of its text before the first '*'.
                size_t literal = pattern ? r.namePrefix.find(L'*') : r.namePrefix.size();
                while (pattern && literal > 0 && iswdigit(r.namePrefix[literal - 1])) --literal;   // "FileZilla 3*": keep the 3
                std::wstring tail = p.displayName.substr(literal < p.displayName.size() ? literal : p.displayName.size());
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

// ---------------------------------------------------------------------------
// Audit checks B: network, paths, persistence, processes, software, tasks
// ---------------------------------------------------------------------------
static void HelperTrace(const std::wstring& msg)
{
    OutputDebugStringW((L"[CheckHelpers] " + msg + L"\n").c_str());
}

namespace {

struct CommandArg {
    std::wstring text;     // quotes removed
    size_t       start = 0;
    bool         quoted = false;
};

// Split a command line the way most programs do: spaces and tabs separate arguments
// unless inside double quotes; the quotes themselves are dropped.
std::vector<CommandArg> SplitCommandArgs(const std::wstring& s)
{
    std::vector<CommandArg> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == L' ' || s[i] == L'\t')) ++i;
        if (i >= s.size()) break;
        CommandArg a;
        a.start = i;
        bool inQuotes = false;
        while (i < s.size()) {
            wchar_t c = s[i];
            if (c == L'"') {
                inQuotes = !inQuotes;
                a.quoted = true;
                ++i;
                continue;
            }
            if (!inQuotes && (c == L' ' || c == L'\t')) break;
            a.text += c;
            ++i;
        }
        out.push_back(a);
    }
    return out;
}

bool IsSwitchArg(const std::wstring& t)
{
    return !t.empty() && (t[0] == L'/' || t[0] == L'-');
}

// True when name (without the dash) is an accepted abbreviation of one of the full
// parameter names. PowerShell takes any unambiguous prefix.
bool IsParameterPrefix(const std::wstring& name, std::initializer_list<const wchar_t*> fullNames)
{
    if (name.empty()) return false;
    for (const wchar_t* full : fullNames) {
        if (std::wstring(full).rfind(name, 0) == 0) return true;
    }
    return false;
}

std::wstring PayloadAt(const std::wstring& commandLine, int depth);

// Everything after a host's own switches, followed one level deeper.
std::wstring PayloadOfRest(const std::wstring& rest, int depth)
{
    std::wstring r = TrimW(rest);
    // cmd /c ""C:\a b\x.exe" arg": cmd drops the outer pair of quotes.
    if (r.size() >= 2 && r[0] == L'"' && r[1] == L'"') {
        r = r.substr(1);
        size_t last = r.find_last_of(L'"');
        if (last != std::wstring::npos) r.erase(last, 1);
    }
    if (r.empty()) return L"";
    if (depth < 4) {
        std::wstring inner = PayloadAt(r, depth + 1);
        if (!inner.empty()) return inner;
    }
    return ProgramFromCommandLine(r);
}

std::wstring PayloadAt(const std::wstring& commandLineIn, int depth)
{
    std::wstring commandLine = TrimW(commandLineIn);
    std::vector<CommandArg> args = SplitCommandArgs(commandLine);
    if (args.empty()) return L"";

    // The host program: the first argument, or for an unquoted path with spaces
    // ("C:\Program Files\PowerShell\7\pwsh.exe -File x.ps1") the words up to ".exe".
    size_t last = 0;
    std::wstring program = args[0].text;
    std::wstring firstName = ToLowerW(FileNameOf(program));
    if (EndsWithI(firstName, L".exe")) firstName = firstName.substr(0, firstName.size() - 4);
    static const wchar_t* const hosts[] = {
        L"rundll32", L"regsvr32", L"wscript", L"cscript", L"mshta", L"powershell", L"pwsh", L"cmd", L"conhost",
    };
    bool firstIsHost = false;
    for (const wchar_t* h : hosts) {
        if (firstName == h) firstIsHost = true;
    }
    if (!args[0].quoted && !firstIsHost && args[0].text.find(L'\\') != std::wstring::npos) {
        std::wstring joined;
        for (size_t k = 0; k < args.size(); ++k) {
            if (args[k].quoted) break;
            joined += (k == 0 ? L"" : L" ") + args[k].text;
            if (EndsWithI(joined, L".exe") || EndsWithI(joined, L".com")) {
                program = joined;
                last = k;
                break;
            }
        }
    }
    std::wstring host = ToLowerW(FileNameOf(program));
    if (EndsWithI(host, L".exe")) host = host.substr(0, host.size() - 4);
    const size_t n = args.size();
    const size_t firstArg = last + 1;

    std::wstring payload;
    if (host == L"rundll32") {
        if (firstArg < n) {
            const std::wstring& a = args[firstArg].text;
            size_t comma = a.find(L',');
            std::wstring dll = TrimW(comma == std::wstring::npos ? a : a.substr(0, comma));
            std::wstring entry = comma == std::wstring::npos ? (firstArg + 1 < n ? args[firstArg + 1].text : L"")
                                                             : a.substr(comma + 1);
            size_t afterEntry = comma == std::wstring::npos ? firstArg + 2 : firstArg + 1;
            bool shell32 = EqualsI(FileNameOf(dll), L"shell32.dll") || EqualsI(FileNameOf(dll), L"shell32");
            if (shell32 && StartsWithI(TrimW(entry), L"control_rundll") && afterEntry < n) {
                // "rundll32 shell32.dll,Control_RunDLL x.cpl" opens a Control Panel item.
                std::wstring cpl = args[afterEntry].text;
                size_t cplComma = cpl.find(L',');
                payload = cplComma == std::wstring::npos ? cpl : cpl.substr(0, cplComma);
            }
            else {
                payload = dll;
            }
        }
    }
    else if (host == L"regsvr32") {
        for (size_t k = firstArg; k < n; ++k) {
            if (!IsSwitchArg(args[k].text)) payload = args[k].text;
        }
    }
    else if (host == L"wscript" || host == L"cscript") {
        for (size_t k = firstArg; k < n; ++k) {
            if (!IsSwitchArg(args[k].text)) {
                payload = args[k].text;
                break;
            }
        }
    }
    else if (host == L"mshta") {
        if (firstArg < n && !IsSwitchArg(args[firstArg].text)) payload = args[firstArg].text;
    }
    else if (host == L"powershell" || host == L"pwsh") {
        for (size_t k = firstArg; k < n; ++k) {
            std::wstring t = ToLowerW(args[k].text);
            if (!IsSwitchArg(t)) {
                // Windows PowerShell runs a bare script path as a command; pwsh treats
                // any first plain argument as -File.
                if (host == L"pwsh" || EndsWithI(t, L".ps1")) payload = args[k].text;
                break;
            }
            std::wstring name = t.substr(1);
            if (IsParameterPrefix(name, { L"file" })) {
                if (k + 1 < n) payload = args[k + 1].text;
                break;
            }
            if (IsParameterPrefix(name, { L"command", L"encodedcommand" }) || name == L"ec") break;
            if (IsParameterPrefix(name, { L"executionpolicy", L"windowstyle", L"version", L"psconsolefile", L"inputformat",
                                          L"outputformat", L"configurationname", L"workingdirectory", L"settingsfile",
                                          L"custompipename", L"encodedarguments" }) ||
                name == L"ep" || name == L"wd") {
                ++k;   // that parameter takes a value
            }
        }
    }
    else if (host == L"cmd") {
        for (size_t k = firstArg; k < n; ++k) {
            std::wstring t = ToLowerW(args[k].text);
            if (t == L"/c" || t == L"/k" || t == L"/r") {
                if (k + 1 >= n) return L"";
                std::wstring rest = commandLine.substr(args[k + 1].start);
                std::vector<CommandArg> restArgs = SplitCommandArgs(rest);
                if (!restArgs.empty() && EqualsI(restArgs[0].text, L"start")) {
                    // start ["title"] [/min /b /d folder ...] program
                    size_t r = 1;
                    if (r < restArgs.size() && restArgs[r].quoted) ++r;
                    while (r < restArgs.size() && IsSwitchArg(restArgs[r].text)) {
                        if (EqualsI(restArgs[r].text, L"/d")) ++r;
                        ++r;
                    }
                    if (r >= restArgs.size()) return L"";
                    rest = rest.substr(restArgs[r].start);
                }
                payload = PayloadOfRest(rest, depth);
                break;
            }
            if (!IsSwitchArg(t)) break;
        }
    }
    else if (host == L"conhost") {
        for (size_t k = firstArg; k < n; ++k) {
            std::wstring t = ToLowerW(args[k].text);
            if (t.rfind(L"--", 0) == 0) {
                if (t == L"--width" || t == L"--height" || t == L"--signal" || t == L"--server") ++k;
                continue;
            }
            if (t == L"0x4") continue;   // legacy console handle argument
            payload = PayloadOfRest(commandLine.substr(args[k].start), depth);
            break;
        }
    }
    else {
        return L"";
    }

    payload = TrimW(payload);
    while (!payload.empty() && payload.front() == L'"') payload.erase(payload.begin());
    while (!payload.empty() && payload.back() == L'"') payload.pop_back();
    if (payload.empty()) return L"";
    std::wstring lower = ToLowerW(payload);
    if (lower.find(L"://") != std::wstring::npos || lower.rfind(L"javascript:", 0) == 0 ||
        lower.rfind(L"vbscript:", 0) == 0 || lower.rfind(L"about:", 0) == 0) {
        return L"";   // inline or remote code; CommandLineSuspicion reports those
    }
    payload = ExpandEnvironment(payload);
    // A bare word with no folder and no extension is a shell built-in ("echo"), not a file.
    if (payload.find(L'\\') == std::wstring::npos && ExtensionOf(payload).empty()) return L"";
    return payload;
}

} // namespace

std::wstring ScriptHostPayload(const std::wstring& commandLine)
{
    std::wstring payload = PayloadAt(commandLine, 0);
    if (!payload.empty()) HelperTrace(L"ScriptHostPayload: " + payload + L" <- " + commandLine);
    return payload;
}

bool SignatureExpected(const std::wstring& path)
{
    static const wchar_t* const unsignedKinds[] = {
        L".url", L".lnk", L".website", L".vsto", L".manifest", L".application", L".xml", L".txt", L".ini", L".json",
        L".bat", L".cmd", L".vbs", L".vbe", L".js", L".jse", L".wsf", L".wsh", L".ps1", L".psm1", L".psd1",
        L".hta", L".reg", L".inf", L".py", L".pyw", L".jar", L".html", L".htm",
    };
    std::wstring ext = ExtensionOf(path);
    for (const wchar_t* e : unsignedKinds) {
        if (ext == e) {
            HelperTrace(L"SignatureExpected: no for " + path);
            return false;
        }
    }
    return true;
}

std::wstring FileUrlToPath(const std::wstring& manifestValue)
{
    std::wstring path = manifestValue;
    size_t bar = path.find(L'|');
    if (bar != std::wstring::npos) path = path.substr(0, bar);
    path = TrimW(path);
    bool url = false;
    if (StartsWithI(path, L"file:///")) {
        path = path.substr(8);
        url = true;
    }
    else if (StartsWithI(path, L"file://")) {
        path = L"//" + path.substr(7);   // file://server/share/x.vsto
        url = true;
    }
    if (url) {
        // Percent-decode the UTF-8 bytes of the URL ("Program%20Files").
        int needed = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()), NULL, 0, NULL, NULL);
        std::string bytes(static_cast<size_t>(needed > 0 ? needed : 0), '\0');
        if (needed > 0) WideCharToMultiByte(CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()), &bytes[0], needed, NULL, NULL);
        auto hexValue = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::string decoded;
        for (size_t i = 0; i < bytes.size(); ++i) {
            int hi = i + 2 < bytes.size() ? hexValue(bytes[i + 1]) : -1;
            int lo = i + 2 < bytes.size() ? hexValue(bytes[i + 2]) : -1;
            if (bytes[i] == '%' && hi >= 0 && lo >= 0) {
                decoded += static_cast<char>(hi * 16 + lo);
                i += 2;
            }
            else {
                decoded += bytes[i];
            }
        }
        int wide = MultiByteToWideChar(CP_UTF8, 0, decoded.c_str(), static_cast<int>(decoded.size()), NULL, 0);
        std::wstring out(static_cast<size_t>(wide > 0 ? wide : 0), L'\0');
        if (wide > 0) MultiByteToWideChar(CP_UTF8, 0, decoded.c_str(), static_cast<int>(decoded.size()), &out[0], wide);
        path = ReplaceAllW(out, L"/", L"\\");
        HelperTrace(L"FileUrlToPath: " + manifestValue + L" -> " + path);
    }
    return path;
}

std::wstring ExtensionMessageKey(const std::wstring& name)
{
    // "__MSG_" + key + "__", with at least one character of key.
    if (name.size() <= 8 || name.rfind(L"__MSG_", 0) != 0) return L"";
    if (name.compare(name.size() - 2, 2, L"__") != 0) {
        HelperTrace(L"ExtensionMessageKey: incomplete reference " + name);
        return L"";
    }
    return name.substr(6, name.size() - 8);
}

std::wstring NormalizeSnapshotKey(const std::wstring& text)
{
    std::wstring lower = ToLowerW(text);
    std::wstring out;
    bool pendingSpace = false;
    for (wchar_t c : lower) {
        bool space = c == L' ' || c == L'\t' || c == L'\r' || c == L'\n' || c == L'\v' || c == L'\f' || c == 0x00A0;
        if (space) {
            pendingSpace = !out.empty();
            continue;
        }
        if (pendingSpace) out += L' ';
        pendingSpace = false;
        out += c;
    }
    if (out.size() != lower.size()) HelperTrace(L"NormalizeSnapshotKey: whitespace folded in " + out);
    return out;
}

bool IsMicrosoftTaskAuthor(const std::wstring& author)
{
    std::wstring a = TrimW(author);
    if (a.empty()) {
        HelperTrace(L"IsMicrosoftTaskAuthor: no author recorded");
        return false;
    }
    if (ContainsI(a, L"Microsoft")) return true;
    std::wstring lower = ToLowerW(a);
    const wchar_t* windowsResources[] = { L"$(@%systemroot%\\", L"@%systemroot%\\", L"$(@%windir%\\", L"@%windir%\\" };
    for (const wchar_t* prefix : windowsResources) {
        if (lower.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

std::wstring CleanPathListEntry(const std::wstring& entry)
{
    std::wstring d = TrimW(entry);
    while (!d.empty() && d.front() == L'"') d.erase(d.begin());
    while (!d.empty() && d.back() == L'"') d.pop_back();
    d = TrimW(d);
    while (d.size() > 1 && (d.back() == L'\\' || d.back() == L'/')) {
        if (d.size() == 3 && d[1] == L':') break;   // "C:\" is the drive root
        d.pop_back();
    }
    if (d != entry) HelperTrace(L"CleanPathListEntry: [" + entry + L"] -> [" + d + L"]");
    return d;
}

std::wstring StripAddressZone(const std::wstring& address)
{
    size_t percent = address.find(L'%');
    if (percent != std::wstring::npos) HelperTrace(L"StripAddressZone: " + address);
    return TrimW(percent == std::wstring::npos ? address : address.substr(0, percent));
}

std::vector<std::wstring> ParseNameServerList(const std::wstring& value)
{
    std::vector<std::wstring> out;
    for (const std::wstring& part : SplitAnyW(value, L", \t;")) {
        std::wstring s = StripAddressZone(part);
        if (!s.empty()) out.push_back(s);
    }
    if (!out.empty()) HelperTrace(L"ParseNameServerList: " + JoinW(out, L", "));
    return out;
}

std::wstring CanonicalAddress(const std::wstring& addressIn)
{
    std::wstring address = StripAddressZone(addressIn);
    wchar_t text[64] = {};
    IN_ADDR v4 = {};
    if (InetPtonW(AF_INET, address.c_str(), &v4) == 1 && InetNtopW(AF_INET, &v4, text, 64)) return text;
    IN6_ADDR v6 = {};
    if (InetPtonW(AF_INET6, address.c_str(), &v6) == 1 && InetNtopW(AF_INET6, &v6, text, 64)) return ToLowerW(text);
    HelperTrace(L"CanonicalAddress: not an IP address: " + address);
    return ToLowerW(address);
}

std::wstring HostsFilePath(const std::wstring& dataBasePath, const std::wstring& defaultFolder)
{
    std::wstring folder = TrimW(dataBasePath);
    if (folder.empty()) folder = defaultFolder;
    std::wstring hosts = JoinPath(folder, L"hosts");
    HelperTrace(L"HostsFilePath: " + hosts);
    return hosts;
}

bool IsBuiltInWindowsRootThumbprint(const std::wstring& sha1Hex)
{
    // Read from the Root store of a Windows 11 25H2 install, October 2026. None of these
    // is in the AuthRoot program list; Windows adds them itself.
    static const wchar_t* const thumbprints[] = {
        L"CDD4EEAE6000AC7F40C3802C171E30148030C072",   // Microsoft Root Certificate Authority
        L"3B1EFD3A66EA28B16697394703A72CA340A05BD5",   // Microsoft Root Certificate Authority 2010
        L"8F43288AD272F3103B6FB1428485EA3014C0BCFE",   // Microsoft Root Certificate Authority 2011
        L"A43489159A520F0D93D032CCAF37E7FE20A8B419",   // Microsoft Root Authority
        L"7F88CD7223F3C813818C994614A89C99FA3B5247",   // Microsoft Authenticode(tm) Root Authority
        L"245C97DF7514E7CF2DF8BE72AE957B9E04741E85",   // Copyright (c) 1997 Microsoft Corp.
        L"06F1AA330B927B753A40E68CDF22E34BCBEF3352",   // Microsoft ECC Product Root Certificate Authority 2018
        L"31F9FC8BA3805986B721EA7295C65B3A44534274",   // Microsoft ECC TS Root Certificate Authority 2018
        L"0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8",   // Microsoft Time Stamp Root Certificate Authority 2014
        L"F40042E2E5F7E8EF8189FED15519AECE42C3BFA2",   // Microsoft Identity Verification Root Certificate Authority 2020
        L"92B46C76E13054E104F230517E6E504D43AB10B5",   // Symantec Enterprise Mobile Root for Microsoft
        L"BE36A4562FB2EE05DBB3D32323ADF445084ED656",   // Thawte Timestamping CA
        L"18F7C1FCC3090203FD5BAA2F861A754976C8DD25",   // VeriSign Time Stamping Service Root
    };
    for (const wchar_t* t : thumbprints) {
        if (EqualsI(sha1Hex, t)) {
            HelperTrace(L"IsBuiltInWindowsRootThumbprint: built-in root " + sha1Hex);
            return true;
        }
    }
    return false;
}

int ParentStartOrder(unsigned long long parentCreated, unsigned long long childCreated)
{
    if (parentCreated == 0 || childCreated == 0) return 0;
    if (parentCreated > childCreated) HelperTrace(L"ParentStartOrder: parent started after the child, PID was reused");
    return parentCreated <= childCreated ? 1 : -1;
}

bool IsPseudoProcessImage(const std::wstring& image)
{
    std::wstring s = TrimW(image);
    if (s.empty()) return false;
    bool pseudo = s.find(L'\\') == std::wstring::npos && s.find(L'/') == std::wstring::npos;
    if (pseudo) HelperTrace(L"IsPseudoProcessImage: " + s);
    return pseudo;
}
