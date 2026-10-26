// Pure helper logic: text utilities, command-line rules, hosts, DNS, software
// versions, script rules, download marks, the AI endpoint gate and CLI parsing.

#include "TestFramework.h"

#include "../AppPaths.h"
#include "../CheckHelpers.h"
#include "../CliRunner.h"
#include "../FileIO.h"
#include "../FileOrigin.h"
#include "../JsonReader.h"
#include "../LLMClient.h"
#include "../ScanCore.h"
#include "../ScanCsv.h"
#include "../ScriptAnalysis.h"
#include "../SecurityChecks.h"
#include "../StartupRequest.h"
#include "../TextUtils.h"

#include <windows.h>
#include <ntsecapi.h>
#include <objbase.h>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

static bool HasCode(const std::vector<std::wstring>& list, const std::wstring& code)
{
    for (const std::wstring& s : list) {
        if (s.rfind(code, 0) == 0) return true;
    }
    return false;
}

TEST(Text_Utilities)
{
    CHECK_EQ(ToLowerW(L"AbC\x00C9"), std::wstring(L"abc\x00E9"));
    CHECK(ContainsI(L"Hello World", L"WORLD"));
    CHECK(StartsWithI(L"C:\\Windows\\x", L"c:\\windows"));
    CHECK(EndsWithI(L"file.EXE", L".exe"));
    CHECK_EQ(TrimW(L" \t x y \r\n"), std::wstring(L"x y"));
    CHECK_EQ(SplitW(L"a; b;;c", L';').size(), static_cast<size_t>(3));
    CHECK_EQ(SplitW(L"a;;b", L';', false).size(), static_cast<size_t>(3));
    CHECK_EQ(SplitAnyW(L"a\r\nb;c", L";\r\n").size(), static_cast<size_t>(3));
    CHECK_EQ(JoinW({ L"a", L"b" }, L", "), std::wstring(L"a, b"));
    CHECK_EQ(ReplaceAllI(L"Foo foo FOO", L"foo", L"x"), std::wstring(L"x x x"));

    CHECK_EQ(CompareVersions(L"24.09", L"24.9"), 0);
    CHECK_EQ(CompareVersions(L"3.0.21", L"3.0.3"), 1);
    CHECK_EQ(CompareVersions(L"0.80", L"0.81"), -1);
    CHECK_EQ(CompareVersions(L"8.8.2", L"8.8.2.0"), 0);
    CHECK_EQ(CompareVersions(L"23.01 (x64)", L"24.09"), -1);

    CHECK_EQ(CsvEscape(L"plain"), std::wstring(L"plain"));
    CHECK_EQ(CsvEscape(L"a,b"), std::wstring(L"\"a,b\""));
    CHECK_EQ(CsvEscape(L"say \"hi\""), std::wstring(L"\"say \"\"hi\"\"\""));
    CHECK_EQ(HtmlEscape(L"<a href='x'>&\"</a>"), std::wstring(L"&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;"));
    CHECK_EQ(FormatFixed(2.0 / 3.0, 2), std::wstring(L"0.67"));
    CHECK_EQ(AsciiPunctuation(L"a\x2014" L"b \x201Cq\x201D \x2019"), std::wstring(L"a-b \"q\" '"));
}

TEST(Paths_Helpers)
{
    CHECK_EQ(FileNameOf(L"C:\\a\\b.exe"), std::wstring(L"b.exe"));
    CHECK_EQ(DirectoryOf(L"C:\\a\\b.exe"), std::wstring(L"C:\\a"));
    CHECK_EQ(JoinPath(L"C:\\a\\", L"b"), std::wstring(L"C:\\a\\b"));
    CHECK_EQ(JoinPath(L"C:\\a", L"b"), std::wstring(L"C:\\a\\b"));
    CHECK_EQ(ExtensionOf(L"C:\\x\\Y.EXE"), std::wstring(L".exe"));
    CHECK_EQ(ExtensionOf(L"C:\\x.y\\noext"), std::wstring(L""));
    std::wstring longPath = L"C:\\" + std::wstring(260, L'a') + L"\\x.exe";
    CHECK(ToExtendedPath(longPath).rfind(L"\\\\?\\", 0) == 0);
    CHECK_EQ(ToExtendedPath(L"C:\\short.exe"), std::wstring(L"C:\\short.exe"));
    CHECK(IsPackagedAppPath(L"C:\\Program Files\\WindowsApps\\Pkg_1.0\\app.exe"));
    CHECK(!IsPackagedAppPath(L"C:\\Program Files\\App\\app.exe"));
    CHECK(IsExecutableExtension(L"x.PS1"));
    CHECK(IsExecutableExtension(L"x.lnk"));
    CHECK(!IsExecutableExtension(L"x.txt"));
    CHECK(!IsExecutableExtension(L"noext"));

    std::wstring dir = tf::TestDir() + L"a\\b\\c";
    CHECK(EnsureDirectory(dir));
    CHECK(DirectoryExists(dir));
    CHECK(!FileExists(dir));

    // A folder we just created is writable by us; Windows itself is not writable by normal users.
    // Both directions, so a function that always answers "no" (for example because it
    // cannot read permissions) fails here.
    std::wstring who;
    CHECK(LowPrivilegeWritable(dir, true, &who));
    CHECK(!who.empty());
    wchar_t sys[MAX_PATH] = {};
    GetSystemDirectoryW(sys, MAX_PATH);
    CHECK(!LowPrivilegeWritable(sys, true, nullptr));
}

TEST(Rules_CommandLines)
{
    std::wstring reason;
    CHECK(IsSuspiciousCommandLine(L"powershell.exe -NoProfile -EncodedCommand SQBFAFgA", &reason));
    CHECK(!reason.empty());
    CHECK(IsSuspiciousCommandLine(L"cmd /c certutil -decode in.txt out.exe", &reason));
    CHECK(!IsSuspiciousCommandLine(L"\"C:\\Program Files\\App\\app.exe\" --background", &reason));
    CHECK(!IsSuspiciousCommandLine(L"notepad.exe C:\\notes.txt", &reason));
    CHECK_EQ(CommandLineSuspicion(L"powershell -EncodedCommand AAAA", &reason), 2);
    CHECK_EQ(CommandLineSuspicion(L"C:\\Windows\\System32\\notepad.exe", &reason), 0);
    CHECK(CommandLineSuspicion(L"powershell.exe -WindowStyle Hidden -File C:\\x.ps1", &reason) >= 1);

    std::vector<std::wstring> dlls = SplitAppInitList(L"C:\\Program Files\\A B\\x.dll,C:\\y.dll");
    REQUIRE(dlls.size() == 2);
    CHECK_EQ(dlls[0], std::wstring(L"C:\\Program Files\\A B\\x.dll"));
    CHECK_EQ(dlls[1], std::wstring(L"C:\\y.dll"));
    CHECK(SplitAppInitList(L"").empty());

    CHECK_EQ(ProgramFromCommandLine(L"\"C:\\a b\\x.exe\" -y"), std::wstring(L"C:\\a b\\x.exe"));
    CHECK_EQ(ProgramFromCommandLine(L"C:\\tools\\x.exe /q"), std::wstring(L"C:\\tools\\x.exe"));
}

TEST(Rules_LongEvidenceIsCapped)
{
    CappedList list(3);
    CHECK(list.Empty());
    for (int i = 0; i < 10; ++i) list.Add(L"line " + std::to_wstring(i) + L"\n");
    CHECK_EQ(list.Total(), static_cast<size_t>(10));
    std::wstring text = list.Text();
    CHECK(text.find(L"line 2") != std::wstring::npos);
    CHECK(text.find(L"line 3") == std::wstring::npos);
    CHECK(text.find(L"and 7 more") != std::wstring::npos);

    CappedList few(5);
    few.Add(L"a\n");
    CHECK_EQ(few.Text(), std::wstring(L"a\n"));   // no "more" line when nothing was left out

    std::wstring shortText = L"short evidence";
    CHECK_EQ(LimitDetail(shortText), shortText);
    std::wstring huge;
    for (int i = 0; i < 5000; ++i) huge += L"autostart entry number " + std::to_wstring(i) + L"\n";
    std::wstring cut = LimitDetail(huge);
    CHECK(cut.size() < 20200);
    CHECK(cut.find(L"was cut to keep the report readable") != std::wstring::npos);
    CHECK(cut.find(L"autostart entry number 0\n") == 0);
}

TEST(Rules_HostsAndDns)
{
    std::vector<HostsEntry> hosts = ParseHostsFile(
        L"# comment line\r\n127.0.0.1 localhost\r\n10.0.0.5 update.microsoft.com other.example # note\r\n\r\n");
    REQUIRE(hosts.size() == 2);
    CHECK_EQ(hosts[0].address, std::wstring(L"10.0.0.5"));
    CHECK_EQ(hosts[0].host, std::wstring(L"update.microsoft.com"));
    CHECK_EQ(hosts[0].line, 3);
    CHECK_EQ(hosts[1].host, std::wstring(L"other.example"));

    CHECK(IsWatchedDomain(L"update.microsoft.com"));
    CHECK(IsWatchedDomain(L"PAYPAL.COM"));
    CHECK(!IsWatchedDomain(L"notmicrosoft.com"));
    CHECK(!IsWatchedDomain(L"example.org"));

    CHECK(IsPrivateOrLocalAddress(L"10.1.2.3"));
    CHECK(IsPrivateOrLocalAddress(L"172.16.0.1"));
    CHECK(!IsPrivateOrLocalAddress(L"172.32.0.1"));
    CHECK(IsPrivateOrLocalAddress(L"192.168.1.1"));
    CHECK(IsPrivateOrLocalAddress(L"127.0.0.1"));
    CHECK(IsPrivateOrLocalAddress(L"fe80::1"));
    CHECK(IsPrivateOrLocalAddress(L"fd00::1"));
    CHECK(!IsPrivateOrLocalAddress(L"8.8.8.8"));
    CHECK(!IsPrivateOrLocalAddress(L"not an address"));
    CHECK(IsWellKnownPublicResolver(L"1.1.1.1"));
    CHECK(IsWellKnownPublicResolver(L"2001:4860:4860::8888"));
    CHECK(!IsWellKnownPublicResolver(L"192.0.2.1"));
}

TEST(Rules_Software)
{
    std::vector<InstalledProgram> programs(4);
    programs[0].displayName = L"7-Zip 23.01 (x64)";
    programs[0].displayVersion = L"23.01";
    programs[1].displayName = L"7-Zip 24.09 (x64)";
    programs[1].displayVersion = L"24.09";
    programs[2].displayName = L"Some Other Tool";
    programs[2].displayVersion = L"1.0";
    programs[3].displayName = L"PuTTY release 0.80 (64-bit)";
    programs[3].displayVersion = L"0.80.0.0";
    std::vector<SoftwareFinding> found = FindOutdatedSoftware(programs, GetBuiltInSoftwareRules());
    REQUIRE(found.size() == 2);
    std::vector<std::wstring> names;
    for (const SoftwareFinding& f : found) names.push_back(f.name);
    CHECK(std::find(names.begin(), names.end(), L"7-Zip 23.01 (x64)") != names.end());
    CHECK(std::find(names.begin(), names.end(), L"PuTTY release 0.80 (64-bit)") != names.end());

    std::vector<SoftwareRule> rules = ParseSoftwareRules(L"# comment\r\nFoo App|2.0|old\r\nBar Tool||end of life\r\nbad line\r\n");
    REQUIRE(rules.size() == 2);
    CHECK_EQ(rules[0].namePrefix, std::wstring(L"Foo App"));
    CHECK_EQ(rules[0].minimumVersion, std::wstring(L"2.0"));
    CHECK(rules[1].minimumVersion.empty());

    std::vector<InstalledProgram> mine(2);
    mine[0].displayName = L"Foo App";
    mine[0].displayVersion = L"1.9";
    mine[1].displayName = L"Bar Tool";
    mine[1].displayVersion = L"99";
    CHECK_EQ(FindOutdatedSoftware(mine, rules).size(), static_cast<size_t>(2));   // old version, and end of life
}

TEST(Rules_WindowsProcessesAndLsa)
{
    CHECK(IsExpectedLsaPackage(L"Authentication Packages", L"msv1_0"));
    CHECK(!IsExpectedLsaPackage(L"Authentication Packages", L"unknownpkg"));
    CHECK_EQ(ExpectedParentProcess(L"lsass.exe"), std::wstring(L"wininit.exe"));
    CHECK(ExpectedParentProcess(L"notepad.exe").empty());
    CHECK(!ExpectedSystemProcessFolder(L"lsass.exe").empty());
    CHECK(IsOfficeProcess(L"winword.exe"));
    CHECK(IsShellOrScriptHost(L"powershell.exe"));
    CHECK(!IsShellOrScriptHost(L"notepad.exe"));

    // Every recommended audit subcategory GUID is one Windows knows.
    for (const AuditSubcategory& sub : GetRecommendedAuditSubcategories()) {
        GUID guid = {};
        bool parsed = SUCCEEDED(CLSIDFromString(sub.guid, &guid));
        if (!parsed) {
            tf::Fail(__FILE__, __LINE__, "bad GUID text " + tf::Narrow(sub.guid));
            continue;
        }
        PWSTR name = nullptr;
        if (AuditLookupSubCategoryNameW(&guid, &name) && name) {
            AuditFree(name);
        }
        else {
            tf::Fail(__FILE__, __LINE__, "Windows does not know audit subcategory " + tf::Narrow(sub.guid));
        }
    }
}

TEST(Rules_Scripts)
{
    ScriptAnalysisResult clean = AnalyzeScriptText(L"Write-Output 'hello'\r\nGet-Date\r\n", L".ps1");
    CHECK(clean.analyzed);
    CHECK(clean.indicators.empty());
    CHECK(clean.score < 0.01);

    ScriptAnalysisResult bad = AnalyzeScriptText(
        L"powershell -NoProfile -WindowStyle Hidden -EncodedCommand AAAA\r\n"
        L"Set-MpPreference -DisableRealtimeMonitoring $true\r\n", L".ps1");
    CHECK(bad.analyzed);
    CHECK(HasCode(bad.indicators, L"ENCODED_COMMAND"));
    CHECK(HasCode(bad.indicators, L"HIDDEN_WINDOW"));
    CHECK(HasCode(bad.indicators, L"DEFENDER_TAMPERING"));
    CHECK(bad.score > clean.score);
    CHECK(bad.score <= 10.0);
    CHECK(!bad.techniques.empty());

    // Language rules: WScript.Shell matters in VBScript, not in a batch file.
    CHECK(HasCode(AnalyzeScriptText(L"Set s = CreateObject(\"WScript.Shell\")", L".vbs").indicators, L"WSCRIPT_SHELL"));
    CHECK(!HasCode(AnalyzeScriptText(L"rem WScript.Shell", L".bat").indicators, L"WSCRIPT_SHELL"));

    CHECK(IsScriptExtension(L".ps1"));
    CHECK(IsScriptExtension(L".hta"));
    CHECK(!IsScriptExtension(L".exe"));
    CHECK(!AnalyzeScriptText(L"x", L".exe").analyzed);

    std::wstring utf16 = tf::TestDir() + L"u16.ps1";
    std::wstring body = L"\xFEFFInvoke-Expression $x";
    REQUIRE(WriteBinaryFile(utf16, body.data(), body.size() * sizeof(wchar_t)));
    CHECK(HasCode(AnalyzeScriptFile(utf16).indicators, L"INVOKE_EXPRESSION"));
}

TEST(Origin_ZoneIdentifier)
{
    int zone = -1;
    std::wstring host, referrer;
    ParseZoneIdentifier(L"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a.example/\r\nHostUrl=https://b.example/f.exe\r\n",
        zone, host, referrer);
    CHECK_EQ(zone, 3);
    CHECK_EQ(host, std::wstring(L"https://b.example/f.exe"));
    CHECK_EQ(referrer, std::wstring(L"https://a.example/"));
    CHECK(!ZoneName(3).empty());

    // On disk: a mark and an extra stream are both found.
    std::wstring path = tf::TestDir() + L"dl.exe";
    REQUIRE(WriteBinaryFile(path, "MZ", 2));
    std::string mark = "[ZoneTransfer]\r\nZoneId=3\r\n";
    REQUIRE(WriteBinaryFile(path + L":Zone.Identifier", mark.data(), mark.size()));
    std::string extra = "MZ hidden program bytes";
    REQUIRE(WriteBinaryFile(path + L":payload.bin", extra.data(), extra.size()));
    FileOriginInfo info = AnalyzeFileOrigin(path, true);
    CHECK_EQ(info.zoneId, 3);
    REQUIRE(info.streams.size() == 1);
    CHECK_EQ(info.streams[0].name, std::wstring(L"payload.bin"));
    CHECK(info.streams[0].executable);
    CHECK(HasCode(info.warnings, L"MOTW_INTERNET"));
    CHECK(HasCode(info.warnings, L"ADS_EXECUTABLE"));
}

TEST(Ai_EndpointGate)
{
    CHECK(IsLoopbackEndpoint(L"http://localhost:1234/v1/chat/completions"));
    CHECK(IsLoopbackEndpoint(L"http://127.0.0.1:8080/v1"));
    CHECK(IsLoopbackEndpoint(L"http://[::1]:1234/v1"));
    CHECK(!IsLoopbackEndpoint(L"https://api.example.com/v1/chat/completions"));
    CHECK(!IsLoopbackEndpoint(L"http://localhost.example.com/v1"));
    CHECK(!IsLoopbackEndpoint(L"not a url"));
    LLMConfig defaults;
    CHECK(IsLoopbackEndpoint(defaults.endpoint));   // the default never leaves the PC
    CHECK(defaults.redact);
}

TEST(Gui_StartupArguments)
{
    StartupRequest r = ParseStartupArguments({ L"C:\\x\\results.CSV", L"--portable", L"--SAMPLES", L"D:\\demo",
                                               L"base.prbl", L"notes.txt" });
    REQUIRE(r.files.size() == 2);
    CHECK_EQ(r.files[0], std::wstring(L"C:\\x\\results.CSV"));
    CHECK_EQ(r.files[1], std::wstring(L"base.prbl"));
    CHECK_EQ(r.samplesFolder, std::wstring(L"D:\\demo"));
    REQUIRE(r.unknown.size() == 1);
    CHECK_EQ(r.unknown[0], std::wstring(L"notes.txt"));

    StartupRequest missing = ParseStartupArguments({ L"--samples" });
    CHECK(missing.samplesFolder.empty());
    CHECK_EQ(missing.unknown.size(), static_cast<size_t>(1));
    CHECK(ParseStartupArguments({}).files.empty());
}

TEST(Cli_ArgumentParsing)
{
    CliOptions help = ParseCliArguments({});
    CHECK(help.help);

    CliOptions a = ParseCliArguments({ L"--audit", L"--report", L"r.html", L"--json", L"r.json", L"--redact" });
    CHECK(a.error.empty());
    CHECK(a.audit);
    CHECK_EQ(a.htmlPath, std::wstring(L"r.html"));
    CHECK_EQ(a.jsonPath, std::wstring(L"r.json"));
    CHECK(a.redact);

    CliOptions d = ParseCliArguments({ L"--diff", L"old.prbl", L"new.prbl" });
    CHECK(d.error.empty());
    CHECK_EQ(d.diffOlder, std::wstring(L"old.prbl"));
    CHECK_EQ(d.diffNewer, std::wstring(L"new.prbl"));

    CHECK(!ParseCliArguments({ L"--full" }).error.empty());                         // missing value
    CHECK(!ParseCliArguments({ L"--fast", L"--full", L"C:\\" }).error.empty());     // two scans
    CHECK(!ParseCliArguments({ L"--revocation", L"sometimes" }).error.empty());
    CHECK(!ParseCliArguments({ L"--made-up" }).error.empty());
    CHECK(ParseCliArguments({ L"--FAST" }).fastScan);                              // case-insensitive

    std::wstring captured;
    CliEnvironment env;
    env.out = [&](const std::wstring& t) { captured += t; };
    CHECK_EQ(RunCli(ParseCliArguments({ L"--version" }), env), 0);
    CHECK(captured.find(L"Phantom Recon") != std::wstring::npos);
    captured.clear();
    CHECK_EQ(RunCli(ParseCliArguments({ L"--bogus" }), env), 2);
    CHECK(captured.find(L"Unknown option") != std::wstring::npos);

    // End to end: sample pack, then a Full Scan against its demo baseline.
    std::wstring pack = tf::TestDir() + L"pack";
    captured.clear();
    CHECK_EQ(RunCli(ParseCliArguments({ L"--make-samples", pack }), env), 0);
    std::wstring html = tf::TestDir() + L"demo.html";
    std::wstring csv = tf::TestDir() + L"demo.csv";
    std::wstring json = tf::TestDir() + L"demo.json";
    int code = RunCli(ParseCliArguments({ L"--full", pack, L"--baseline", pack + L"\\demo_baseline.prbl",
                                          L"--report", html, L"--csv", csv, L"--json", json, L"--revocation", L"off",
                                          L"--quiet" }), env);
    CHECK_EQ(code, 1);   // NEW, CHANGED and MISSING files need attention
    CHECK(FileExists(html));
    CHECK(FileExists(csv));

    // Exit code 1 also comes from any file scoring 7 or more, so on its own it would
    // pass with the comparison broken. The counts prove the comparison ran.
    std::vector<uint8_t> raw;
    REQUIRE(ReadBinaryFile(json, raw));
    JsonValue doc;
    std::string error;
    REQUIRE(ParseJson(std::string(raw.begin(), raw.end()), doc, error));
    const JsonValue* scan = doc.Find("scan");
    REQUIRE(scan != nullptr);
    const JsonValue* counts = scan->Find("counts");
    REQUIRE(counts != nullptr);
    auto count = [&](const char* key) {
        const JsonValue* v = counts->Find(key);
        return v && v->type == JsonValue::Type::Number ? static_cast<int>(v->number) : -1;
    };
    CHECK_EQ(count("new"), 1);
    CHECK_EQ(count("changed"), 1);
    CHECK_EQ(count("missing"), 1);
    CHECK_EQ(count("match"), 5);
    CHECK_EQ(count("updated"), 0);
    CHECK_EQ(count("known"), 0);

    // And the CSV holds one row per file, with the same statuses.
    std::vector<ScanRow> rows;
    REQUIRE(LoadRowsFromCsv(csv, rows));
    int fresh = 0, changed = 0, missing = 0;
    for (const ScanRow& r : rows) {
        if (r.status == L"NEW") ++fresh;
        if (r.status == L"CHANGED") ++changed;
        if (r.status == L"MISSING") ++missing;
    }
    CHECK_EQ(fresh, 1);
    CHECK_EQ(changed, 1);
    CHECK_EQ(missing, 1);
}
