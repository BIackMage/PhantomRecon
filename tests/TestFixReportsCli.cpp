// Reports, command line and AI client fixes from the 2026-10-26 review (group 5):
// the AI host gate (A5), names left in redacted output (B1 to B6), argument parsing,
// scan errors, --diff counts and failed weekly runs (E1 to E5), AI answer parsing,
// size cap and status handling (E7, E8, I1 to I4), finite numbers in the AI request
// (E9), unpaired surrogates in reports and the SplitIntoParts limit.

// Winsock 2 before anything that pulls in windows.h.
#include <winsock2.h>
#include <ws2tcpip.h>

#include "TestFramework.h"
#include "JsonCheck.h"

#include "../AppPaths.h"
#include "../Baseline.h"
#include "../CliRunner.h"
#include "../FileIO.h"
#include "../JsonReader.h"
#include "../JsonWriter.h"
#include "../LLMClient.h"
#include "../Redactor.h"
#include "../Reports.h"
#include "../SampleData.h"
#include "../ScanCore.h"
#include "../ScanCsv.h"
#include "../ScheduledScan.h"
#include "../SecurityChecks.h"
#include "../StringConv.h"
#include "../SystemInfo.h"
#include "../TextUtils.h"

#include <windows.h>
#include <atomic>
#include <cmath>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// True when word occurs in text as a whole word (the redactor's own rule).
static bool HasWholeWord(const std::wstring& text, const std::wstring& word)
{
    if (word.empty()) return false;
    return ReplaceWholeWordI(text, word, L"\x0001") != text;
}

static std::wstring ReadAll(const std::wstring& path)
{
    std::wstring text;
    ReadTextFile(path, text);
    return text;
}

static RedactionTerms FixedTerms()
{
    RedactionTerms t;
    t.userName = L"bo";                                   // two letters (B5)
    t.profileDirectory = L"C:\\Users\\bo";
    t.computerName = L"PCNAME";
    t.domain = L"corp.example";
    t.otherUserNames = { L"lucas", L"Alice Example", L"alice" };
    t.otherProfileDirectories = { L"C:\\Users\\ALICEE~1" };
    t.otherHostNames = { L"pcname-with-a-very-long-dns-name" };   // longer than 15 characters (B6)
    t.otherDomains = { L"CORP" };                          // NetBIOS domain (B6)
    return t;
}

// ---------------------------------------------------------------------------
// A5: only localhost, ::1 and a real 127.0.0.0/8 literal are this PC
// ---------------------------------------------------------------------------
TEST(Fix5_LoopbackGate)
{
    CHECK(IsLoopbackEndpoint(L"http://localhost:1234/v1/chat/completions"));
    CHECK(IsLoopbackEndpoint(L"http://LOCALHOST:1234/v1"));
    CHECK(IsLoopbackEndpoint(L"http://127.0.0.1:8080/v1"));
    CHECK(IsLoopbackEndpoint(L"http://127.255.255.254/v1"));
    CHECK(IsLoopbackEndpoint(L"http://127.0.0.0/v1"));
    CHECK(IsLoopbackEndpoint(L"http://[::1]:1234/v1"));

    CHECK(!IsLoopbackEndpoint(L"http://127.attacker.example/v1"));
    CHECK(!IsLoopbackEndpoint(L"https://127.0.0.1.attacker.example/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://127.1/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://0127.0.0.1/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://127.00.0.1/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://127.0.0.256/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://128.0.0.1/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://10.0.0.1/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://localhost.example.com/v1"));
    CHECK(!IsLoopbackEndpoint(L"http://mylocalhost/v1"));
    CHECK(!IsLoopbackEndpoint(L"not a url"));

    CHECK(IsLoopbackIPv4Literal(L"127.0.0.1"));
    CHECK(IsLoopbackIPv4Literal(L"127.10.20.30"));
    CHECK(!IsLoopbackIPv4Literal(L"127.0.0"));
    CHECK(!IsLoopbackIPv4Literal(L"127.0.0.1."));
    CHECK(!IsLoopbackIPv4Literal(L"127..0.1"));
    CHECK(!IsLoopbackIPv4Literal(L"127.0.0.1.5"));
    CHECK(!IsLoopbackIPv4Literal(L"127.0.0.+1"));
    CHECK(!IsLoopbackIPv4Literal(L"127.0.0.1000"));
    CHECK(!IsLoopbackIPv4Literal(L""));
}

// ---------------------------------------------------------------------------
// B4, B5, B6: word boundaries, short names, extra names, placeholders
// ---------------------------------------------------------------------------
TEST(Fix5_RedactWordRules)
{
    RedactionTerms t = FixedTerms();

    // B4: '-' and '_' end a word, so a name glued to a suffix is still hidden.
    CHECK_EQ(RedactText(L"D:\\PCNAME-backup\\x.exe", t), std::wstring(L"D:\\<host>-backup\\x.exe"));
    CHECK_EQ(RedactText(L"PCNAME_old", t), std::wstring(L"<host>_old"));
    CHECK_EQ(RedactText(L"xPCNAME stays", t), std::wstring(L"xPCNAME stays"));

    // B5: a two-letter user name is hidden in a path and as a word; "bob" is not "bo".
    CHECK_EQ(RedactText(L"C:\\Users\\bo\\Desktop\\a.exe", t), std::wstring(L"C:\\Users\\<user>\\Desktop\\a.exe"));
    CHECK_EQ(RedactText(L"signed in as bo today, bob stays", t), std::wstring(L"signed in as <user> today, bob stays"));

    // B6: NetBIOS domain, other local accounts, long DNS host name, full names, 8.3 path.
    CHECK_EQ(RedactText(L"CORP\\bo", t), std::wstring(L"<domain>\\<user>"));
    CHECK_EQ(RedactText(L"lucas: disabled", t), std::wstring(L"<user>: disabled"));
    CHECK_EQ(RedactText(L"host pcname-with-a-very-long-dns-name.corp.example", t), std::wstring(L"host <host>.<domain>"));
    CHECK_EQ(RedactText(L"Owner: Alice Example", t), std::wstring(L"Owner: <user>"));    // longest name first
    CHECK_EQ(RedactText(L"C:\\Users\\ALICEE~1\\AppData\\x", t), std::wstring(L"C:\\Users\\<user>\\AppData\\x"));
    CHECK_EQ(RedactText(L"malice stays", t), std::wstring(L"malice stays"));

    // Placeholders are never hit by a name like "user" or "host", and twice equals once.
    RedactionTerms odd;
    odd.userName = L"user";
    odd.profileDirectory = L"C:\\Users\\user";
    odd.computerName = L"host";
    odd.domain = L"domain";
    std::wstring once = RedactText(L"user on host in domain, C:\\Users\\user\\x", odd);
    CHECK_EQ(once, std::wstring(L"<user> on <host> in <domain>, C:\\Users\\<user>\\x"));
    CHECK_EQ(RedactText(once, odd), once);
    std::wstring sample = L"C:\\Users\\bo\\PCNAME-x on CORP";
    CHECK_EQ(RedactText(RedactText(sample, t), t), RedactText(sample, t));

    // The old behaviour kept for the existing helpers.
    CHECK_EQ(ReplaceWholeWordI(L"Bob bob bobby", L"bob", L"X"), std::wstring(L"X X bobby"));
    CHECK_EQ(ReplaceWholeWordI(L"ba-a-a", L"a-a", L"X"), std::wstring(L"ba-X"));   // match inside a skipped one
}

// The terms read from this PC include the user and the computer, and never the
// built-in account names that audit text needs.
TEST(Fix5_CurrentTermsAreComplete)
{
    RedactionTerms t = CurrentRedactionTerms();
    CHECK(!t.userName.empty());
    CHECK(!t.computerName.empty());
    CHECK(t.profileDirectory.size() > 3);
    for (const std::wstring& n : t.otherUserNames) {
        CHECK(!EqualsI(n, L"Administrator"));
        CHECK(!EqualsI(n, L"Guest"));
        CHECK(!EqualsI(n, L"DefaultAccount"));
        CHECK(!EqualsI(n, L"WDAGUtilityAccount"));
        CHECK(!EqualsI(n, t.userName));
    }
    for (const std::wstring& d : t.otherDomains) CHECK(!EqualsI(d, L"WORKGROUP"));
    // Every local account that is not a built-in default is on the list.
    for (const LocalAccountName& a : GetLocalAccountNames()) {
        bool builtIn = (a.rid == 500 || a.rid == 501 || a.rid == 503 || a.rid == 504);
        if (builtIn) continue;
        bool listed = EqualsI(a.name, t.userName);
        for (const std::wstring& n : t.otherUserNames) listed = listed || EqualsI(n, a.name);
        if (!listed) tf::Fail(__FILE__, __LINE__, "local account not in the redaction terms: " + tf::Narrow(a.name));
    }
    CHECK_EQ(&CachedRedactionTerms(), &CachedRedactionTerms());
}

// ---------------------------------------------------------------------------
// B3: every text field of a row
// ---------------------------------------------------------------------------
TEST(Fix5_RedactScanRowEveryField)
{
    RedactionTerms t = FixedTerms();
    ScanRow row;
    BaselineEntry& e = row.entry;
    e.path = L"C:\\Users\\bo\\Downloads\\PCNAME-tool.exe";
    e.signature = L"Valid (lucas)";
    e.signatureType = L"Embedded by PCNAME";
    e.issuer = L"CN=lucas";
    e.rootCA = L"CN=PCNAME Root";
    e.version = L"1.0 built by lucas";
    e.developer = L"Alice Example";
    e.permissions = L"CORP\\bo: Full";
    e.packingStatus = L"PACKED [lucas]";
    e.sigWarnings = L"SELF_SIGNED: by PCNAME";
    e.packIndicators = L"UPX from lucas";
    e.catalogSigner = L"PCNAME";
    e.revocation = L"Unknown on PCNAME";
    e.zoneHostUrl = L"https://files.corp.example/lucas/tool.exe";
    e.zoneReferrerUrl = L"https://intranet.corp.example/~bo/";
    e.altStreams = L"lucas.txt (12)";
    e.originWarnings = L"MOTW_INTERNET: from corp.example";
    e.peAnomalies = L"PDB_USER_PATH: C:\\Users\\bo\\src";
    e.pdbPath = L"C:\\Users\\bo\\src\\tool.pdb";
    e.scriptIndicators = L"DOWNLOAD: \\\\PCNAME\\share";
    e.md5 = L"0123456789abcdef0123456789abcdef";
    e.sha256 = std::wstring(64, L'b');
    e.imphash = L"aaaabbbbccccddddeeeeffff00001111";
    e.ssdeep = L"3:bo:bo";
    e.thumbprint = L"ABCDEF";
    e.attackIds = L"T1027";
    row.status = L"NEW";
    row.changeDetails = L"Signer changed from lucas to PCNAME";

    const ScanRow r = RedactScanRow(row, t);
    const BaselineEntry& x = r.entry;
    for (const std::wstring* f : { &x.path, &x.signature, &x.signatureType, &x.issuer, &x.rootCA, &x.version,
                                   &x.developer, &x.permissions, &x.packingStatus, &x.sigWarnings, &x.packIndicators,
                                   &x.catalogSigner, &x.revocation, &x.zoneHostUrl, &x.zoneReferrerUrl, &x.altStreams,
                                   &x.originWarnings, &x.peAnomalies, &x.pdbPath, &x.scriptIndicators, &r.changeDetails }) {
        bool leak = HasWholeWord(*f, L"lucas") || HasWholeWord(*f, L"PCNAME") || HasWholeWord(*f, L"bo") ||
                    HasWholeWord(*f, L"corp") || HasWholeWord(*f, L"Alice");
        if (leak) tf::Fail(__FILE__, __LINE__, "name left in a row field: " + tf::Narrow(*f));
    }
    // Hashes and fixed fields are untouched.
    CHECK_EQ(x.md5, e.md5);
    CHECK_EQ(x.sha256, e.sha256);
    CHECK_EQ(x.imphash, e.imphash);
    CHECK_EQ(x.ssdeep, e.ssdeep);
    CHECK_EQ(x.thumbprint, e.thumbprint);
    CHECK_EQ(x.attackIds, e.attackIds);
    CHECK_EQ(r.status, row.status);
    CHECK_EQ(x.path, std::wstring(L"C:\\Users\\<user>\\Downloads\\<host>-tool.exe"));
}

// ---------------------------------------------------------------------------
// B1, B2, B3 with this PC's own names: every output format
// ---------------------------------------------------------------------------
static ReportData ReportWithOwnNames(const RedactionTerms& t)
{
    ReportData d;
    FillReportHost(d, true);
    d.hasAudit = true;
    SecurityCheckResult r;
    r.id = L"acct.local";
    r.name = L"Local accounts";
    r.status = CHECK_WARNING;
    r.detail = L"Administrators group: " + t.computerName + L"\\" + t.userName + L"\n  " + t.userName + L": enabled";
    if (!t.otherUserNames.empty()) r.detail += L"\n  " + t.otherUserNames.front() + L": disabled";
    d.audit.push_back(r);
    d.score = ComputeHardeningScore(d.audit);

    d.hasScan = true;
    d.scanTitle = L"Full Scan of " + t.profileDirectory + L"\\Downloads";
    d.scan.root = t.profileDirectory + L"\\Downloads";
    ScanRow row;
    row.entry.path = t.profileDirectory + L"\\Downloads\\" + t.userName + L".exe";
    row.entry.developer = t.userName;
    row.entry.signature = L"Valid (" + t.computerName + L")";
    row.entry.issuer = L"CN=" + t.computerName + L"-CA";
    row.entry.zoneHostUrl = L"https://example.com/" + t.userName + L"/x.exe";
    row.entry.originWarnings = L"MOTW_INTERNET: saved by " + t.userName;
    row.entry.scriptIndicators = L"REMOTE_PATH: \\\\" + t.computerName + L"\\share";
    row.entry.peAnomalies = L"PDB_USER_PATH: " + t.profileDirectory + L"\\src";
    row.entry.packIndicators = L"built on " + t.computerName;
    row.entry.attackIds = L"T1027, T1204.002";
    row.entry.malwareScore = 7.5;
    row.status = L"NEW";
    d.rows.push_back(row);
    return d;
}

static void CheckNoOwnNames(const std::wstring& text, const RedactionTerms& t, const char* what)
{
    if (ContainsI(text, t.profileDirectory)) tf::Fail(__FILE__, __LINE__, std::string(what) + ": profile folder left");
    // A name shorter than 4 letters may also be an ordinary word in the fixed help text.
    if (t.userName.size() >= 4 && HasWholeWord(text, t.userName)) tf::Fail(__FILE__, __LINE__, std::string(what) + ": user name left");
    if (t.computerName.size() >= 4 && HasWholeWord(text, t.computerName)) tf::Fail(__FILE__, __LINE__, std::string(what) + ": computer name left");
}

TEST(Fix5_ReportsHideOwnNames)
{
    const RedactionTerms& t = CachedRedactionTerms();
    REQUIRE(t.profileDirectory.size() > 3);
    REQUIRE(!t.userName.empty());
    ReportData d = ReportWithOwnNames(t);

    std::wstring json = BuildJsonReport(d);
    std::wstring html = BuildHtmlReport(d);
    std::wstring nav = BuildNavigatorReport(d);    // B2: built from the redacted rows
    CheckNoOwnNames(json, t, "JSON");
    CheckNoOwnNames(html, t, "HTML");
    CheckNoOwnNames(nav, t, "Navigator");
    CHECK(nav.find(L"<user>.exe") != std::wstring::npos);
    CHECK(JsonCheck(json).Valid());
    CHECK(JsonCheck(nav).Valid());

    // The structured copy: every field, including the other account name.
    ReportData r = RedactReport(d);
    CHECK_EQ(r.hostName, std::wstring(L"<host>"));
    CHECK_EQ(r.userName, std::wstring(L"<user>"));
    if (!t.otherUserNames.empty()) CHECK(!HasWholeWord(r.audit[0].detail, t.otherUserNames.front()));
    CHECK(!HasWholeWord(r.rows[0].entry.developer, t.userName));
    CHECK(!HasWholeWord(r.rows[0].entry.zoneHostUrl, t.userName));
    CHECK(!HasWholeWord(r.rows[0].entry.signature, t.computerName));
    CHECK(!HasWholeWord(r.rows[0].entry.issuer, t.computerName));

    // B1: the CSV and text helpers.
    std::wstring csvPath = tf::TestDir() + L"rows.csv";
    REQUIRE(ExportRowsToCsv(csvPath, RedactRows(d.rows)));
    CheckNoOwnNames(ReadAll(csvPath), t, "CSV");
    std::wstring txtPath = tf::TestDir() + L"audit.txt";
    REQUIRE(WriteSecurityReport(txtPath, RedactAuditResults(d.audit)));
    CheckNoOwnNames(ReadAll(txtPath), t, "text report");
}

// The scan's own CSV follows ScanOptions::redactCsv (the CLI --redact and the GUI's
// hide-names setting). The test folder lives under the user's profile.
TEST(Fix5_ScanCsvRedaction)
{
    const RedactionTerms& t = CachedRedactionTerms();
    std::wstring root = tf::TestDir() + L"tree";
    REQUIRE(EnsureDirectory(root));
    std::wstring exe = root + L"\\" + t.userName + L"-tool.exe";
    REQUIRE(CopyFileW(L"C:\\Windows\\System32\\whoami.exe", exe.c_str(), FALSE));

    ScanOptions plain;
    plain.revocation = RevocationMode::Off;
    plain.computeFuzzyHash = false;
    ScanOptions hidden = plain;
    hidden.redactCsv = true;

    std::wstring csvPlain = tf::TestDir() + L"plain.csv";
    std::wstring csvHidden = tf::TestDir() + L"hidden.csv";
    std::vector<ScanRow> rowsSeen;
    ScanCallbacks cb;
    cb.onRow = [&](const ScanRow& r) { rowsSeen.push_back(r); };
    RunScan(ScanMode::Baseline, root, csvPlain, nullptr, tf::TestDir() + L"p.prbl", plain, cb);
    RunScan(ScanMode::Baseline, root, csvHidden, nullptr, tf::TestDir() + L"h.prbl", hidden, cb);

    std::wstring a = ReadAll(csvPlain);
    std::wstring b = ReadAll(csvHidden);
    CHECK(ContainsI(a, t.profileDirectory));          // the plain CSV is unchanged
    CheckNoOwnNames(b, t, "scan CSV");
    CHECK(b.find(L"<user>-tool.exe") != std::wstring::npos);
    // The rows handed to the program keep the real path (it still opens the file).
    REQUIRE(rowsSeen.size() == 2);
    CHECK(ContainsI(rowsSeen[1].entry.path, t.profileDirectory));
}

// ---------------------------------------------------------------------------
// E1, E2: argument parsing
// ---------------------------------------------------------------------------
TEST(Fix5_CliArguments)
{
    // E1: an option is never taken as the previous option's value.
    CliOptions a = ParseCliArguments({ L"--findings-md", L"--audit" });
    CHECK(!a.error.empty());
    CHECK(a.findingsMdPath.empty());
    CHECK(!ParseCliArguments({ L"--report", L"-h", L"--audit" }).error.empty());
    CHECK(!ParseCliArguments({ L"--diff", L"old.prbl", L"--json", L"x.json" }).error.empty());
    CHECK(!ParseCliArguments({ L"--baseline", L"--fast" }).error.empty());

    // E2: an empty value, or options with nothing to do, are errors (exit 2), not help.
    CHECK(!ParseCliArguments({ L"--full", L"" }).error.empty());
    CHECK(!ParseCliArguments({ L"--full", L"   " }).error.empty());
    CHECK(!ParseCliArguments({ L"--text", L"x.txt" }).error.empty());
    CHECK(!ParseCliArguments({ L"--redact" }).error.empty());
    CHECK(!ParseCliArguments({ L"--quiet", L"--notify" }).error.empty());
    CHECK(!ParseCliArguments({ L"--fast", L"--text", L"x.txt" }).error.empty());       // --text needs --audit
    CHECK(!ParseCliArguments({ L"--audit", L"--csv", L"x.csv" }).error.empty());       // --csv needs a scan
    CHECK(!ParseCliArguments({ L"--make-samples", L"d", L"--report", L"r.html" }).error.empty());

    // Still fine.
    CHECK(ParseCliArguments({}).help);
    CHECK(ParseCliArguments({ L"--help", L"--redact" }).help);
    CHECK(ParseCliArguments({ L"--audit", L"--text", L"x.txt" }).error.empty());
    CHECK(ParseCliArguments({ L"--fast", L"--csv", L"x.csv", L"--report", L"r.html" }).error.empty());
    CHECK(ParseCliArguments({ L"--audit", L"--json", L"j.json", L"--redact" }).error.empty());
    CHECK(ParseCliArguments({ L"--full", L"C:\\-odd-folder" }).error.empty());          // one leading '-' is a value

    std::wstring captured;
    CliEnvironment env;
    env.out = [&](const std::wstring& s) { captured += s; };
    CHECK_EQ(RunCli(ParseCliArguments({ L"--text", L"x.txt" }), env), 2);
    CHECK(captured.find(L"Error:") != std::wstring::npos);
    captured.clear();
    CHECK_EQ(RunCli(ParseCliArguments({ L"--findings-md", L"--audit" }), env), 2);
    CHECK(!FileExists(L"--audit"));
}

// ---------------------------------------------------------------------------
// E3, E5: a failed scan keeps the audit reports and still notifies
// ---------------------------------------------------------------------------
TEST(Fix5_ScanErrorKeepsAuditAndNotifies)
{
    std::wstring json = tf::TestDir() + L"audit.json";
    std::wstring html = tf::TestDir() + L"audit.html";
    std::wstring notifyTitle, notifyText;
    int notifications = 0;
    CliEnvironment env;
    env.out = [](const std::wstring&) {};
    env.notify = [&](const std::wstring& title, const std::wstring& text) { notifyTitle = title; notifyText = text; ++notifications; };
    env.defaultBaselinePath = tf::TestDir() + L"no-baseline.prbl";
    env.defaultReportsDir = tf::TestDir() + L"reports";

    int code = RunCli(ParseCliArguments({ L"--audit", L"--full", tf::TestDir() + L"no-such-folder", L"--json", json,
                                          L"--report", html, L"--notify", L"--quiet" }), env);
    CHECK_EQ(code, 2);
    REQUIRE(FileExists(json));
    CHECK(FileExists(html));
    std::wstring text = ReadAll(json);
    CHECK(text.find(L"\"findings\"") != std::wstring::npos);
    CHECK(text.find(L"\"hardeningScore\"") != std::wstring::npos);
    CHECK_EQ(notifications, 1);
    CHECK(notifyTitle.find(L"failed") != std::wstring::npos);
    CHECK(notifyText.find(L"baseline") != std::wstring::npos);
}

TEST(Fix5_FailedRunsNotify)
{
    std::wstring notifyTitle;
    int notifications = 0;
    CliEnvironment env;
    env.out = [](const std::wstring&) {};
    env.notify = [&](const std::wstring& title, const std::wstring&) { notifyTitle = title; ++notifications; };
    env.defaultBaselinePath = tf::TestDir() + L"missing.prbl";
    env.defaultReportsDir = tf::TestDir() + L"reports";

    // The weekly task's own arguments with the baseline gone: exit 2 and a notification.
    CHECK_EQ(RunCli(ParseCliArguments({ L"--fast", L"--notify", L"--quiet" }), env), 2);
    CHECK_EQ(notifications, 1);
    CHECK(notifyTitle.find(L"failed") != std::wstring::npos);

    // A parse error with --notify also says so.
    notifications = 0;
    CHECK_EQ(RunCli(ParseCliArguments({ L"--fast", L"--notify", L"--bogus" }), env), 2);
    CHECK_EQ(notifications, 1);
}

// ---------------------------------------------------------------------------
// E5: no weekly task without a baseline (nothing is ever registered here)
// ---------------------------------------------------------------------------
TEST(Fix5_WeeklyTaskNeedsBaseline)
{
    bool before = IsWeeklyScanRegistered();
    std::wstring error;
    CHECK(!RegisterWeeklyScan(L"C:\\x\\PhantomReconCli.exe", tf::TestDir() + L"missing.prbl", tf::TestDir(), error));
    CHECK(error.find(L"baseline") != std::wstring::npos);

    // A file that is not a baseline is refused the same way.
    std::wstring junk = tf::TestDir() + L"junk.prbl";
    REQUIRE(WriteUtf8File(junk, L"not a baseline"));
    error.clear();
    CHECK(!RegisterWeeklyScan(L"C:\\x\\PhantomReconCli.exe", junk, tf::TestDir(), error));
    CHECK(error.find(L"baseline") != std::wstring::npos);

    std::wstring captured;
    CliEnvironment env;
    env.out = [&](const std::wstring& s) { captured += s; };
    env.exePathForSchedule = L"C:\\x\\PhantomReconCli.exe";
    env.defaultBaselinePath = tf::TestDir() + L"missing.prbl";
    env.defaultReportsDir = tf::TestDir() + L"reports";
    CHECK_EQ(RunCli(ParseCliArguments({ L"--schedule-weekly" }), env), 2);
    CHECK(captured.find(L"No task was created") != std::wstring::npos);
    CHECK_EQ(IsWeeklyScanRegistered(), before);
}

// ---------------------------------------------------------------------------
// E4: --diff fills the counts, the high-risk number and the mode name
// ---------------------------------------------------------------------------
static BaselineEntry DiffEntry(const std::wstring& path, double score)
{
    BaselineEntry e;
    e.path = path;
    e.fileSize = 100;
    e.md5 = L"0123456789abcdef0123456789abcdef";
    e.sha256 = std::wstring(64, L'a');
    e.signature = L"Unsigned";
    e.malwareScore = score;
    return e;
}

TEST(Fix5_DiffFillsSummary)
{
    Baseline older, newer;
    older.AddEntry(DiffEntry(L"C:\\T\\a.exe", 1.0));
    newer.AddEntry(DiffEntry(L"C:\\T\\a.exe", 1.0));
    newer.AddEntry(DiffEntry(L"C:\\T\\b.exe", 7.5));
    std::wstring oldPath = tf::TestDir() + L"old.prbl";
    std::wstring newPath = tf::TestDir() + L"new.prbl";
    REQUIRE(older.SaveToFile(oldPath));
    REQUIRE(newer.SaveToFile(newPath));

    std::wstring captured;
    CliEnvironment env;
    env.out = [&](const std::wstring& s) { captured += s; };
    std::wstring json = tf::TestDir() + L"diff.json";
    CHECK_EQ(RunCli(ParseCliArguments({ L"--diff", oldPath, newPath, L"--json", json }), env), 1);
    std::wstring text = ReadAll(json);
    CHECK(text.find(L"\"mode\": \"Baseline comparison\"") != std::wstring::npos);
    CHECK(text.find(L"\"executables\": 2") != std::wstring::npos);
    CHECK(text.find(L"\"filesProcessed\": 2") != std::wstring::npos);
    CHECK(text.find(L"\"highRisk\": 1") != std::wstring::npos);
    CHECK(text.find(L"\"new\": 1") != std::wstring::npos);
    CHECK(text.find(L"\"match\": 1") != std::wstring::npos);
    CHECK(captured.find(L"2 programs analysed") != std::wstring::npos);

    // Same file twice: nothing changed, but a file scoring 7 or more still needs attention.
    CHECK_EQ(RunCli(ParseCliArguments({ L"--diff", newPath, newPath, L"--quiet" }), env), 1);
    // And with nothing risky and nothing changed: 0.
    CHECK_EQ(RunCli(ParseCliArguments({ L"--diff", oldPath, oldPath, L"--quiet" }), env), 0);
}

// ---------------------------------------------------------------------------
// E7, I1, I2: answer parsing
// ---------------------------------------------------------------------------
TEST(Fix5_AiReplyParsing)
{
    std::string content, error;
    // Answer texts live outside the CHECK macros: stringizing a raw string with \u in it
    // is not valid C++.
    const std::string escapes = R"({"choices":[{"message":{"role":"assistant","content":"It\u2019s fine \ud83d\ude00 \"ok\"\n"}}]})";
    const std::string decoy = R"({"id":"x","choices":[{"index":0,"logprobs":{"content":"WRONG"},"message":{"content":"RIGHT"}}]})";
    const std::string errorObject = R"({"error":{"message":"model not loaded","content":"WRONG"}})";
    const std::string parts = R"({"choices":[{"message":{"content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}}]})";
    const std::string legacy = R"({"choices":[{"text":"legacy"}]})";
    const std::string nullContent = R"({"choices":[{"message":{"content":null}}]})";
    const std::string noChoices = R"({"choices":[]})";
    const std::string trailing = R"({"choices":[{"message":{"content":"x"}}]} trailing)";
    const std::string unterminated = R"({"choices":[{"message":{"content":"unterminated}}]})";
    const std::string deep = std::string(5000, '[') + std::string(5000, ']');
    const std::string mixed = R"({"n":-1.5e2,"s":"\u00e9\ud800x","t":true,"z":null,"a":[1,2]})";

    // \u escapes, including a surrogate pair, decode to UTF-8.
    CHECK(ExtractChatReply(escapes, content, error));
    CHECK_EQ(content, std::string("It\xE2\x80\x99s fine \xF0\x9F\x98\x80 \"ok\"\n"));

    // An earlier "content" key elsewhere is not the answer (I2).
    CHECK(ExtractChatReply(decoy, content, error));
    CHECK_EQ(content, std::string("RIGHT"));

    // An error object is reported, not shown as the answer.
    CHECK(!ExtractChatReply(errorObject, content, error));
    CHECK(error.find("model not loaded") != std::string::npos);
    CHECK(content.empty());

    // Content as text parts, and the older completions format.
    CHECK(ExtractChatReply(parts, content, error));
    CHECK_EQ(content, std::string("ab"));
    CHECK(ExtractChatReply(legacy, content, error));
    CHECK_EQ(content, std::string("legacy"));

    // Empty, null, missing, broken and hostile answers fail with a reason.
    CHECK(!ExtractChatReply(nullContent, content, error));
    CHECK(!error.empty());
    CHECK(!ExtractChatReply(noChoices, content, error));
    CHECK(!ExtractChatReply(trailing, content, error));
    CHECK(!ExtractChatReply(unterminated, content, error));
    CHECK(!ExtractChatReply("", content, error));
    CHECK(!ExtractChatReply(deep, content, error));
    CHECK(error.find("deeply") != std::string::npos);

    // The reader itself: escapes, numbers without the C locale, lone surrogate escape.
    JsonValue v;
    std::string why;
    REQUIRE(ParseJson(mixed, v, why));
    CHECK(v.Find("n") && std::fabs(v.Find("n")->number + 150.0) < 1e-9);
    CHECK(v.Find("s") && v.Find("s")->text == std::string("\xC3\xA9\xEF\xBF\xBDx"));
    CHECK(v.Find("t") && v.Find("t")->boolean);
    CHECK(v.Find("z") && v.Find("z")->IsNull());
    CHECK(v.Find("a") && v.Find("a")->items.size() == 2);
    CHECK(!ParseJson("01", v, why));
    CHECK(!ParseJson("[1,]", v, why));
    CHECK(!ParseJson("\"a\x01\"", v, why));
}

// ---------------------------------------------------------------------------
// E9: only finite numbers in the request
// ---------------------------------------------------------------------------
TEST(Fix5_AiRequestNumbersFinite)
{
    std::vector<LLMMessage> msgs = { { "user", "hi \"there\"\n" } };
    LLMConfig c;
    for (double t : { std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::infinity(),
                      -std::numeric_limits<double>::infinity() }) {
        c.temperature = t;
        std::string body = BuildChatRequestJson(c, msgs);
        JsonValue v;
        std::string why;
        if (!ParseJson(body, v, why)) tf::Fail(__FILE__, __LINE__, "request JSON invalid: " + why);
        CHECK(body.find("\"temperature\":0.300") != std::string::npos);
        CHECK(body.find("nan") == std::string::npos && body.find("inf") == std::string::npos);
    }
    c.temperature = 7.0;
    CHECK(BuildChatRequestJson(c, msgs).find("\"temperature\":2.000") != std::string::npos);
    c.temperature = -1.0;
    CHECK(BuildChatRequestJson(c, msgs).find("\"temperature\":0.000") != std::string::npos);
    c.temperature = 0.25;
    c.maxTokens = 0;
    std::string body = BuildChatRequestJson(c, msgs);
    CHECK(body.find("\"temperature\":0.250") != std::string::npos);
    CHECK(body.find("\"max_tokens\":2048") != std::string::npos);
    JsonValue v;
    std::string why;
    REQUIRE(ParseJson(body, v, why));
    const JsonValue* m = v.Find("messages");
    REQUIRE(m && m->At(0) && m->At(0)->Find("content"));
    CHECK_EQ(m->At(0)->Find("content")->text, std::string("hi \"there\"\n"));
}

// ---------------------------------------------------------------------------
// E8, I3: size cap and status before body, against a one-shot server on 127.0.0.1
// ---------------------------------------------------------------------------
namespace {
class OneShotServer {
public:
    explicit OneShotServer(std::string response) : m_response(std::move(response)) {}
    ~OneShotServer() { Stop(); }

    bool Start()
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        m_started = true;
        m_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_listener == INVALID_SOCKET) return false;
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(m_listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
        if (listen(m_listener, 1) != 0) return false;
        int len = sizeof(addr);
        if (getsockname(m_listener, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return false;
        m_port = ntohs(addr.sin_port);
        m_thread = std::thread([this]() { Serve(); });
        return true;
    }

    void Stop()
    {
        if (m_listener != INVALID_SOCKET) {
            closesocket(m_listener);
            m_listener = INVALID_SOCKET;
        }
        if (m_thread.joinable()) m_thread.join();
        if (m_started) {
            WSACleanup();
            m_started = false;
        }
    }

    int Port() const { return m_port; }
    size_t BytesSent() const { return m_sent; }

private:
    std::string        m_response;
    SOCKET             m_listener = INVALID_SOCKET;
    std::thread        m_thread;
    int                m_port = 0;
    bool               m_started = false;
    std::atomic<size_t> m_sent{ 0 };

    void Serve()
    {
        SOCKET c = accept(m_listener, nullptr, nullptr);
        if (c == INVALID_SOCKET) return;
        DWORD timeout = 5000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        // Read the request: headers, then Content-Length bytes of body.
        std::string req;
        char buf[4096];
        size_t need = std::string::npos;
        while (true) {
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<size_t>(n));
            size_t end = req.find("\r\n\r\n");
            if (end != std::string::npos && need == std::string::npos) {
                std::string lower = req.substr(0, end);
                for (char& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
                size_t cl = lower.find("content-length:");
                size_t length = cl == std::string::npos ? 0 : static_cast<size_t>(atoi(lower.c_str() + cl + 15));
                need = end + 4 + length;
            }
            if (need != std::string::npos && req.size() >= need) break;
        }
        size_t pos = 0;
        while (pos < m_response.size()) {
            int chunk = static_cast<int>((std::min)(m_response.size() - pos, static_cast<size_t>(64 * 1024)));
            int n = send(c, m_response.data() + pos, chunk, 0);
            if (n <= 0) break;
            pos += static_cast<size_t>(n);
            m_sent = pos;
        }
        shutdown(c, SD_SEND);
        closesocket(c);
    }
};

std::string HttpResponse(int status, const std::string& body)
{
    return "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Error") +
           "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

std::string AskServer(OneShotServer& server, LLMClient& client)
{
    LLMConfig cfg;
    cfg.endpoint = L"http://127.0.0.1:" + std::to_wstring(server.Port()) + L"/v1/chat/completions";
    cfg.redact = false;
    client.SetConfig(cfg);
    return client.SendChatCompletion({ { "user", "hello" } });
}
}   // namespace

TEST(Fix5_AiHttpLimits)
{
    // A normal answer with escapes comes through decoded.
    {
        OneShotServer server(HttpResponse(200, R"({"choices":[{"message":{"content":"caf\u00e9 \ud83d\ude00"}}]})"));
        REQUIRE(server.Start());
        LLMClient client;
        std::string reply = AskServer(server, client);
        server.Stop();
        CHECK_EQ(reply, std::string("caf\xC3\xA9 \xF0\x9F\x98\x80"));
    }
    // An answer over the cap is refused, and not read to the end.
    {
        std::string big = "{\"choices\":[{\"message\":{\"content\":\"" + std::string(kMaxAiReplyBytes + 1024 * 1024, 'a') + "\"}}]}";
        OneShotServer server(HttpResponse(200, big));
        REQUIRE(server.Start());
        LLMClient client;
        std::string reply = AskServer(server, client);
        server.Stop();
        CHECK(reply.empty());
        CHECK(client.GetLastError().find("larger than") != std::string::npos);
    }
    // An error status reads only the start of the body for the message.
    {
        OneShotServer server(HttpResponse(500, std::string(200000, 'x')));
        REQUIRE(server.Start());
        LLMClient client;
        std::string reply = AskServer(server, client);
        server.Stop();
        CHECK(reply.empty());
        std::string err = client.GetLastError();
        CHECK(err.rfind("HTTP 500: ", 0) == 0);
        CHECK(err.size() <= kMaxAiErrorBytes + 64);
    }
    // A 200 with an error object reports the server's message.
    {
        OneShotServer server(HttpResponse(200, R"({"error":{"message":"no model loaded"}})"));
        REQUIRE(server.Start());
        LLMClient client;
        std::string reply = AskServer(server, client);
        server.Stop();
        CHECK(reply.empty());
        CHECK(client.GetLastError().find("no model loaded") != std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// H: unpaired surrogates and the SplitIntoParts limit
// ---------------------------------------------------------------------------
TEST(Fix5_LoneSurrogatesInReports)
{
    CHECK_EQ(WideToUtf8(L"a\xD800" L"b"), std::string("a[U+D800]b"));
    CHECK_EQ(WideToUtf8(L"x\xDC01"), std::string("x[U+DC01]"));
    CHECK_EQ(WideToUtf8(L"\xD83D\xDE00"), std::string("\xF0\x9F\x98\x80"));       // a real pair is kept
    CHECK_EQ(WideToUtf8(L"\xDE00\xD83D"), std::string("[U+DE00][U+D83D]"));        // reversed: two lone halves
    CHECK(WideToUtf8(L"a\xD800" L"b") != WideToUtf8(L"a\xD801" L"b"));            // two names stay distinct
    std::wstring withNul(L"a\0b", 3);
    CHECK_EQ(WideToUtf8(withNul).size(), static_cast<size_t>(3));
    CHECK_EQ(Utf8ToWide(WideToUtf8(L"\x00e9\x4e2d\xD83D\xDE00")), std::wstring(L"\x00e9\x4e2d\xD83D\xDE00"));

    // JSON keeps the exact code unit as an escape, and the report stays valid JSON.
    CHECK_EQ(JsonWriter::Escape(L"x\xDC00y"), std::wstring(L"x\\udc00y"));
    CHECK_EQ(JsonWriter::Escape(L"\xD83D\xDE00"), std::wstring(L"\xD83D\xDE00"));
    ReportData d;
    FillReportHost(d, false);
    d.hasScan = true;
    ScanRow row;
    row.entry.path = L"C:\\odd\\name\xD800.exe";
    row.status = L"NEW";
    d.rows.push_back(row);
    std::wstring json = BuildJsonReport(d);
    CHECK(json.find(L"name\\ud800.exe") != std::wstring::npos);
    CHECK(JsonCheck(json).Valid());
    std::wstring path = tf::TestDir() + L"odd.html";
    REQUIRE(SaveReportFile(path, BuildHtmlReport(d)));
    CHECK(ReadAll(path).find(L"name[U+D800].exe") != std::wstring::npos);
}

TEST(Fix5_SplitIntoPartsLimit)
{
    // A line end exactly one past the limit used to make a part one character too long.
    std::wstring text = std::wstring(200, L'a') + L"\n" + std::wstring(150, L'b');
    std::vector<std::wstring> parts = SplitIntoParts(text, 200);
    std::wstring joined;
    for (const std::wstring& p : parts) {
        CHECK(p.size() <= 200);
        joined += p;
    }
    CHECK_EQ(joined, text);

    // Every limit and line length combination stays within the limit.
    for (size_t limit = 200; limit <= 260; limit += 7) {
        for (size_t lineLen = 1; lineLen <= 300; lineLen += 13) {
            std::wstring t;
            for (int i = 0; i < 20; ++i) t += std::wstring(lineLen, L'x') + L"\n";
            std::wstring j;
            for (const std::wstring& p : SplitIntoParts(t, limit)) {
                if (p.size() > limit) tf::Fail(__FILE__, __LINE__, "part over the limit");
                j += p;
            }
            CHECK(j == t);
        }
    }

    // A surrogate pair across the cut point is kept whole.
    std::wstring pairText = std::wstring(199, L'c') + L"\xD83D\xDE00" + std::wstring(100, L'd');
    std::vector<std::wstring> pp = SplitIntoParts(pairText, 200);
    REQUIRE(pp.size() >= 2);
    CHECK_EQ(pp[0].size(), static_cast<size_t>(199));
    CHECK(pp[1][0] == 0xD83D);
}
