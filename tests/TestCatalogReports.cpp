// The check catalog, the hardening score, the audit run and the three report formats.

#include "TestFramework.h"
#include "JsonCheck.h"

#include "../AttackMapping.h"
#include "../CheckCatalog.h"
#include "../DetailText.h"
#include "../HardeningScore.h"
#include "../Redactor.h"
#include "../Reports.h"
#include "../SecurityChecks.h"
#include "../TextUtils.h"

#include <algorithm>
#include <cstdio>
#include <set>

static bool HasTypographicPunctuation(const std::wstring& s)
{
    for (wchar_t c : s) {
        if (c == 0x2013 || c == 0x2014 || c == 0x2018 || c == 0x2019 || c == 0x201C || c == 0x201D) return true;
    }
    return false;
}

TEST(Catalog_EveryCheckHasCodeAndText)
{
    const std::vector<CheckInfo>& catalog = GetCheckCatalog();
    const std::vector<RegisteredCheck>& checks = GetRegisteredChecks();
    REQUIRE(!catalog.empty());

    // Both directions: every catalog row runs, every registered check has catalog text.
    std::set<std::wstring> registered;
    for (const RegisteredCheck& c : checks) registered.insert(c.id);
    std::set<std::wstring> ids;
    for (const CheckInfo& info : catalog) {
        CHECK(ids.insert(info.id).second);   // ids are unique
        if (registered.find(info.id) == registered.end()) tf::Fail(__FILE__, __LINE__, "no check function for " + tf::Narrow(info.id));
    }
    for (const RegisteredCheck& c : checks) {
        if (!FindCheckInfo(c.id)) tf::Fail(__FILE__, __LINE__, "no catalog row for " + tf::Narrow(c.id));
    }
    CHECK_EQ(checks.size(), catalog.size());

    // The memory-reading check was removed on purpose and must not come back.
    CHECK(FindCheckInfo(L"proc.memory") == nullptr);

    const std::vector<std::wstring>& categories = GetCheckCategories();
    for (const CheckInfo& info : catalog) {
        std::string id = tf::Narrow(info.id);
        if (info.title.empty() || info.explanation.empty() || info.fix.empty() || info.undo.empty()) {
            tf::Fail(__FILE__, __LINE__, "missing text for " + id);
        }
        if (std::find(categories.begin(), categories.end(), info.category) == categories.end()) {
            tf::Fail(__FILE__, __LINE__, "unknown category for " + id);
        }
        for (const std::wstring* text : { &info.title, &info.explanation, &info.fix, &info.undo, &info.cisBenchmark }) {
            if (HasTypographicPunctuation(*text)) tf::Fail(__FILE__, __LINE__, "typographic dash or quote in " + id);
        }
        for (const std::wstring& t : info.attack) {
            if (AttackTechniqueName(t).empty()) tf::Fail(__FILE__, __LINE__, "unnamed ATT&CK id " + tf::Narrow(t) + " in " + id);
        }
        CHECK(SeverityWeight(info.severity) >= 0);
    }

    std::wstring md = BuildFindingsMarkdown();
    for (const CheckInfo& info : catalog) {
        if (md.find(info.id) == std::wstring::npos) tf::Fail(__FILE__, __LINE__, "FINDINGS.md lacks " + tf::Narrow(info.id));
    }
    CHECK(!HasTypographicPunctuation(md));
}

TEST(Attack_TechniqueTable)
{
    std::vector<std::wstring> known = KnownAttackTechniques();
    REQUIRE(known.size() > 20);
    for (const std::wstring& id : known) {
        CHECK(id.rfind(L"T1", 0) == 0);
        CHECK(!AttackTechniqueName(id).empty());
    }
    CHECK(AttackTechniqueName(L"T9999").empty());
    CHECK_EQ(IndicatorCode(L"TLS_CALLBACKS: 2 callback(s)"), std::wstring(L"TLS_CALLBACKS"));
    CHECK_EQ(IndicatorCode(L"  MOTW_INTERNET"), std::wstring(L"MOTW_INTERNET"));
    CHECK(!ExplainIndicator(L"TLS_CALLBACKS").empty());
    CHECK(ExplainIndicator(L"NOT_A_REAL_CODE").empty());

    std::vector<std::wstring> list = { L"T1055" };
    AddUniqueTechniques(list, { L"T1055", L"", L"T1027" });
    CHECK_EQ(list.size(), static_cast<size_t>(2));
}

static const CheckInfo* FirstWithSeverity(Severity sev, const std::wstring& skipId = L"")
{
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (info.severity == sev && info.id != skipId && SeverityWeight(sev) > 0) return &info;
    }
    return nullptr;
}

static SecurityCheckResult Result(const CheckInfo* info, const wchar_t* status)
{
    SecurityCheckResult r = MakeCheckResult(info->id);
    r.status = status;
    return r;
}

TEST(Score_Math)
{
    const CheckInfo* high1 = FirstWithSeverity(Severity::High);
    REQUIRE(high1 != nullptr);
    const CheckInfo* high2 = FirstWithSeverity(Severity::High, high1->id);
    REQUIRE(high2 != nullptr);
    const CheckInfo* low = FirstWithSeverity(Severity::Low);
    const CheckInfo* critical = FirstWithSeverity(Severity::Critical);

    CHECK_EQ(SeverityWeight(Severity::Critical), 10);
    CHECK_EQ(SeverityWeight(Severity::High), 6);
    CHECK_EQ(SeverityWeight(Severity::Medium), 3);
    CHECK_EQ(SeverityWeight(Severity::Low), 1);

    CHECK_EQ(ComputeHardeningScore({ Result(high1, CHECK_PASS), Result(high2, CHECK_PASS) }).score, 100);
    CHECK_EQ(ComputeHardeningScore({ Result(high1, CHECK_FAIL), Result(high2, CHECK_FAIL) }).score, 0);
    CHECK_EQ(ComputeHardeningScore({ Result(high1, CHECK_PASS), Result(high2, CHECK_FAIL) }).score, 50);
    CHECK_EQ(ComputeHardeningScore({ Result(high1, CHECK_PASS), Result(high2, CHECK_WARNING) }).score, 75);

    // INFO, N/A and ERROR do not move the score.
    HardeningScore s = ComputeHardeningScore({ Result(high1, CHECK_PASS), Result(high2, CHECK_FAIL),
                                               Result(high2, CHECK_INFO), Result(high1, CHECK_NA), Result(high1, CHECK_ERROR) });
    CHECK_EQ(s.score, 50);
    CHECK_EQ(s.counted, 2);
    CHECK_EQ(s.pass, 1);
    CHECK_EQ(s.fail, 1);
    CHECK_EQ(s.info, 1);
    CHECK_EQ(s.notApplicable, 1);
    CHECK_EQ(s.error, 1);

    if (low && critical) {
        // A critical pass outweighs a low fail: 10 / 11 = 91.
        CHECK_EQ(ComputeHardeningScore({ Result(critical, CHECK_PASS), Result(low, CHECK_FAIL) }).score, 91);
    }

    CHECK_EQ(ComputeHardeningScore({}).label, std::wstring(L"Not scored"));
    CHECK_EQ(HardeningLabel(95), std::wstring(L"Strong"));
    CHECK_EQ(HardeningLabel(80), std::wstring(L"Good"));
    CHECK_EQ(HardeningLabel(59), std::wstring(L"Fair"));
    CHECK_EQ(HardeningLabel(10), std::wstring(L"Weak"));
}

// Runs the real audit on this PC. It does not judge the results (every PC is
// different); it checks that every check returns a well-formed answer.
TEST(Audit_RunsEveryCheck)
{
    AuditContext context;
    context.snapshotPath = tf::TestDir() + L"persistence.snapshot";
    int lastDone = -1, lastTotal = -1;
    context.onProgress = [&](int done, int total, const std::wstring&) {
        CHECK(done >= lastDone);
        lastDone = done;
        lastTotal = total;
    };
    std::vector<SecurityCheckResult> results = RunAllSecurityChecks(context);
    CHECK_EQ(results.size(), GetRegisteredChecks().size());
    CHECK_EQ(lastDone, lastTotal);

    static const std::set<std::wstring> allowed = { CHECK_PASS, CHECK_FAIL, CHECK_WARNING, CHECK_INFO, CHECK_ERROR, CHECK_NA };
    int errors = 0;
    for (const SecurityCheckResult& r : results) {
        std::string id = tf::Narrow(r.id);
        if (!FindCheckInfo(r.id)) tf::Fail(__FILE__, __LINE__, "result with unknown id " + id);
        if (allowed.find(r.status) == allowed.end()) tf::Fail(__FILE__, __LINE__, "bad status for " + id + ": " + tf::Narrow(r.status));
        if (r.name.empty()) tf::Fail(__FILE__, __LINE__, "no name for " + id);
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, "no detail for " + id);
        if (r.detail.size() > 20200) tf::Fail(__FILE__, __LINE__, "detail too long for " + id + ": " + std::to_string(r.detail.size()));
        if (HasTypographicPunctuation(r.detail)) tf::Fail(__FILE__, __LINE__, "typographic punctuation in " + id);
        if (r.status == CHECK_ERROR) {
            ++errors;
            std::printf("    note: %s returned ERROR: %s\n", id.c_str(), tf::Narrow(r.detail).c_str());
        }
    }
    CHECK(errors <= 2);   // a check may fail on an unusual PC, but not most of them

    HardeningScore score = ComputeHardeningScore(results);
    CHECK(score.score >= 0 && score.score <= 100);
    CHECK(score.counted > 10);

    std::wstring path = tf::TestDir() + L"audit.txt";
    CHECK(WriteSecurityReport(path, results));

    // Cancelling stops early.
    AuditContext stop;
    stop.snapshotPath = context.snapshotPath;
    stop.isCancelled = []() { return true; };
    CHECK(RunAllSecurityChecks(stop).empty());
}

static ReportData SampleReport()
{
    ReportData d;
    FillReportHost(d, false);
    d.hasAudit = true;
    const CheckInfo& first = GetCheckCatalog().front();
    SecurityCheckResult r = MakeCheckResult(first.id);
    r.status = CHECK_FAIL;
    r.detail = L"Found <script>alert(1)</script> & \"quotes\" in C:\\Temp\\x.exe\nsecond line\ttab";
    d.audit.push_back(r);
    d.score = ComputeHardeningScore(d.audit);

    d.hasScan = true;
    d.scanTitle = L"Full Scan of C:\\Test <folder>";
    d.scan.mode = ScanMode::FullScan;
    d.scan.added = 1;
    ScanRow row;
    row.entry.path = L"C:\\Test <folder>\\a&b \"c\".exe";
    row.entry.sha256 = std::wstring(64, L'a');
    row.entry.malwareScore = 7.5;
    row.entry.attackIds = L"T1027, T1553.005";
    row.entry.developer = L"\x00c9diteur";
    row.status = L"NEW";
    d.rows.push_back(row);
    return d;
}

TEST(Reports_JsonIsValid)
{
    ReportData d = SampleReport();
    std::wstring json = BuildJsonReport(d);
    JsonCheck check(json);
    bool ok = check.Valid();
    if (!ok) tf::Fail(__FILE__, __LINE__, "JSON report invalid: " + tf::Narrow(check.error));
    CHECK(json.find(L"phantomrecon.report/1") != std::wstring::npos);
    CHECK(json.find(L"T1553.005") != std::wstring::npos);

    std::wstring nav = BuildNavigatorReport(d);
    JsonCheck navCheck(nav);
    bool navOk = navCheck.Valid();
    if (!navOk) tf::Fail(__FILE__, __LINE__, "Navigator layer invalid: " + tf::Narrow(navCheck.error));
    CHECK(nav.find(L"\"techniqueID\"") != std::wstring::npos);
    CHECK(nav.find(L"T1027") != std::wstring::npos);

    std::vector<TechniqueCount> techniques = CollectTechniques(d);
    bool found = false;
    for (const TechniqueCount& t : techniques) {
        if (t.id == L"T1553.005") found = t.count >= 1;
    }
    CHECK(found);

    std::wstring path = tf::TestDir() + L"r.json";
    REQUIRE(SaveReportFile(path, json));
}

TEST(Reports_HtmlEscapesEverything)
{
    ReportData d = SampleReport();
    std::wstring html = BuildHtmlReport(d);
    CHECK(html.find(L"<script>alert(1)</script>") == std::wstring::npos);
    CHECK(html.find(L"&lt;script&gt;alert(1)&lt;/script&gt;") != std::wstring::npos);
    CHECK(html.find(L"a&amp;b") != std::wstring::npos);
    CHECK(html.find(L"<!DOCTYPE html>") != std::wstring::npos || html.find(L"<!doctype html>") != std::wstring::npos);
    CHECK(!HasTypographicPunctuation(html));
    CHECK(html.find(L"http://") == std::wstring::npos || html.find(L"src=\"http") == std::wstring::npos);   // no external files
}

TEST(Reports_Redaction)
{
    // RedactReport uses this PC's own names, so the test builds the data from them.
    RedactionTerms terms = CurrentRedactionTerms();
    REQUIRE(terms.profileDirectory.size() > 3);
    ReportData d = SampleReport();
    d.rows[0].entry.path = terms.profileDirectory + L"\\Downloads\\tool.exe";
    d.audit[0].detail = L"Seen on " + terms.computerName + L" by " + terms.userName;
    ReportData r = RedactReport(d);
    CHECK(r.redacted);
    CHECK_EQ(r.rows.size(), d.rows.size());
    CHECK(r.rows[0].entry.path.find(L"<user>") != std::wstring::npos);
    CHECK(r.rows[0].entry.path.find(terms.profileDirectory) == std::wstring::npos);
    if (terms.computerName.size() >= 3) CHECK(r.audit[0].detail.find(L"<host>") != std::wstring::npos);
    if (terms.userName.size() >= 3) CHECK(!ContainsI(r.audit[0].detail, L" by " + terms.userName));
    std::wstring json = BuildJsonReport(r);
    CHECK(json.find(terms.profileDirectory) == std::wstring::npos);

    // The text helpers on fixed names.
    RedactionTerms fixed;
    fixed.userName = L"alice";
    fixed.profileDirectory = L"C:\\Users\\alice";
    fixed.computerName = L"DESKTOP-42";
    fixed.domain = L"corp.example";
    std::wstring out = RedactText(L"C:\\Users\\alice\\x.exe on DESKTOP-42 in corp.example, malice stays", fixed);
    CHECK_EQ(out, std::wstring(L"C:\\Users\\<user>\\x.exe on <host> in <domain>, malice stays"));
    CHECK_EQ(ReplaceWholeWordI(L"Bob bob bobby", L"bob", L"X"), std::wstring(L"X X bobby"));

    std::wstring longText;
    for (int i = 0; i < 100; ++i) longText += L"line number " + std::to_wstring(i) + L" with some words\n";
    std::vector<std::wstring> parts = SplitIntoParts(longText, 500);
    CHECK(parts.size() > 1);
    std::wstring joined;
    for (const std::wstring& p : parts) {
        CHECK(p.size() <= 500);
        joined += p;
    }
    CHECK_EQ(joined, longText);
    CHECK(parts[0].back() == L'\n');   // cuts at line ends
}

TEST(DetailText_RowAndFinding)
{
    ScanRow row;
    row.entry.path = L"C:\\x\\odd.exe";
    row.entry.malwareScore = 6.5;
    row.entry.sha256 = std::wstring(64, L'b');
    row.entry.peTimestamp = 0x65000000;
    row.entry.totalImports = 3;
    row.entry.peAnomalies = L"TLS_CALLBACKS: 1 callback(s) run before the entry point; CHECKSUM_MISMATCH: Header says 0x1, file is 0x2";
    row.entry.originWarnings = L"MOTW_INTERNET: Downloaded from the internet";
    row.entry.zoneId = 3;
    row.entry.attackIds = L"T1027";
    row.entry.sigWarnings = L"plain sentence without a code";
    row.status = L"NEW";

    std::vector<std::wstring> codes = RowIndicatorCodes(row);
    CHECK_EQ(codes.size(), static_cast<size_t>(3));
    CHECK(std::find(codes.begin(), codes.end(), L"TLS_CALLBACKS") != codes.end());
    CHECK(std::find(codes.begin(), codes.end(), L"MOTW_INTERNET") != codes.end());

    std::wstring text = BuildRowDetailText(row);
    CHECK(text.find(L"odd.exe") != std::wstring::npos);
    CHECK(text.find(L"6.5 out of 10") != std::wstring::npos);
    CHECK(text.find(AttackTechniqueName(L"T1027")) != std::wstring::npos);
    CHECK(text.find(ExplainIndicator(L"TLS_CALLBACKS")) != std::wstring::npos);
    CHECK(!HasTypographicPunctuation(text));

    std::wstring crlf = ToWindowsLineEnds(L"a\nb\r\nc");
    CHECK_EQ(crlf, std::wstring(L"a\r\nb\r\nc"));

    // Time left: nothing until there is enough to judge, then rounded steps.
    CHECK_EQ(TimeLeftText(10, 100, 1000, 9000), std::wstring(L""));          // fewer than 20 files
    CHECK_EQ(TimeLeftText(50, 100, 1000, 2000), std::wstring(L""));          // under 3 seconds
    CHECK_EQ(TimeLeftText(100, 100, 1000, 9000), std::wstring(L""));         // done
    CHECK_EQ(TimeLeftText(50, 100, 0, 9000), std::wstring(L""));             // no start time
    CHECK_EQ(TimeLeftText(50, 100, 1000, 21000), std::wstring(L"About 20 seconds left"));
    CHECK_EQ(TimeLeftText(50, 100, 1000, 4000), std::wstring(L"About 5 seconds left"));
    CHECK_EQ(TimeLeftText(20, 100, 1000, 61000), std::wstring(L"About 4 minutes left"));
    CHECK_EQ(TimeLeftText(20, 1000, 1000, 61000), std::wstring(L"About 49 minutes left"));   // 2,940 s
    CHECK_EQ(TimeLeftText(20, 10000, 1000, 61000), std::wstring(L"About 8 hours left"));

    const CheckInfo& info = GetCheckCatalog().front();
    std::wstring notRun = BuildFindingDetailText(info, nullptr);
    CHECK(notRun.find(L"not run yet") != std::wstring::npos);
    CHECK(notRun.find(info.fix) != std::wstring::npos);
    CHECK(notRun.find(info.undo) != std::wstring::npos);

    SecurityCheckResult fail = MakeCheckResult(info.id);
    fail.status = CHECK_FAIL;
    fail.detail = L"evidence line";
    SecurityCheckResult pass = MakeCheckResult(GetCheckCatalog().back().id);
    pass.status = CHECK_PASS;
    std::wstring audit = BuildAuditFindingsText({ pass, fail });
    CHECK(audit.find(L"[FAIL]") != std::wstring::npos);
    CHECK(audit.find(L"evidence line") != std::wstring::npos);
    CHECK(audit.find(L"[PASS]") == std::wstring::npos);

    fail.detail = std::wstring(9000, L'x');
    std::wstring shortened = BuildAuditFindingsText({ fail });
    CHECK(shortened.size() < 4000 + info.explanation.size());
    CHECK(shortened.find(L"evidence shortened") != std::wstring::npos);
}
