// Biggest wins (BiggestWins.cpp): the fixes that raise the hardening score the most,
// their points, the tie order, and where they show (HTML, JSON, text, console).

#include "TestFramework.h"
#include "JsonCheck.h"

#include "../BiggestWins.h"
#include "../CheckCatalog.h"
#include "../FileIO.h"
#include "../HardeningScore.h"
#include "../Reports.h"
#include "../SecurityChecks.h"
#include "../TextUtils.h"

#include <set>
#include <string>
#include <vector>

namespace {

SecurityCheckResult With(const std::wstring& id, const wchar_t* status)
{
    SecurityCheckResult r = MakeCheckResult(id);
    r.id = id;
    r.status = status;
    r.detail = L"evidence";
    const CheckInfo* info = FindCheckInfo(id);
    r.name = info ? info->title : id;
    return r;
}

// Every catalog check with a status that cycles through FAIL, WARNING, PASS, N/A.
std::vector<SecurityCheckResult> MixedResults()
{
    const wchar_t* statuses[] = { CHECK_FAIL, CHECK_WARNING, CHECK_PASS, CHECK_FAIL, CHECK_NA, CHECK_WARNING, CHECK_PASS };
    std::vector<SecurityCheckResult> out;
    size_t i = 0;
    for (const CheckInfo& info : GetCheckCatalog()) out.push_back(With(info.id, statuses[i++ % 7]));
    return out;
}

double Gain(const SecurityCheckResult& r)
{
    const CheckInfo* info = FindCheckInfo(r.id);
    int w = info ? SeverityWeight(info->severity) : 0;
    return r.status == CHECK_FAIL ? w : w / 2.0;
}

size_t CatalogIndex(const std::wstring& id)
{
    const std::vector<CheckInfo>& c = GetCheckCatalog();
    for (size_t i = 0; i < c.size(); ++i) {
        if (c[i].id == id) return i;
    }
    return c.size();
}

// The first scored checks of a severity, in catalog order.
std::vector<std::wstring> ScoredIds(Severity severity, size_t count)
{
    std::vector<std::wstring> ids;
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (info.scored && info.severity == severity && ids.size() < count) ids.push_back(info.id);
    }
    return ids;
}

bool Contains(const std::wstring& text, const std::wstring& part)
{
    return text.find(part) != std::wstring::npos;
}

} // namespace

TEST(BiggestWins_PointsAddUpToTheRealScore)
{
    std::vector<SecurityCheckResult> results = MixedResults();
    BiggestWinsResult wins = ComputeBiggestWins(results);
    REQUIRE(wins.wins.size() == 5);
    CHECK_EQ(wins.scoreBefore, ComputeHardeningScore(results).score);

    // Flip exactly those checks to PASS in a copy: the real score is scoreAfter, and the
    // points add up to the difference.
    std::vector<SecurityCheckResult> fixed = results;
    int sum = 0;
    for (const ScoreWin& w : wins.wins) {
        sum += w.points;
        CHECK(w.points >= 0);
        bool flipped = false;
        for (SecurityCheckResult& r : fixed) {
            if (r.id == w.id) {
                CHECK(r.status == CHECK_FAIL || r.status == CHECK_WARNING);
                CHECK_EQ(w.status, r.status);
                r.status = CHECK_PASS;
                flipped = true;
            }
        }
        CHECK(flipped);
    }
    CHECK_EQ(ComputeHardeningScore(fixed).score, wins.scoreAfter);
    CHECK_EQ(sum, wins.totalPoints);
    CHECK_EQ(wins.scoreAfter - wins.scoreBefore, wins.totalPoints);
    CHECK(wins.totalPoints > 0);

    // Each win's points are its exact share rounded down or up by one, and a bigger win
    // never shows fewer points than a smaller one below it.
    double possible = ComputeHardeningScore(results).possible;
    REQUIRE(possible > 0.0);
    for (size_t i = 0; i < wins.wins.size(); ++i) {
        double exact = 100.0 * wins.wins[i].weight / possible;
        CHECK(wins.wins[i].points >= static_cast<int>(exact));
        CHECK(wins.wins[i].points <= static_cast<int>(exact) + 1);
        if (i > 0) CHECK(wins.wins[i - 1].points >= wins.wins[i].points);
    }

    // Nothing left out does better: every other scored problem gains no more than the last win.
    double lastGain = wins.wins.back().weight;
    std::set<std::wstring> chosen;
    for (const ScoreWin& w : wins.wins) chosen.insert(w.id);
    for (const SecurityCheckResult& r : results) {
        const CheckInfo* info = FindCheckInfo(r.id);
        if (!info || !info->scored || chosen.count(r.id)) continue;
        if (r.status != CHECK_FAIL && r.status != CHECK_WARNING) continue;
        if (Gain(r) > lastGain) tf::Fail(__FILE__, __LINE__, "a bigger win was left out: " + tf::Narrow(r.id));
    }
    // Best first.
    for (size_t i = 1; i < wins.wins.size(); ++i) CHECK(wins.wins[i - 1].weight >= wins.wins[i].weight);

    // The whole list (no limit) still adds up, and ends at 100 when every scored problem is fixed.
    BiggestWinsResult all = ComputeBiggestWins(results, 1000);
    int total = 0;
    for (const ScoreWin& w : all.wins) total += w.points;
    CHECK_EQ(total, all.scoreAfter - all.scoreBefore);
    CHECK_EQ(all.scoreAfter, 100);
}

TEST(BiggestWins_UnscoredChecksNeverAppear)
{
    std::vector<SecurityCheckResult> results;
    size_t unscored = 0;
    for (const CheckInfo& info : GetCheckCatalog()) {
        results.push_back(With(info.id, CHECK_FAIL));
        if (!info.scored) ++unscored;
    }
    REQUIRE(unscored > 0);
    results.push_back(With(L"not.a.check", CHECK_FAIL));   // unknown ids count for nothing
    BiggestWinsResult all = ComputeBiggestWins(results, 1000);
    for (const ScoreWin& w : all.wins) {
        const CheckInfo* info = FindCheckInfo(w.id);
        REQUIRE(info != nullptr);
        if (!info->scored) tf::Fail(__FILE__, __LINE__, "an unscored check is a win: " + tf::Narrow(w.id));
        CHECK(SeverityWeight(info->severity) > 0);
    }
    // Only unscored problems: no wins at all.
    std::vector<SecurityCheckResult> eventsOnly;
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (!info.scored) eventsOnly.push_back(With(info.id, CHECK_WARNING));
    }
    CHECK(ComputeBiggestWins(eventsOnly).wins.empty());
    CHECK(BiggestWinsHeadline(ComputeBiggestWins(eventsOnly)).empty());
    CHECK(BiggestWinsText(ComputeBiggestWins(eventsOnly), L"\n").empty());
    // Every check passing: none either.
    std::vector<SecurityCheckResult> passing;
    for (const CheckInfo& info : GetCheckCatalog()) passing.push_back(With(info.id, CHECK_PASS));
    CHECK(ComputeBiggestWins(passing).wins.empty());
}

TEST(BiggestWins_TiesAreOrderedAsDocumented)
{
    // Same gain, same severity: catalog order, whatever the order of the results.
    std::vector<std::wstring> highs = ScoredIds(Severity::High, 3);
    REQUIRE(highs.size() == 3);
    std::vector<SecurityCheckResult> results = { With(highs[2], CHECK_FAIL), With(highs[0], CHECK_FAIL), With(highs[1], CHECK_FAIL) };
    BiggestWinsResult wins = ComputeBiggestWins(results);
    REQUIRE(wins.wins.size() == 3);
    for (size_t i = 0; i < 3; ++i) CHECK_EQ(wins.wins[i].id, highs[i]);
    CHECK(CatalogIndex(highs[0]) < CatalogIndex(highs[1]));

    // Same gain, different severity: a High WARNING (6 / 2 = 3) before a Medium FAIL (3).
    std::vector<std::wstring> mediums = ScoredIds(Severity::Medium, 1);
    REQUIRE(mediums.size() == 1);
    BiggestWinsResult tie = ComputeBiggestWins({ With(mediums[0], CHECK_FAIL), With(highs[0], CHECK_WARNING) });
    REQUIRE(tie.wins.size() == 2);
    CHECK_EQ(tie.wins[0].id, highs[0]);
    CHECK_EQ(tie.wins[0].weight, 3.0);
    CHECK_EQ(tie.wins[1].weight, 3.0);

    // A larger gain always comes first: a Critical FAIL before a High FAIL listed earlier.
    std::vector<std::wstring> criticals = ScoredIds(Severity::Critical, 1);
    REQUIRE(criticals.size() == 1);
    BiggestWinsResult order = ComputeBiggestWins({ With(highs[0], CHECK_FAIL), With(criticals[0], CHECK_FAIL) });
    REQUIRE(order.wins.size() == 2);
    CHECK_EQ(order.wins[0].id, criticals[0]);
    CHECK_EQ(BiggestWinRank(order, criticals[0]), 1);
    CHECK_EQ(BiggestWinRank(order, highs[0]), 2);
    CHECK_EQ(BiggestWinRank(order, L"not.a.check"), 0);

    // The limit.
    CHECK_EQ(ComputeBiggestWins(MixedResults(), 2).wins.size(), static_cast<size_t>(2));
    CHECK(ComputeBiggestWins(MixedResults(), 0).wins.empty());
}

TEST(BiggestWins_ShownInEveryReport)
{
    ReportData d;
    d.generatedAt = L"2026-10-27T01:00:00";
    d.hostName = L"DEMO-PC";
    d.osText = L"Windows";
    d.hasAudit = true;
    d.audit = MixedResults();
    d.score = ComputeHardeningScore(d.audit);
    BiggestWinsResult wins = ComputeBiggestWins(d.audit);
    REQUIRE(wins.wins.size() == 5);
    std::wstring headline = BiggestWinsHeadline(wins);
    CHECK_EQ(headline, L"Fix these 5 and the score goes from " + std::to_wstring(wins.scoreBefore) + L" to " +
                       std::to_wstring(wins.scoreAfter) + L".");

    // HTML: the box near the top, each win a link to its finding's anchor on the page.
    std::wstring html = BuildHtmlReport(d);
    size_t box = html.find(L"<section class=\"wins\">");
    REQUIRE(box != std::wstring::npos);
    CHECK(box < html.find(L"<article class=\"finding\""));
    CHECK(Contains(html, headline));
    for (const ScoreWin& w : wins.wins) {
        CHECK(Contains(html, L"<a href=\"#check-" + w.id + L"\" onclick=\"showFinding(this)\">"));
        CHECK(Contains(html, L"<article class=\"finding\" id=\"check-" + w.id + L"\""));
        CHECK(Contains(html, L"<b>+" + std::to_wstring(w.points) + L"</b>"));
    }
    CHECK(Contains(html, L"function showFinding(a)"));

    // JSON: biggestWins with id and points, in order, between the score and the findings.
    std::wstring json = BuildJsonReport(d);
    JsonCheck check(json);
    CHECK(check.Valid());
    CHECK_EQ(check.KeyCount(L"biggestWins"), 1);
    CHECK_EQ(check.KeyCount(L"points"), 5);
    size_t at = json.find(L"\"biggestWins\"");
    size_t findings = json.find(L"\"findings\"");
    REQUIRE(at != std::wstring::npos && findings != std::wstring::npos && at < findings);
    size_t pos = at;
    for (const ScoreWin& w : wins.wins) {
        size_t idAt = json.find(L"\"id\": \"" + w.id + L"\"", pos);
        CHECK(idAt != std::wstring::npos && idAt < findings);
        size_t pointsAt = json.find(L"\"points\": " + std::to_wstring(w.points), idAt);
        CHECK(pointsAt != std::wstring::npos && pointsAt < findings);
        if (idAt != std::wstring::npos) pos = idAt;
    }

    // Text report and console summary: the top 5 with points.
    std::wstring txtPath = tf::TestDir() + L"audit.txt";
    REQUIRE(WriteSecurityReport(txtPath, d.audit));
    std::wstring text;
    REQUIRE(ReadTextFile(txtPath, text, 4 * 1024 * 1024));
    std::wstring console = GetSecuritySummary(d.audit);
    for (const std::wstring* t : { &text, &console }) {
        CHECK(Contains(*t, L"Biggest wins (the fixes that raise the hardening score the most):"));
        CHECK(Contains(*t, headline));
        for (size_t i = 0; i < wins.wins.size(); ++i) {
            const ScoreWin& w = wins.wins[i];
            CHECK(Contains(*t, L"  " + std::to_wstring(i + 1) + L". +" + std::to_wstring(w.points) + L"  " + w.title + L" (" + w.id));
        }
    }
    CHECK(Contains(text, L"\r\n  1. +"));

    // Nothing to win: no box, an empty list.
    for (SecurityCheckResult& r : d.audit) r.status = CHECK_PASS;
    d.score = ComputeHardeningScore(d.audit);
    CHECK(!Contains(BuildHtmlReport(d), L"<section class=\"wins\">"));
    std::wstring emptyJson = BuildJsonReport(d);
    JsonCheck emptyCheck(emptyJson);
    CHECK(emptyCheck.Valid());
    CHECK_EQ(emptyCheck.KeyCount(L"biggestWins"), 1);
    CHECK_EQ(emptyCheck.KeyCount(L"points"), 0);
    CHECK(!Contains(GetSecuritySummary(d.audit), L"Biggest wins"));

    // One win: "this one".
    BiggestWinsResult one = ComputeBiggestWins({ With(ScoredIds(Severity::High, 1)[0], CHECK_FAIL) });
    CHECK(BiggestWinsHeadline(one).rfind(L"Fix this one and the score goes from 0 to 100.", 0) == 0);

    // A problem worth less than half a point near the top: the number does not move, and
    // the headline says so instead of "from 100 to 100".
    BiggestWinsResult flat = one;
    flat.scoreBefore = 100;
    flat.scoreAfter = 100;
    flat.totalPoints = 0;
    CHECK_EQ(BiggestWinsHeadline(flat),
             std::wstring(L"Fix this one to clear what is left. The score already rounds to 100, so the number will not change."));
}
