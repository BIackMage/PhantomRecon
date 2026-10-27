#include "pch.h"
#include "BiggestWins.h"

#include "HardeningScore.h"

#include <windows.h>
#include <algorithm>
#include <cmath>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[BiggestWins] " + msg + L"\n").c_str());
}

namespace {

struct Candidate {
    size_t       resultIndex;
    size_t       catalogIndex;
    const CheckInfo* info;
    double       gain;
};

size_t CatalogIndexOf(const std::wstring& id)
{
    const std::vector<CheckInfo>& catalog = GetCheckCatalog();
    for (size_t i = 0; i < catalog.size(); ++i) {
        if (catalog[i].id == id) return i;
    }
    return catalog.size();
}

} // namespace

BiggestWinsResult ComputeBiggestWins(const std::vector<SecurityCheckResult>& results, size_t limit)
{
    BiggestWinsResult out;
    out.scoreBefore = ComputeHardeningScore(results).score;
    out.scoreAfter = out.scoreBefore;

    std::vector<Candidate> candidates;
    for (size_t i = 0; i < results.size(); ++i) {
        const SecurityCheckResult& r = results[i];
        if (r.status != CHECK_FAIL && r.status != CHECK_WARNING) continue;
        const CheckInfo* info = FindCheckInfo(r.id);
        if (!info || !info->scored) continue;
        int weight = SeverityWeight(info->severity);
        if (weight <= 0) continue;
        double gain = r.status == CHECK_FAIL ? weight : weight / 2.0;
        candidates.push_back({ i, CatalogIndexOf(r.id), info, gain });
    }
    std::stable_sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        if (a.gain != b.gain) return a.gain > b.gain;
        if (a.info->severity != b.info->severity) return static_cast<int>(a.info->severity) > static_cast<int>(b.info->severity);
        return a.catalogIndex < b.catalogIndex;
    });
    if (candidates.size() > limit) candidates.resize(limit);

    // The real score with every listed win turned to PASS.
    std::vector<SecurityCheckResult> fixed = results;
    for (const Candidate& c : candidates) fixed[c.resultIndex].status = CHECK_PASS;
    out.scoreAfter = ComputeHardeningScore(fixed).score;
    out.totalPoints = out.scoreAfter - out.scoreBefore;

    // Split the total by largest remainder: each win gets the whole points of its exact
    // share (100 * gain / possible weight), and the points left over go to the largest
    // fractions, the better rank first on a tie. The total is the rounded difference of
    // two scores, so the left-over is between 0 and the number of wins.
    double possible = ComputeHardeningScore(results).possible;
    std::vector<double> exact;
    int floors = 0;
    for (const Candidate& c : candidates) {
        double e = possible > 0.0 ? 100.0 * c.gain / possible : 0.0;
        exact.push_back(e);
        ScoreWin win;
        win.id = c.info->id;
        win.title = c.info->title;
        win.status = results[c.resultIndex].status;
        win.severity = c.info->severity;
        win.weight = c.gain;
        win.points = static_cast<int>(std::floor(e));
        floors += win.points;
        out.wins.push_back(win);
    }
    std::vector<size_t> byFraction;
    for (size_t i = 0; i < exact.size(); ++i) byFraction.push_back(i);
    std::stable_sort(byFraction.begin(), byFraction.end(), [&](size_t a, size_t b) {
        return exact[a] - std::floor(exact[a]) > exact[b] - std::floor(exact[b]);
    });
    int left = out.totalPoints - floors;
    for (size_t i = 0; i < byFraction.size() && left > 0; ++i, --left) out.wins[byFraction[i]].points++;
    if (left != 0) DebugLog(L"Unexpected left-over points: " + std::to_wstring(left));
    DebugLog(L"Biggest wins: " + std::to_wstring(out.wins.size()) + L" of " + std::to_wstring(results.size()) +
             L" results, score " + std::to_wstring(out.scoreBefore) + L" -> " + std::to_wstring(out.scoreAfter));
    return out;
}

int BiggestWinRank(const BiggestWinsResult& wins, const std::wstring& id)
{
    for (size_t i = 0; i < wins.wins.size(); ++i) {
        if (wins.wins[i].id == id) return static_cast<int>(i) + 1;
    }
    return 0;
}

std::wstring BiggestWinsHeadline(const BiggestWinsResult& wins)
{
    if (wins.wins.empty()) return L"";
    std::wstring which = wins.wins.size() == 1 ? L"Fix this one" : L"Fix these " + std::to_wstring(wins.wins.size());
    // Near the top a small problem can be worth less than half a point, so the rounded
    // score does not move; say that instead of "from 100 to 100".
    if (wins.scoreAfter == wins.scoreBefore) {
        return which + L" to clear what is left. The score already rounds to " + std::to_wstring(wins.scoreBefore) +
               L", so the number will not change.";
    }
    return which + L" and the score goes from " + std::to_wstring(wins.scoreBefore) + L" to " +
           std::to_wstring(wins.scoreAfter) + L".";
}

std::wstring BiggestWinsText(const BiggestWinsResult& wins, const std::wstring& lineEnd)
{
    if (wins.wins.empty()) return L"";
    std::wstring out = L"Biggest wins (the fixes that raise the hardening score the most):" + lineEnd;
    out += L"  " + BiggestWinsHeadline(wins) + lineEnd;
    for (size_t i = 0; i < wins.wins.size(); ++i) {
        const ScoreWin& w = wins.wins[i];
        out += L"  " + std::to_wstring(i + 1) + L". +" + std::to_wstring(w.points) + L"  " + w.title + L" (" + w.id +
               L", " + w.status + L")" + lineEnd;
    }
    return out;
}
