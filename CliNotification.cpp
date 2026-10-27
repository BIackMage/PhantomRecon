// CliNotification.cpp: the words of the end-of-run desktop notification and the
// --notify-on-change decision. Pure: see CliNotification.h.

#include "pch.h"
#include "CliNotification.h"

#include "DebugTrace.h"

#include <algorithm>

static void DebugLog(const std::wstring& msg)
{
    Trace(L"CliNotification", msg);
}

static std::wstring Count(size_t n, const wchar_t* one, const wchar_t* many)
{
    return std::to_wstring(n) + L" " + (n == 1 ? one : many);
}

// "since 20 Oct", or "since the last audit" when the stored time is not readable.
static std::wstring Since(const std::wstring& isoUtc)
{
    std::wstring date = HistoryDateText(isoUtc, false);
    return date.empty() ? L"since the last audit" : L"since " + date;
}

// "score 61, down 4", "score 68, up 3" or "score 65".
static std::wstring ScoreClause(const AuditComparison& c)
{
    std::wstring text = L"score " + std::to_wstring(c.currentScore);
    if (c.scoreChange < 0) text += L", down " + std::to_wstring(-c.scoreChange);
    else if (c.scoreChange > 0) text += L", up " + std::to_wstring(c.scoreChange);
    return text;
}

static std::wstring JoinAnd(const std::wstring& a, const std::wstring& b)
{
    if (a.empty()) return b;
    if (b.empty()) return a;
    return a + L" and " + b;
}

bool RunFailed(const NotificationFacts& f)
{
    return f.exitCode == 2 || !f.error.empty();
}

static bool AuditGotWorse(const NotificationFacts& f)
{
    if (!f.hasAudit || !f.hasHistory || !f.comparison.hasPrevious) return false;
    const AuditComparison& c = f.comparison;
    return !c.newProblems.empty() || !c.worse.empty() || c.scoreChange < 0;
}

static bool ScanGotWorse(const NotificationFacts& f)
{
    return f.hasScan && !f.baselineScan && (f.scanAdded > 0 || f.scanChanged > 0);
}

bool RunGotWorse(const NotificationFacts& f)
{
    return AuditGotWorse(f) || ScanGotWorse(f);
}

bool ShouldShowNotification(const NotificationFacts& f, bool onlyWhenWorse)
{
    bool show = !onlyWhenWorse || RunFailed(f) || RunGotWorse(f);
    DebugLog(std::wstring(L"Notification ") + (show ? L"shown" : L"not shown") +
             (onlyWhenWorse ? L" (only when worse)" : L" (always)") + L": failed " + (RunFailed(f) ? L"yes" : L"no") +
             L", audit worse " + (AuditGotWorse(f) ? L"yes" : L"no") + L", scan worse " + (ScanGotWorse(f) ? L"yes" : L"no"));
    return show;
}

std::wstring NotificationAuditSentence(const NotificationFacts& f)
{
    if (!f.hasAudit) return L"";
    if (!f.hasHistory || !f.comparison.hasPrevious) {
        return L"Hardening score " + std::to_wstring(f.score) + L"/100.";
    }
    const AuditComparison& c = f.comparison;
    if (c.sameState) {
        return L"No change " + Since(c.previousFirstSeen) + L" (score " + std::to_wstring(c.currentScore) + L").";
    }

    std::wstring since = Since(c.previousDate);
    std::wstring sentence;
    std::wstring bad = JoinAnd(c.newProblems.empty() ? L"" : Count(c.newProblems.size(), L"new problem", L"new problems"),
                               c.worse.empty() ? L"" : Count(c.worse.size(), L"check worse", L"checks worse"));
    if (!bad.empty()) {
        sentence = bad + L" " + since + L" (" + ScoreClause(c) + L"). Open Phantom Recon to see them.";
    }
    else if (c.scoreChange < 0) {
        sentence = L"Score " + std::to_wstring(c.currentScore) + L", down " + std::to_wstring(-c.scoreChange) + L" " + since +
                   L". Open Phantom Recon to see why.";
    }
    else {
        std::wstring good = JoinAnd(c.fixed.empty() ? L"" : Count(c.fixed.size(), L"fixed", L"fixed"),
                                    c.better.empty() ? L"" : Count(c.better.size(), L"check better", L"checks better"));
        if (!good.empty()) sentence = good + L" " + since + L" (" + ScoreClause(c) + L").";
        else sentence = L"No new problems " + since + L" (" + ScoreClause(c) + L").";
    }
    // Unscored activity checks: one short sentence, never the headline.
    if (!c.activity.empty()) {
        sentence += L" Recent activity changed in " + Count(c.activity.size(), L"unscored check.", L"unscored checks.");
    }
    return sentence;
}

std::wstring NotificationScanSentence(const NotificationFacts& f)
{
    if (!f.hasScan) return L"";
    if (f.baselineScan) return L"Baseline taken: " + Count(static_cast<size_t>((std::max)(0, f.scanPrograms)), L"file.", L"files.");
    std::wstring text;
    if (f.scanAdded == 0 && f.scanChanged == 0 && f.scanMissing == 0) {
        text = L"Scan: nothing new, changed or missing.";
    }
    else {
        text = L"Scan: " + std::to_wstring(f.scanAdded) + L" new, " + std::to_wstring(f.scanChanged) + L" changed, " +
               std::to_wstring(f.scanMissing) + L" missing.";
    }
    if (f.scanHighRisk > 0) text += L" " + std::to_wstring(f.scanHighRisk) + L" scored 7 or more.";
    return text;
}

// Cut to max characters with "..." at the end, never between the halves of a surrogate pair.
static std::wstring Cap(const std::wstring& text, size_t max)
{
    if (text.size() <= max || max < 4) return text.substr(0, (std::min)(text.size(), max));
    size_t keep = max - 3;
    if (keep > 0 && text[keep - 1] >= 0xD800 && text[keep - 1] <= 0xDBFF) --keep;
    return text.substr(0, keep) + L"...";
}

CliNotification BuildCliNotification(const NotificationFacts& f)
{
    CliNotification n;
    if (RunFailed(f)) n.title = L"Phantom Recon: the run failed";
    else if (RunGotWorse(f)) n.title = L"Phantom Recon: something got worse";
    else if (f.exitCode == 1) n.title = L"Phantom Recon: please review";
    else n.title = L"Phantom Recon: all clear";

    std::wstring text;
    auto add = [&](const std::wstring& part) {
        if (part.empty()) return;
        if (!text.empty()) text += L" ";
        text += part;
    };
    if (!f.error.empty()) {
        std::wstring error = L"Error: " + f.error;
        if (error.back() != L'.') error += L".";
        add(error);
    }
    else if (RunFailed(f)) {
        add(L"Error: the run did not finish.");
    }
    add(NotificationAuditSentence(f));
    add(NotificationScanSentence(f));
    if (text.empty()) text = L"Done.";

    n.title = Cap(n.title, kNotificationTitleMaxChars);
    n.text = Cap(text, kNotificationTextMaxChars);
    DebugLog(L"Notification text: " + n.title + L" | " + n.text);
    return n;
}
