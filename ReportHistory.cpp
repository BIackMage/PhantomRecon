#include "pch.h"
#include "ReportHistory.h"

#include "CheckCatalog.h"
#include "JsonWriter.h"
#include "TextUtils.h"

#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[ReportHistory] " + msg + L"\n").c_str());
}

static std::wstring H(const std::wstring& s)
{
    return HtmlEscape(AsciiPunctuation(s));
}

static std::wstring TitleOf(const std::wstring& id)
{
    const CheckInfo* info = FindCheckInfo(id);
    return info ? info->title : id;
}

// ---------------------------------------------------------------------------
// Chart
// ---------------------------------------------------------------------------
std::wstring BuildHistoryChartSvg(const std::vector<AuditRecord>& records)
{
    if (records.size() < 2) return L"";
    const double width = 640, height = 220;
    const double left = 40, right = 16, top = 14, bottom = 40;
    const double plotW = width - left - right;
    const double plotH = height - top - bottom;
    const size_t n = records.size();
    auto xAt = [&](size_t i) { return left + plotW * static_cast<double>(i) / static_cast<double>(n - 1); };
    auto yAt = [&](int score) { return top + plotH * (100.0 - score) / 100.0; };

    // The text alternative reads out every point.
    std::wstring desc = L"Oldest first: ";
    for (size_t i = 0; i < n; ++i) {
        if (i > 0) desc += L", ";
        desc += std::to_wstring(records[i].score) + L" on " + HistoryDateText(records[i].firstSeen, true);
    }
    desc += L".";

    std::wstringstream s;
    s << L"<svg class=\"trend\" viewBox=\"0 0 640 220\" role=\"img\" aria-labelledby=\"trend-t trend-d\">"
      << L"<title id=\"trend-t\">Hardening score over the last " << n << L" audits</title>"
      << L"<desc id=\"trend-d\">" << H(desc) << L"</desc>";
    for (int mark = 0; mark <= 100; mark += 25) {
        std::wstring y = FormatFixed(yAt(mark), 1);
        s << L"<line class=\"grid\" x1=\"" << FormatFixed(left, 1) << L"\" y1=\"" << y << L"\" x2=\"" << FormatFixed(width - right, 1)
          << L"\" y2=\"" << y << L"\"/>"
          << L"<text x=\"" << FormatFixed(left - 6, 1) << L"\" y=\"" << FormatFixed(yAt(mark) + 4, 1) << L"\" text-anchor=\"end\">"
          << mark << L"</text>";
    }
    s << L"<polyline class=\"line\" points=\"";
    for (size_t i = 0; i < n; ++i) {
        if (i > 0) s << L" ";
        s << FormatFixed(xAt(i), 1) << L"," << FormatFixed(yAt(records[i].score), 1);
    }
    s << L"\"/>";
    for (size_t i = 0; i < n; ++i) {
        s << L"<circle class=\"dot\" cx=\"" << FormatFixed(xAt(i), 1) << L"\" cy=\"" << FormatFixed(yAt(records[i].score), 1)
          << L"\" r=\"4\"><title>" << records[i].score << L" on " << H(HistoryDateText(records[i].firstSeen, true))
          << L"</title></circle>";
    }
    const std::wstring labelY = FormatFixed(height - bottom + 20, 1);
    s << L"<text x=\"" << FormatFixed(left, 1) << L"\" y=\"" << labelY << L"\" text-anchor=\"start\">"
      << H(HistoryDateText(records.front().firstSeen, true)) << L"</text>"
      << L"<text x=\"" << FormatFixed(width - right, 1) << L"\" y=\"" << labelY << L"\" text-anchor=\"end\">"
      << H(HistoryDateText(records.back().firstSeen, true)) << L"</text>";
    s << L"</svg>";
    return s.str();
}

// ---------------------------------------------------------------------------
// HTML section
// ---------------------------------------------------------------------------
static void WriteChangeList(std::wstringstream& html, const wchar_t* heading, const std::vector<AuditChange>& changes,
                            bool showBefore)
{
    if (changes.empty()) return;
    html << L"<h3 style=\"margin-top:14px\">" << heading << L" (" << changes.size() << L")</h3><ul>";
    for (const AuditChange& ch : changes) {
        html << L"<li>" << H(TitleOf(ch.id)) << L" <span class=\"sev\">";
        if (showBefore && !ch.before.empty()) html << H(ch.before) << L" to " << H(ch.after);
        else html << L"now " << H(ch.after);
        html << L"</span></li>";
    }
    html << L"</ul>\n";
}

std::wstring BuildHistoryHtmlSection(const AuditComparison& c, const std::vector<AuditRecord>& records)
{
    std::wstringstream html;
    html << L"<section class=\"hist\" aria-labelledby=\"hist-h\"><h2 id=\"hist-h\">Since your last audit</h2>\n";
    if (!c.hasPrevious) {
        html << L"<p class=\"meta\">This is the first audit recorded on this PC. The next audit will show what changed "
             << L"since this one.</p></section>\n";
        DebugLog(L"History section: first audit");
        return html.str();
    }

    std::wstring last = HistoryDateText(c.previousDate, true);
    if (c.sameState) {
        html << L"<p>No change since the last audit on " << H(last) << L". The score (" << c.currentScore
             << L") and every check's result have been the same since " << H(HistoryDateText(c.previousFirstSeen, true))
             << L".</p>\n";
    }
    else {
        std::wstring change;
        std::wstring cls = L"info";
        if (c.scoreChange > 0) { change = L"up " + std::to_wstring(c.scoreChange); cls = L"pass"; }
        else if (c.scoreChange < 0) { change = L"down " + std::to_wstring(-c.scoreChange); cls = L"fail"; }
        else change = L"unchanged";
        html << L"<p>Score <b>" << c.currentScore << L"</b>, <b class=\"" << cls << L"\">" << change << L"</b> from "
             << c.previousScore << L" at the last audit on " << H(last) << L".</p>\n";
        html << L"<div class=\"tiles\">"
             << L"<div class=\"tile\"><b class=\"pass\">" << c.fixed.size() << L"</b><span>Fixed</span></div>"
             << L"<div class=\"tile\"><b class=\"fail\">" << c.newProblems.size() << L"</b><span>New problems</span></div>"
             << L"<div class=\"tile\"><b class=\"fail\">" << c.worse.size() << L"</b><span>Worse</span></div>"
             << L"<div class=\"tile\"><b class=\"warn\">" << c.better.size() << L"</b><span>Better</span></div></div>\n";
        WriteChangeList(html, L"Fixed", c.fixed, true);
        WriteChangeList(html, L"New problems", c.newProblems, true);
        WriteChangeList(html, L"Worse", c.worse, true);
        WriteChangeList(html, L"Better", c.better, true);
        WriteChangeList(html, L"New checks in this version", c.newChecks, false);
        WriteChangeList(html, L"Recent activity, not scored", c.activity, true);
        if (c.fixed.empty() && c.newProblems.empty() && c.worse.empty() && c.better.empty() && c.newChecks.empty() &&
            c.activity.empty()) {
            html << L"<p class=\"meta\">No check moved into or out of FAIL or WARNING.</p>\n";
        }
    }

    std::wstring chart = BuildHistoryChartSvg(records);
    if (!chart.empty()) {
        html << chart << L"\n<details><summary>The same scores as a table</summary><table><thead><tr><th>First seen</th>"
             << L"<th>Last seen</th><th>Score</th><th>Pass</th><th>Warning</th><th>Fail</th></tr></thead><tbody>";
        for (const AuditRecord& r : records) {
            html << L"<tr><td>" << H(HistoryDateTimeText(r.firstSeen)) << L"</td><td>" << H(HistoryDateTimeText(r.lastSeen))
                 << L"</td><td>" << r.score << L"</td><td>" << r.pass << L"</td><td>" << r.warn << L"</td><td>" << r.fail
                 << L"</td></tr>";
        }
        html << L"</tbody></table></details>\n";
    }
    html << L"</section>\n";
    DebugLog(L"History section: " + std::to_wstring(records.size()) + L" records, score change " + std::to_wstring(c.scoreChange));
    return html.str();
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------
void WriteHistoryJson(JsonWriter& w, const AuditComparison& c)
{
    w.BeginObject();
    w.Key(L"firstAudit"); w.Bool(!c.hasPrevious);
    w.Key(L"previous");
    if (c.hasPrevious) {
        w.BeginObject();
        w.Key(L"date"); w.String(c.previousDate);
        w.Key(L"firstSeen"); w.String(c.previousFirstSeen);
        w.Key(L"score"); w.Number(c.previousScore);
        w.EndObject();
    }
    else {
        w.Null();
    }
    w.Key(L"score"); w.Number(c.currentScore);
    w.Key(L"scoreChange"); w.Number(c.scoreChange);
    w.Key(L"sameState"); w.Bool(c.sameState);
    w.Key(L"fixed"); w.StringArray(AuditChangeIds(c.fixed));
    w.Key(L"newProblems"); w.StringArray(AuditChangeIds(c.newProblems));
    w.Key(L"worse"); w.StringArray(AuditChangeIds(c.worse));
    w.Key(L"better"); w.StringArray(AuditChangeIds(c.better));
    w.Key(L"newChecks"); w.StringArray(AuditChangeIds(c.newChecks));
    w.Key(L"activity"); w.StringArray(AuditChangeIds(c.activity));
    w.EndObject();
}
