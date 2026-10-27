// AuditHistoryText.cpp: the words people read about audit history (score line,
// text report paragraph, findings window note, --history table). Pure: no files.

#include "pch.h"
#include "AuditHistory.h"

#include "CheckCatalog.h"
#include "TextUtils.h"

#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[AuditHistory] " + msg + L"\n").c_str());
}

static std::wstring TitleOf(const std::wstring& id)
{
    const CheckInfo* info = FindCheckInfo(id);
    return info ? info->title : id;
}

static std::wstring Signed(int value)
{
    return value > 0 ? L"+" + std::to_wstring(value) : std::to_wstring(value);
}

std::wstring HistoryScoreLine(const AuditComparison& c)
{
    if (!c.hasPrevious) return L"first audit";
    if (c.sameState) return L"no change since " + HistoryDateText(c.previousFirstSeen, false);
    std::wstring date = HistoryDateText(c.previousDate, false);
    if (c.scoreChange == 0) return L"same score as " + date;
    return Signed(c.scoreChange) + L" since " + date;
}

// "Title (FAIL -> PASS), Title (WARNING -> FAIL)"
static std::wstring ChangeList(const std::vector<AuditChange>& changes, bool showBefore)
{
    std::vector<std::wstring> parts;
    for (const AuditChange& ch : changes) {
        std::wstring part = TitleOf(ch.id) + L" (";
        part += showBefore && !ch.before.empty() ? ch.before + L" -> " + ch.after : ch.after;
        part += L")";
        parts.push_back(part);
    }
    return JoinW(parts, L", ");
}

std::wstring BuildHistoryParagraph(const AuditComparison& c)
{
    if (!c.hasPrevious) {
        return L"Audit history: this is the first audit recorded on this PC. The next audit will show what changed.";
    }
    std::wstring last = HistoryDateText(c.previousDate, true);
    if (c.sameState) {
        return L"Since the last audit (" + last + L"): no change. The score (" + std::to_wstring(c.currentScore) +
               L") and every check's result have been the same since " + HistoryDateText(c.previousFirstSeen, true) + L".";
    }
    std::wstringstream ss;
    ss << L"Since the last audit (" << last << L"): score " << c.previousScore << L" -> " << c.currentScore << L" ("
       << Signed(c.scoreChange) << L").";
    bool any = false;
    auto list = [&](const wchar_t* name, const std::vector<AuditChange>& changes, bool showBefore) {
        if (changes.empty()) return;
        ss << L" " << name << L" " << changes.size() << L": " << ChangeList(changes, showBefore) << L".";
        any = true;
    };
    list(L"Fixed", c.fixed, true);
    list(L"New problems", c.newProblems, true);
    list(L"Worse", c.worse, true);
    list(L"Better", c.better, true);
    list(L"New checks in this version", c.newChecks, false);
    list(L"Recent activity, not scored,", c.activity, true);
    if (!any) ss << L" No check moved into or out of FAIL or WARNING.";
    return ss.str();
}

static const AuditChange* FindChange(const std::vector<AuditChange>& changes, const std::wstring& id)
{
    for (const AuditChange& ch : changes) {
        if (ch.id == id) return &ch;
    }
    return nullptr;
}

std::wstring HistoryNoteForCheck(const AuditComparison& c, const std::wstring& id)
{
    if (!c.hasPrevious) return L"";
    std::wstring when = L" since the last audit (" + HistoryDateText(c.previousDate, true) + L"): it was ";
    if (const AuditChange* ch = FindChange(c.fixed, id)) return L"Fixed" + when + ch->before + L".";
    if (const AuditChange* ch = FindChange(c.newProblems, id)) return L"New problem" + when + ch->before + L".";
    if (const AuditChange* ch = FindChange(c.worse, id)) return L"Worse" + when + ch->before + L".";
    if (const AuditChange* ch = FindChange(c.better, id)) return L"Better" + when + ch->before + L".";
    if (FindChange(c.newChecks, id)) {
        return L"New check in this version: the last audit (" + HistoryDateText(c.previousDate, true) + L") did not have it.";
    }
    if (const AuditChange* ch = FindChange(c.activity, id)) {
        return L"Changed" + when + ch->before + L". This check reports events and is not scored.";
    }
    return L"";
}

std::wstring BuildHistoryTable(const std::vector<AuditRecord>& records, size_t maxRows)
{
    if (records.empty()) return L"No audit history yet.\n";
    size_t from = records.size() > maxRows ? records.size() - maxRows : 0;
    std::wstringstream ss;
    ss << L"Audit history on this PC, oldest first (" << (records.size() - from) << L" of " << records.size() << L" records)\n\n";
    wchar_t line[160];
    swprintf_s(line, L"%-17s  %-17s  %5s  %4s  %4s  %4s\n", L"First seen", L"Last seen", L"Score", L"Pass", L"Warn", L"Fail");
    ss << line;
    swprintf_s(line, L"%-17s  %-17s  %5s  %4s  %4s  %4s\n", L"----------", L"---------", L"-----", L"----", L"----", L"----");
    ss << line;
    for (size_t i = from; i < records.size(); ++i) {
        const AuditRecord& r = records[i];
        swprintf_s(line, L"%-17s  %-17s  %5d  %4d  %4d  %4d\n", HistoryDateTimeText(r.firstSeen).c_str(),
            HistoryDateTimeText(r.lastSeen).c_str(), r.score, r.pass, r.warn, r.fail);
        ss << line;
    }
    DebugLog(L"History table built with " + std::to_wstring(records.size() - from) + L" rows");
    return ss.str();
}
