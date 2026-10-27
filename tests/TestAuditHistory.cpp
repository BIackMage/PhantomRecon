// Audit history: records, the history file, the comparison with the previous audit,
// the text for people, the HTML and JSON report parts, and the console options.

#include "TestFramework.h"
#include "JsonCheck.h"

#include "../AppPaths.h"
#include "../AuditHistory.h"
#include "../CheckCatalog.h"
#include "../CliRunner.h"
#include "../FileIO.h"
#include "../JsonReader.h"
#include "../JsonWriter.h"
#include "../ReportHistory.h"
#include "../Reports.h"
#include "../StringConv.h"
#include "../TextUtils.h"

#include <map>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::vector<std::wstring> CatalogIds(bool scored)
{
    std::vector<std::wstring> ids;
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (info.scored == scored) ids.push_back(info.id);
    }
    return ids;
}

static std::wstring TitleOf(const std::wstring& id)
{
    const CheckInfo* info = FindCheckInfo(id);
    return info ? info->title : id;
}

static AuditRecord Record(const std::wstring& when, int score, const std::map<std::wstring, std::wstring>& statuses)
{
    AuditRecord r;
    r.firstSeen = when;
    r.lastSeen = when;
    r.version = L"1.0.0";
    r.score = score;
    r.label = HardeningLabel(score);
    r.statuses = statuses;
    for (const auto& s : statuses) {
        if (s.second == CHECK_PASS) r.pass++;
        else if (s.second == CHECK_WARNING) r.warn++;
        else if (s.second == CHECK_FAIL) r.fail++;
        else if (s.second == CHECK_ERROR) r.error++;
        else r.info++;
    }
    return r;
}

// "2026-10-01T12:00:00Z" plus n days (n < 28) or, past that, minutes.
static std::wstring Day(int n)
{
    wchar_t buf[32];
    if (n < 28) swprintf_s(buf, L"2026-10-%02dT12:00:00Z", n + 1);
    else swprintf_s(buf, L"2026-11-01T%02d:%02d:00Z", (n / 60) % 24, n % 60);
    return buf;
}

static std::wstring ReadAll(const std::wstring& path)
{
    std::wstring text;
    ReadTextFile(path, text);
    return text;
}

static size_t CountLines(const std::wstring& text)
{
    size_t lines = 0;
    for (const std::wstring& line : SplitW(text, L'\n')) {
        if (!TrimW(line).empty()) ++lines;
    }
    return lines;
}

static bool Contains(const std::vector<AuditChange>& changes, const std::wstring& id, const std::wstring& before,
                     const std::wstring& after)
{
    for (const AuditChange& c : changes) {
        if (c.id == id && c.before == before && c.after == after) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Records and the file
// ---------------------------------------------------------------------------
TEST(History_RecordRoundTrip)
{
    std::vector<std::wstring> ids = CatalogIds(true);
    REQUIRE(ids.size() >= 4);
    std::vector<SecurityCheckResult> results;
    const wchar_t* statuses[] = { CHECK_PASS, CHECK_FAIL, CHECK_WARNING, CHECK_NA };
    for (size_t i = 0; i < 4; ++i) {
        SecurityCheckResult r = MakeCheckResult(ids[i]);
        r.status = statuses[i];
        r.detail = L"C:\\Users\\someone\\secret path";   // evidence must never reach the file
        results.push_back(r);
    }
    HardeningScore score = ComputeHardeningScore(results);
    AuditRecord rec = MakeAuditRecord(results, score, L"2026-10-20T08:15:30Z");
    CHECK_EQ(rec.firstSeen, std::wstring(L"2026-10-20T08:15:30Z"));
    CHECK_EQ(rec.lastSeen, rec.firstSeen);
    CHECK_EQ(rec.score, score.score);
    CHECK_EQ(rec.pass, 1);
    CHECK_EQ(rec.fail, 1);
    CHECK_EQ(rec.warn, 1);
    CHECK_EQ(rec.info, 1);   // N/A counts as info
    CHECK_EQ(rec.statuses.size(), static_cast<size_t>(4));

    std::wstring line = AuditRecordToJsonLine(rec);
    CHECK(line.find(L'\n') == std::wstring::npos);
    CHECK(line.find(L"secret") == std::wstring::npos);
    CHECK(line.find(L"Users") == std::wstring::npos);
    JsonCheck check(line);
    CHECK(check.Valid());
    // Exactly the fields the header promises, nothing else.
    for (const wchar_t* key : { L"firstSeen", L"lastSeen", L"version", L"score", L"label", L"pass", L"warn", L"fail",
                                L"info", L"error", L"statuses" }) {
        CHECK_EQ(check.KeyCount(key), 1);
    }

    AuditRecord back;
    std::string why;
    REQUIRE(AuditRecordFromJsonLine(WideToUtf8(line), back, why));
    CHECK_EQ(back.firstSeen, rec.firstSeen);
    CHECK_EQ(back.lastSeen, rec.lastSeen);
    CHECK_EQ(back.version, rec.version);
    CHECK_EQ(back.score, rec.score);
    CHECK_EQ(back.label, rec.label);
    CHECK_EQ(back.pass, rec.pass);
    CHECK_EQ(back.warn, rec.warn);
    CHECK_EQ(back.fail, rec.fail);
    CHECK_EQ(back.info, rec.info);
    CHECK_EQ(back.error, rec.error);
    CHECK(back.statuses == rec.statuses);
    CHECK(SameAuditState(back, rec));

    // The compact writer used for the line.
    JsonWriter w;
    w.SetCompact(true);
    w.BeginObject();
    w.Key(L"a"); w.Number(1);
    w.Key(L"b"); w.StringArray({ L"x", L"y\nz" });
    w.EndObject();
    CHECK_EQ(w.Text(), std::wstring(L"{\"a\":1,\"b\":[\"x\",\"y\\nz\"]}"));
}

TEST(History_SameStateUpdatesNewRecordAppends)
{
    std::vector<AuditRecord> records;
    AuditRecord a = Record(Day(0), 60, { { L"net.llmnr", CHECK_FAIL }, { L"net.mdns", CHECK_PASS } });
    CHECK(AddAuditRecord(records, a));
    CHECK_EQ(records.size(), static_cast<size_t>(1));

    // Same statuses and score: only lastSeen moves.
    AuditRecord same = Record(Day(3), 60, { { L"net.llmnr", CHECK_FAIL }, { L"net.mdns", CHECK_PASS } });
    CHECK(!AddAuditRecord(records, same));
    REQUIRE(records.size() == 1);
    CHECK_EQ(records[0].firstSeen, Day(0));
    CHECK_EQ(records[0].lastSeen, Day(3));

    // One status different: appended.
    AuditRecord changed = Record(Day(5), 60, { { L"net.llmnr", CHECK_PASS }, { L"net.mdns", CHECK_PASS } });
    CHECK(AddAuditRecord(records, changed));
    CHECK_EQ(records.size(), static_cast<size_t>(2));

    // Same statuses but another score (a scoring weight changed): appended too.
    AuditRecord rescored = changed;
    rescored.firstSeen = rescored.lastSeen = Day(6);
    rescored.score = 61;
    CHECK(AddAuditRecord(records, rescored));
    CHECK_EQ(records.size(), static_cast<size_t>(3));
    CHECK_EQ(records.back().firstSeen, Day(6));
}

TEST(History_KeepsAtMost500)
{
    std::vector<AuditRecord> records;
    for (int i = 0; i < 510; ++i) {
        AuditRecord r = Record(Day(30 + i), i % 2 == 0 ? 40 : 60, { { L"net.llmnr", i % 2 == 0 ? CHECK_FAIL : CHECK_PASS } });
        CHECK(AddAuditRecord(records, r));
    }
    CHECK_EQ(records.size(), kAuditHistoryMaxRecords);
    CHECK_EQ(records.front().firstSeen, Day(30 + 10));   // the 10 oldest were dropped
    CHECK_EQ(records.back().firstSeen, Day(30 + 509));

    // The cap holds through the file too.
    std::wstring path = tf::TestDir() + L"cap.jsonl";
    REQUIRE(SaveAuditHistory(path, records));
    AuditRecord next = Record(Day(30 + 510), 40, { { L"net.llmnr", CHECK_FAIL } });
    AuditHistoryUpdate u = RecordAuditInHistory(path, next);
    CHECK(u.saved);
    std::vector<AuditRecord> loaded;
    REQUIRE(LoadAuditHistory(path, loaded));
    CHECK_EQ(loaded.size(), kAuditHistoryMaxRecords);
    CHECK_EQ(loaded.front().firstSeen, Day(30 + 11));
    CHECK_EQ(loaded.back().firstSeen, Day(30 + 510));
    CHECK_EQ(u.recent.size(), kAuditHistoryChartRecords);
    CHECK_EQ(u.recent.back().firstSeen, Day(30 + 510));
}

TEST(History_BrokenLinesSkipped)
{
    AuditRecord good1 = Record(Day(1), 50, { { L"net.llmnr", CHECK_FAIL } });
    AuditRecord good2 = Record(Day(2), 70, { { L"net.llmnr", CHECK_PASS } });
    std::string text = "\xEF\xBB\xBF" + WideToUtf8(AuditRecordToJsonLine(good1)) + "\r\n" +
        "this is not json\n" +
        "{\"firstSeen\":\"2026-10-03T12:00:00Z\",\"score\":50,\"statuses\":{}}\n" +                         // no lastSeen
        "{\"firstSeen\":\"2026-02-30T12:00:00Z\",\"lastSeen\":\"2026-02-30T12:00:00Z\",\"score\":50,\"statuses\":{}}\n" +   // no such day
        "{\"firstSeen\":\"2026-10-03T12:00:00Z\",\"lastSeen\":\"2026-10-03T12:00:00Z\",\"score\":150,\"statuses\":{}}\n" +  // score out of range
        "{\"firstSeen\":\"2026-10-03T12:00:00Z\",\"lastSeen\":\"2026-10-03T12:00:00Z\",\"score\":50.5,\"statuses\":{}}\n" + // not whole
        "[1,2,3]\n" +
        "{\"firstSeen\":\"2026-10-03T12:00:00Z\",\"lastSeen\":\"2026-10-03T12:00:00Z\",\"score\":50,\"statuses\":{}\n" +    // cut off
        "\n   \n" +                                                                                                       // blank: not counted
        WideToUtf8(AuditRecordToJsonLine(good2)) + "\n" +
        // A record from a later version: unknown field kept out, unknown status entry dropped, the rest used.
        "{\"firstSeen\":\"2026-10-04T12:00:00Z\",\"lastSeen\":\"2026-10-04T12:00:00Z\",\"score\":55,\"future\":true,"
        "\"statuses\":{\"net.llmnr\":\"PASS\",\"net.mdns\":\"MAYBE\",\"net.nbtns\":7}}";

    int skipped = 0;
    std::vector<AuditRecord> records = ParseAuditHistoryText(text, &skipped);
    CHECK_EQ(skipped, 7);
    REQUIRE(records.size() == 3);
    CHECK(SameAuditState(records[0], good1));
    CHECK(SameAuditState(records[1], good2));
    CHECK_EQ(records[2].score, 55);
    CHECK_EQ(records[2].statuses.size(), static_cast<size_t>(1));
    CHECK_EQ(records[2].statuses[L"net.llmnr"], std::wstring(CHECK_PASS));

    // Through the file: the broken lines never stop the next audit from being recorded.
    std::wstring path = tf::TestDir() + L"broken.jsonl";
    REQUIRE(WriteBinaryFile(path, text.data(), text.size()));
    AuditRecord now = Record(Day(9), 80, { { L"net.llmnr", CHECK_PASS } });
    AuditHistoryUpdate u = RecordAuditInHistory(path, now);
    CHECK(u.loaded);
    CHECK(u.saved);
    CHECK_EQ(u.skippedLines, 7);
    CHECK(u.comparison.hasPrevious);
    CHECK_EQ(u.comparison.previousScore, 55);
    CHECK_EQ(u.comparison.scoreChange, 25);
    std::vector<AuditRecord> loaded;
    int skippedAfter = -1;
    REQUIRE(LoadAuditHistory(path, loaded, &skippedAfter));
    CHECK_EQ(loaded.size(), static_cast<size_t>(4));
    CHECK_EQ(skippedAfter, 0);
    CHECK(!FileExists(path + L".tmp"));

    // A file that is entirely junk is an empty history, not an error.
    std::string junk = "\x01\x02 garbage \xFF\xFE";
    REQUIRE(WriteBinaryFile(path, junk.data(), junk.size()));
    REQUIRE(LoadAuditHistory(path, loaded, &skippedAfter));
    CHECK(loaded.empty());
    CHECK_EQ(skippedAfter, 1);

    // A missing file is an empty history too.
    REQUIRE(LoadAuditHistory(tf::TestDir() + L"none.jsonl", loaded, &skippedAfter));
    CHECK(loaded.empty());
    CHECK_EQ(skippedAfter, 0);
}

TEST(History_RecordInFile)
{
    std::wstring path = tf::TestDir() + L"h.jsonl";
    std::vector<std::wstring> ids = CatalogIds(true);
    REQUIRE(ids.size() >= 2);

    AuditRecord first = Record(Day(1), 50, { { ids[0], CHECK_FAIL }, { ids[1], CHECK_PASS } });
    AuditHistoryUpdate u1 = RecordAuditInHistory(path, first);
    CHECK(u1.loaded);
    CHECK(u1.saved);
    CHECK(!u1.comparison.hasPrevious);
    CHECK_EQ(u1.comparison.currentScore, 50);
    CHECK_EQ(u1.recent.size(), static_cast<size_t>(1));
    CHECK_EQ(CountLines(ReadAll(path)), static_cast<size_t>(1));

    // The same state again (the window program audits at every start): still one line.
    AuditRecord again = Record(Day(2), 50, { { ids[0], CHECK_FAIL }, { ids[1], CHECK_PASS } });
    AuditHistoryUpdate u2 = RecordAuditInHistory(path, again);
    CHECK(u2.comparison.hasPrevious);
    CHECK(u2.comparison.sameState);
    CHECK_EQ(u2.comparison.previousFirstSeen, Day(1));
    CHECK_EQ(u2.comparison.previousDate, Day(1));
    CHECK_EQ(CountLines(ReadAll(path)), static_cast<size_t>(1));
    std::vector<AuditRecord> loaded;
    REQUIRE(LoadAuditHistory(path, loaded));
    REQUIRE(loaded.size() == 1);
    CHECK_EQ(loaded[0].firstSeen, Day(1));
    CHECK_EQ(loaded[0].lastSeen, Day(2));

    // Fixed one check: a second line and the comparison says so.
    AuditRecord fixed = Record(Day(3), 70, { { ids[0], CHECK_PASS }, { ids[1], CHECK_PASS } });
    AuditHistoryUpdate u3 = RecordAuditInHistory(path, fixed);
    CHECK(!u3.comparison.sameState);
    CHECK_EQ(u3.comparison.previousDate, Day(2));     // the last audit before this one
    CHECK_EQ(u3.comparison.previousFirstSeen, Day(1));
    CHECK_EQ(u3.comparison.scoreChange, 20);
    CHECK(Contains(u3.comparison.fixed, ids[0], CHECK_FAIL, CHECK_PASS));
    CHECK_EQ(CountLines(ReadAll(path)), static_cast<size_t>(2));
    CHECK_EQ(u3.recent.size(), static_cast<size_t>(2));
    CHECK(!FileExists(path + L".tmp"));

    // A history that exists but cannot be read (held open by another program) is never
    // overwritten: nothing is compared, nothing is saved, and the file stays as it was.
    std::wstring before = ReadAll(path);
    HANDLE locked = CreateFileW(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(locked != INVALID_HANDLE_VALUE);
    AuditHistoryUpdate u4 = RecordAuditInHistory(path, Record(Day(4), 10, { { ids[0], CHECK_FAIL } }));
    CloseHandle(locked);
    CHECK(!u4.loaded);
    CHECK(!u4.saved);
    CHECK(!u4.error.empty());
    CHECK(!u4.comparison.hasPrevious);
    CHECK_EQ(ReadAll(path), before);
    CHECK(!FileExists(path + L".tmp"));
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------
TEST(History_CompareTransitions)
{
    std::vector<std::wstring> s = CatalogIds(true);
    std::vector<std::wstring> u = CatalogIds(false);
    REQUIRE(s.size() >= 12);
    REQUIRE(u.size() >= 2);

    std::map<std::wstring, std::wstring> before = {
        { s[0], CHECK_FAIL },      // -> PASS     fixed
        { s[1], CHECK_WARNING },   // -> N/A      fixed
        { s[2], CHECK_PASS },      // -> FAIL     new problem
        { s[3], CHECK_NA },        // -> WARNING  new problem
        { s[4], CHECK_ERROR },     // -> FAIL     new problem (nothing was known before)
        { s[5], CHECK_WARNING },   // -> FAIL     worse
        { s[6], CHECK_FAIL },      // -> WARNING  better
        { s[8], CHECK_PASS },      // -> PASS     no change
        { s[9], CHECK_PASS },      // -> INFO     moved, but in no list
        { s[10], CHECK_FAIL },     // -> ERROR    moved, but not fixed
        { u[0], CHECK_PASS },      // -> WARNING  activity, never a new problem
        { L"old.removed", CHECK_FAIL },   // gone in this version: ignored
    };
    std::map<std::wstring, std::wstring> after = {
        { s[0], CHECK_PASS }, { s[1], CHECK_NA }, { s[2], CHECK_FAIL }, { s[3], CHECK_WARNING }, { s[4], CHECK_FAIL },
        { s[5], CHECK_FAIL }, { s[6], CHECK_WARNING },
        { s[7], CHECK_FAIL },      // new in this version: listed apart, not a new problem
        { s[8], CHECK_PASS }, { s[9], CHECK_INFO }, { s[10], CHECK_ERROR },
        { u[0], CHECK_WARNING },
        { u[1], CHECK_WARNING },   // unscored and new in this version: a new check
    };
    AuditRecord prev = Record(Day(1), 40, before);
    AuditRecord cur = Record(Day(4), 52, after);
    AuditComparison c = CompareWithPrevious(cur, prev);

    CHECK(c.hasPrevious);
    CHECK(!c.sameState);
    CHECK_EQ(c.previousScore, 40);
    CHECK_EQ(c.currentScore, 52);
    CHECK_EQ(c.scoreChange, 12);
    CHECK_EQ(c.previousDate, Day(1));

    CHECK_EQ(c.fixed.size(), static_cast<size_t>(2));
    CHECK(Contains(c.fixed, s[0], CHECK_FAIL, CHECK_PASS));
    CHECK(Contains(c.fixed, s[1], CHECK_WARNING, CHECK_NA));

    CHECK_EQ(c.newProblems.size(), static_cast<size_t>(3));
    CHECK(Contains(c.newProblems, s[2], CHECK_PASS, CHECK_FAIL));
    CHECK(Contains(c.newProblems, s[3], CHECK_NA, CHECK_WARNING));
    CHECK(Contains(c.newProblems, s[4], CHECK_ERROR, CHECK_FAIL));

    CHECK_EQ(c.worse.size(), static_cast<size_t>(1));
    CHECK(Contains(c.worse, s[5], CHECK_WARNING, CHECK_FAIL));
    CHECK_EQ(c.better.size(), static_cast<size_t>(1));
    CHECK(Contains(c.better, s[6], CHECK_FAIL, CHECK_WARNING));

    CHECK_EQ(c.newChecks.size(), static_cast<size_t>(2));
    CHECK(Contains(c.newChecks, s[7], L"", CHECK_FAIL));
    CHECK(Contains(c.newChecks, u[1], L"", CHECK_WARNING));

    CHECK_EQ(c.activity.size(), static_cast<size_t>(1));
    CHECK(Contains(c.activity, u[0], CHECK_PASS, CHECK_WARNING));

    // Neither the new check nor the unscored one is a new problem.
    for (const AuditChange& ch : c.newProblems) {
        CHECK(ch.id != s[7]);
        CHECK(ch.id != u[0]);
        CHECK(ch.id != u[1]);
    }
    // Catalog order inside each list.
    CHECK_EQ(c.fixed[0].id, s[0]);
    CHECK_EQ(c.newProblems[0].id, s[2]);
    CHECK_EQ(c.newProblems[2].id, s[4]);
    CHECK(AuditChangeIds(c.newProblems) == (std::vector<std::wstring>{ s[2], s[3], s[4] }));

    // Identical records: same state, every list empty.
    AuditComparison same = CompareWithPrevious(prev, prev);
    CHECK(same.sameState);
    CHECK_EQ(same.scoreChange, 0);
    CHECK(same.fixed.empty() && same.newProblems.empty() && same.worse.empty() && same.better.empty() &&
          same.newChecks.empty() && same.activity.empty());
}

// ---------------------------------------------------------------------------
// Text for people
// ---------------------------------------------------------------------------
TEST(History_TextForPeople)
{
    SYSTEMTIME st = {};
    CHECK(ParseUtcIso(L"2026-10-20T08:15:30Z", &st));
    CHECK_EQ(static_cast<int>(st.wYear), 2026);
    CHECK_EQ(static_cast<int>(st.wMonth), 10);
    CHECK_EQ(static_cast<int>(st.wSecond), 30);
    CHECK(ParseUtcIso(L"2028-02-29T00:00:00Z", nullptr));
    CHECK(!ParseUtcIso(L"2026-02-29T00:00:00Z", nullptr));   // not a leap year
    CHECK(!ParseUtcIso(L"2026-10-20 08:15:30", nullptr));
    CHECK(!ParseUtcIso(L"2026-10-20T08:15:30+02:00", nullptr));
    CHECK(!ParseUtcIso(L"2026-13-01T00:00:00Z", nullptr));
    CHECK(!ParseUtcIso(L"2026-10-20T24:00:00Z", nullptr));
    CHECK(!ParseUtcIso(L"", nullptr));
    CHECK(ParseUtcIso(NowUtcIso(), nullptr));

    // Midday UTC is the same date in every time zone from -11 to +11 hours.
    CHECK_EQ(HistoryDateText(L"2026-10-20T12:00:00Z", true), std::wstring(L"20 Oct 2026"));
    CHECK_EQ(HistoryDateText(L"2019-01-05T12:00:00Z", false), std::wstring(L"5 Jan 2019"));   // another year keeps it
    CHECK_EQ(HistoryDateText(L"not a date", true), std::wstring(L""));
    // This year's dates leave the year out when asked to.
    SYSTEMTIME today;
    GetLocalTime(&today);
    std::wstring nowShort = HistoryDateText(NowUtcIso(), false);
    CHECK(!nowShort.empty());
    CHECK(nowShort.find(std::to_wstring(today.wYear)) == std::wstring::npos);
    CHECK(HistoryDateText(NowUtcIso(), true).find(std::to_wstring(today.wYear)) != std::wstring::npos);
    CHECK_EQ(HistoryDateTimeText(L"2026-10-20T12:00:00Z").size(), static_cast<size_t>(16));

    std::vector<std::wstring> s = CatalogIds(true);
    std::vector<std::wstring> u = CatalogIds(false);
    REQUIRE(s.size() >= 3);
    REQUIRE(!u.empty());
    AuditRecord prev = Record(L"2026-10-20T12:00:00Z", 58, { { s[0], CHECK_FAIL }, { s[1], CHECK_PASS }, { u[0], CHECK_PASS } });
    AuditRecord cur = Record(L"2026-10-22T12:00:00Z", 64,
        { { s[0], CHECK_PASS }, { s[1], CHECK_WARNING }, { s[2], CHECK_FAIL }, { u[0], CHECK_WARNING } });
    AuditComparison c = CompareWithPrevious(cur, prev);

    // Score line: sign and date; "20 Oct" or "20 Oct 2026" depending on the year now.
    std::wstring line = HistoryScoreLine(c);
    CHECK(line.rfind(L"+6 since 20 Oct", 0) == 0);
    AuditComparison down = c;
    down.scoreChange = -3;
    CHECK(HistoryScoreLine(down).rfind(L"-3 since 20 Oct", 0) == 0);
    AuditComparison even = c;
    even.scoreChange = 0;
    CHECK(HistoryScoreLine(even).rfind(L"same score as 20 Oct", 0) == 0);
    AuditComparison same = CompareWithPrevious(prev, prev);
    CHECK(HistoryScoreLine(same).rfind(L"no change since 20 Oct", 0) == 0);
    CHECK_EQ(HistoryScoreLine(AuditComparison()), std::wstring(L"first audit"));

    // The paragraph names every change with its title.
    std::wstring para = BuildHistoryParagraph(c);
    CHECK(para.find(L"Since the last audit (20 Oct 2026): score 58 -> 64 (+6).") != std::wstring::npos);
    CHECK(para.find(L"Fixed 1: " + TitleOf(s[0]) + L" (FAIL -> PASS)") != std::wstring::npos);
    CHECK(para.find(L"New problems 1:") != std::wstring::npos);
    CHECK(para.find(TitleOf(s[1]) + L" (PASS -> WARNING)") != std::wstring::npos);
    CHECK(para.find(L"New checks in this version 1: " + TitleOf(s[2]) + L" (FAIL)") != std::wstring::npos);
    CHECK(para.find(L"Recent activity, not scored, 1: " + TitleOf(u[0]) + L" (PASS -> WARNING)") != std::wstring::npos);
    CHECK(para.find(L"\n") == std::wstring::npos);   // one paragraph
    CHECK(BuildHistoryParagraph(AuditComparison()).find(L"first audit") != std::wstring::npos);
    CHECK(BuildHistoryParagraph(same).find(L"no change") != std::wstring::npos);

    // The findings window note for each kind, and none for an unchanged check.
    CHECK_EQ(HistoryNoteForCheck(c, s[0]), std::wstring(L"Fixed since the last audit (20 Oct 2026): it was FAIL."));
    CHECK_EQ(HistoryNoteForCheck(c, s[1]), std::wstring(L"New problem since the last audit (20 Oct 2026): it was PASS."));
    CHECK(HistoryNoteForCheck(c, s[2]).rfind(L"New check in this version", 0) == 0);
    CHECK(HistoryNoteForCheck(c, u[0]).find(L"not scored") != std::wstring::npos);
    CHECK_EQ(HistoryNoteForCheck(same, s[0]), std::wstring(L""));
    CHECK_EQ(HistoryNoteForCheck(AuditComparison(), s[0]), std::wstring(L""));

    // Every text is plain ASCII.
    for (const std::wstring& t : { line, para, HistoryNoteForCheck(c, s[0]) }) {
        for (wchar_t ch : t) CHECK(ch < 0x80);
    }

    // The table: the last 20 of 25, oldest first.
    std::vector<AuditRecord> records;
    for (int i = 0; i < 25; ++i) records.push_back(Record(Day(i), 40 + i, { { s[0], CHECK_PASS } }));
    std::wstring table = BuildHistoryTable(records);
    CHECK(table.find(L"(20 of 25 records)") != std::wstring::npos);
    CHECK(table.find(L"Score") != std::wstring::npos);
    CHECK(table.find(L"   64  ") != std::wstring::npos);    // the newest score
    CHECK(table.find(L"   44  ") == std::wstring::npos);    // record 4 is too old to show
    CHECK(table.find(L"   45  ") != std::wstring::npos);    // record 5 is the oldest shown
    CHECK_EQ(CountLines(table), static_cast<size_t>(1 + 2 + 20));
    CHECK_EQ(BuildHistoryTable({}), std::wstring(L"No audit history yet.\n"));
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------
static ReportData ReportWithHistory(const AuditComparison& c, const std::vector<AuditRecord>& records)
{
    ReportData d;
    FillReportHost(d, false);
    d.hasAudit = true;
    for (const CheckInfo& info : GetCheckCatalog()) {
        SecurityCheckResult r = MakeCheckResult(info.id);
        r.status = CHECK_PASS;
        r.detail = L"fine";
        d.audit.push_back(r);
        if (d.audit.size() >= 6) break;
    }
    d.score = ComputeHardeningScore(d.audit);
    d.hasHistory = true;
    d.history = c;
    d.historyRecords = records;
    return d;
}

static void CheckSelfContained(const std::wstring& html)
{
    std::wstring lower = ToLowerW(html);
    for (const wchar_t* bad : { L"http://", L"https://", L"src=\"//", L"href=\"//", L"url(", L"@import", L"<link", L"<img",
                                L"<iframe", L"<object", L"<embed", L"<base" }) {
        if (lower.find(bad) != std::wstring::npos) tf::Fail(__FILE__, __LINE__, "HTML report contains " + tf::Narrow(bad));
    }
}

TEST(History_HtmlSection)
{
    std::vector<std::wstring> s = CatalogIds(true);
    REQUIRE(s.size() >= 3);
    std::vector<AuditRecord> records = {
        Record(L"2026-10-18T12:00:00Z", 52, { { s[0], CHECK_FAIL }, { s[1], CHECK_PASS } }),
        Record(L"2026-10-20T12:00:00Z", 58, { { s[0], CHECK_FAIL }, { s[1], CHECK_WARNING } }),
        Record(L"2026-10-22T12:00:00Z", 64, { { s[0], CHECK_PASS }, { s[1], CHECK_FAIL } }),
    };
    AuditComparison c = CompareWithPrevious(records[2], records[1]);
    std::wstring html = BuildHtmlReport(ReportWithHistory(c, records));

    CHECK(html.find(L"Since your last audit") != std::wstring::npos);
    CHECK(html.find(L"<b class=\"pass\">up 6</b> from 58 at the last audit on 20 Oct 2026") != std::wstring::npos);
    CHECK(html.find(L"Fixed (1)</h3><ul><li>" + HtmlEscape(TitleOf(s[0])) + L" <span class=\"sev\">FAIL to PASS") != std::wstring::npos);
    CHECK(html.find(L"Worse (1)</h3><ul><li>" + HtmlEscape(TitleOf(s[1])) + L" <span class=\"sev\">WARNING to FAIL") != std::wstring::npos);
    // The chart: inline SVG with three points, a title and a text alternative.
    CHECK(html.find(L"<svg class=\"trend\"") != std::wstring::npos);
    CHECK(html.find(L"role=\"img\" aria-labelledby=\"trend-t trend-d\"") != std::wstring::npos);
    CHECK(html.find(L"<title id=\"trend-t\">Hardening score over the last 3 audits</title>") != std::wstring::npos);
    CHECK(html.find(L"<desc id=\"trend-d\">Oldest first: 52 on 18 Oct 2026, 58 on 20 Oct 2026, 64 on 22 Oct 2026.</desc>") != std::wstring::npos);
    CHECK(html.find(L"<polyline class=\"line\"") != std::wstring::npos);
    size_t dots = 0;
    for (size_t p = html.find(L"<circle class=\"dot\""); p != std::wstring::npos; p = html.find(L"<circle class=\"dot\"", p + 1)) ++dots;
    CHECK_EQ(dots, static_cast<size_t>(3));
    CHECK(html.find(L"The same scores as a table") != std::wstring::npos);
    // Drawn with the report's colours, so light and dark both work.
    CHECK(html.find(L".trend .line{fill:none;stroke:var(--accent)") != std::wstring::npos);
    CHECK(html.find(L"<script") == html.rfind(L"<script"));   // no extra script for the chart
    CheckSelfContained(html);
    for (wchar_t bad : { L'\x2013', L'\x2014', L'\x2018', L'\x2019', L'\x201C', L'\x201D' }) {
        CHECK(html.find(bad) == std::wstring::npos);
    }

    // The chart's y positions follow the scores: 0 is the bottom line, 100 the top.
    std::wstring svg = BuildHistoryChartSvg({ Record(Day(1), 0, {}), Record(Day(2), 100, {}) });
    CHECK(svg.find(L"points=\"40.0,180.0 624.0,14.0\"") != std::wstring::npos);
    CHECK(BuildHistoryChartSvg({ Record(Day(1), 50, {}) }).empty());

    // First audit: says so, no chart.
    std::wstring first = BuildHtmlReport(ReportWithHistory(AuditComparison(), { records[0] }));
    CHECK(first.find(L"Since your last audit") != std::wstring::npos);
    CHECK(first.find(L"first audit recorded on this PC") != std::wstring::npos);
    CHECK(first.find(L"<svg class=\"trend\"") == std::wstring::npos);
    CheckSelfContained(first);

    // History off: no section at all.
    ReportData off = ReportWithHistory(c, records);
    off.hasHistory = false;
    std::wstring none = BuildHtmlReport(off);
    CHECK(none.find(L"Since your last audit") == std::wstring::npos);
    CHECK(none.find(L"<svg class=\"trend\"") == std::wstring::npos);

    // Same state: no change, and the chart still shows the trend.
    AuditComparison same = CompareWithPrevious(records[2], records[2]);
    std::wstring unchanged = BuildHtmlReport(ReportWithHistory(same, records));
    CHECK(unchanged.find(L"No change since the last audit") != std::wstring::npos);
    CHECK(unchanged.find(L"<svg class=\"trend\"") != std::wstring::npos);
}

TEST(History_JsonObject)
{
    std::vector<std::wstring> s = CatalogIds(true);
    std::vector<std::wstring> u = CatalogIds(false);
    REQUIRE(s.size() >= 6);
    REQUIRE(!u.empty());
    AuditRecord prev = Record(L"2026-10-20T12:00:00Z", 58,
        { { s[0], CHECK_FAIL }, { s[1], CHECK_PASS }, { s[2], CHECK_WARNING }, { s[3], CHECK_FAIL }, { u[0], CHECK_PASS } });
    AuditRecord cur = Record(L"2026-10-22T12:00:00Z", 61,
        { { s[0], CHECK_PASS }, { s[1], CHECK_FAIL }, { s[2], CHECK_FAIL }, { s[3], CHECK_WARNING }, { s[4], CHECK_FAIL },
          { u[0], CHECK_WARNING } });
    AuditComparison c = CompareWithPrevious(cur, prev);
    std::wstring json = BuildJsonReport(ReportWithHistory(c, { prev, cur }));

    JsonCheck check(json);
    bool ok = check.Valid();
    if (!ok) tf::Fail(__FILE__, __LINE__, "JSON report invalid: " + tf::Narrow(check.error));
    CHECK_EQ(check.KeyCount(L"history"), 1);
    CHECK(json.find(L"phantomrecon.report/1") != std::wstring::npos);   // schema name unchanged

    JsonValue root;
    std::string why;
    REQUIRE(ParseJson(WideToUtf8(json), root, why));
    const JsonValue* h = root.Find("history");
    REQUIRE(h && h->IsObject());
    REQUIRE(h->Find("firstAudit"));
    CHECK(!h->Find("firstAudit")->boolean);
    const JsonValue* p = h->Find("previous");
    REQUIRE(p && p->IsObject());
    CHECK_EQ(p->Find("date")->text, std::string("2026-10-20T12:00:00Z"));
    CHECK(p->Find("score")->number == 58.0);
    CHECK(h->Find("score")->number == 61.0);
    CHECK(h->Find("scoreChange")->number == 3.0);
    auto ids = [&](const char* key) {
        std::vector<std::wstring> out;
        const JsonValue* a = h->Find(key);
        if (a && a->IsArray()) {
            for (const JsonValue& item : a->items) out.push_back(Utf8ToWide(item.text));
        }
        return out;
    };
    CHECK(ids("fixed") == (std::vector<std::wstring>{ s[0] }));
    CHECK(ids("newProblems") == (std::vector<std::wstring>{ s[1] }));
    CHECK(ids("worse") == (std::vector<std::wstring>{ s[2] }));
    CHECK(ids("better") == (std::vector<std::wstring>{ s[3] }));
    CHECK(ids("newChecks") == (std::vector<std::wstring>{ s[4] }));
    CHECK(ids("activity") == (std::vector<std::wstring>{ u[0] }));

    // First audit: previous is null.
    std::wstring first = BuildJsonReport(ReportWithHistory(AuditComparison(), { prev }));
    CHECK(JsonCheck(first).Valid());
    REQUIRE(ParseJson(WideToUtf8(first), root, why));
    REQUIRE(root.Find("history"));
    CHECK(root.Find("history")->Find("firstAudit")->boolean);
    CHECK(root.Find("history")->Find("previous")->IsNull());

    // History off: no member.
    ReportData off = ReportWithHistory(c, { prev, cur });
    off.hasHistory = false;
    JsonCheck offCheck(BuildJsonReport(off));
    CHECK(offCheck.Valid());
    CHECK_EQ(offCheck.KeyCount(L"history"), 0);
}

// ---------------------------------------------------------------------------
// The console program
// ---------------------------------------------------------------------------
TEST(History_CliOptions)
{
    CHECK(ParseCliArguments({ L"--history" }).showHistory);
    CHECK(ParseCliArguments({ L"--history" }).error.empty());
    CHECK(ParseCliArguments({ L"--audit", L"--no-history" }).noHistory);
    CHECK(!ParseCliArguments({ L"--no-history" }).error.empty());              // nothing to do
    CHECK(!ParseCliArguments({ L"--history", L"--no-history" }).error.empty());
    CHECK(!ParseCliArguments({ L"--history", L"--report", L"r.html" }).error.empty());   // a report needs an audit
    CHECK(CliUsageText().find(L"--history") != std::wstring::npos);
    CHECK(CliUsageText().find(L"--no-history") != std::wstring::npos);

    // --history prints the last 20 of the file's records and exits 0.
    std::wstring path = tf::TestDir() + L"cli.jsonl";
    std::vector<AuditRecord> records;
    for (int i = 0; i < 25; ++i) records.push_back(Record(Day(i), 30 + i, { { L"net.llmnr", i % 2 ? CHECK_PASS : CHECK_FAIL } }));
    REQUIRE(SaveAuditHistory(path, records));
    std::wstring captured;
    CliEnvironment env;
    env.out = [&](const std::wstring& t) { captured += t; };
    env.historyPath = path;
    CHECK_EQ(RunCli(ParseCliArguments({ L"--history" }), env), 0);
    CHECK(captured.find(L"(20 of 25 records)") != std::wstring::npos);
    CHECK(captured.find(L"   54  ") != std::wstring::npos);
    CHECK(captured.find(L"   34  ") == std::wstring::npos);
    // Even with --quiet: it is what was asked for.
    captured.clear();
    CHECK_EQ(RunCli(ParseCliArguments({ L"--history", L"--quiet" }), env), 0);
    CHECK(captured.find(L"(20 of 25 records)") != std::wstring::npos);

    // No file yet: says so, still exit 0, and nothing is created.
    captured.clear();
    env.historyPath = tf::TestDir() + L"missing.jsonl";
    CHECK_EQ(RunCli(ParseCliArguments({ L"--history" }), env), 0);
    CHECK(captured.find(L"No audit history yet.") != std::wstring::npos);
    CHECK(!FileExists(env.historyPath));
}

// Two real audits through the console program with history on, then one with it off.
TEST(History_CliAuditRecordsAndOff)
{
    std::wstring path = tf::TestDir() + L"audit-history.jsonl";
    std::wstring json1 = tf::TestDir() + L"a1.json", json2 = tf::TestDir() + L"a2.json";
    std::wstring html2 = tf::TestDir() + L"a2.html", text2 = tf::TestDir() + L"a2.txt";
    std::wstring captured;
    CliEnvironment env;
    env.out = [&](const std::wstring& t) { captured += t; };
    env.defaultBaselinePath = tf::TestDir() + L"none.prbl";
    env.defaultReportsDir = tf::TestDir() + L"reports";
    env.historyPath = path;

    int code1 = RunCli(ParseCliArguments({ L"--audit", L"--json", json1 }), env);
    CHECK(code1 == 0 || code1 == 1);
    REQUIRE(FileExists(path));
    CHECK_EQ(CountLines(ReadAll(path)), static_cast<size_t>(1));
    CHECK(captured.find(L"this is the first audit recorded on this PC") != std::wstring::npos);
    JsonValue root;
    std::string why;
    REQUIRE(ParseJson(WideToUtf8(ReadAll(json1)), root, why));
    REQUIRE(root.Find("history"));
    CHECK(root.Find("history")->Find("firstAudit")->boolean);

    captured.clear();
    int code2 = RunCli(ParseCliArguments({ L"--audit", L"--json", json2, L"--report", html2, L"--text", text2 }), env);
    CHECK(code2 == 0 || code2 == 1);
    CHECK(captured.find(L"Since the last audit (") != std::wstring::npos);
    REQUIRE(ParseJson(WideToUtf8(ReadAll(json2)), root, why));
    const JsonValue* h = root.Find("history");
    REQUIRE(h);
    CHECK(!h->Find("firstAudit")->boolean);
    REQUIRE(h->Find("previous") && h->Find("previous")->IsObject());
    // Two audits a few seconds apart: usually the same state (one line). Recent-activity
    // checks may see a new event in between, which makes a second line; never more.
    size_t lines = CountLines(ReadAll(path));
    CHECK(lines == 1 || lines == 2);
    if (h->Find("sameState")->boolean) CHECK_EQ(lines, static_cast<size_t>(1));
    std::wstring html = ReadAll(html2);
    CHECK(html.find(L"Since your last audit") != std::wstring::npos);
    CHECK(html.find(L"first audit recorded") == std::wstring::npos);
    CHECK(ReadAll(text2).find(L"Since the last audit (") != std::wstring::npos);
    std::wstring historyText = ReadAll(path);

    // Off: the file is neither read nor written, and the reports have no history part.
    captured.clear();
    std::wstring json3 = tf::TestDir() + L"a3.json";
    RunCli(ParseCliArguments({ L"--audit", L"--no-history", L"--json", json3 }), env);
    CHECK_EQ(ReadAll(path), historyText);
    CHECK(captured.find(L"Since the last audit") == std::wstring::npos);
    CHECK(captured.find(L"first audit") == std::wstring::npos);
    JsonCheck offCheck(ReadAll(json3));
    CHECK(offCheck.Valid());
    CHECK_EQ(offCheck.KeyCount(L"history"), 0);

    // The history went only where it was pointed: nothing in the program's data folder.
    CHECK(!FileExists(tf::DataDir() + AuditHistoryFileName()));
    CHECK(!FileExists(AppFilePath(AuditHistoryFileName())));
}

// A CliEnvironment with no history location (what every other test uses) keeps no
// history: an --audit run writes nothing and the reports have no history part.
TEST(History_NoLocationNoHistory)
{
    std::wstring json = tf::TestDir() + L"bare.json";
    CliEnvironment bare;
    bare.out = [](const std::wstring&) {};
    bare.defaultBaselinePath = tf::TestDir() + L"none.prbl";
    bare.defaultReportsDir = tf::TestDir() + L"reports";
    RunCli(ParseCliArguments({ L"--audit", L"--quiet", L"--json", json }), bare);
    JsonCheck check(ReadAll(json));
    CHECK(check.Valid());
    CHECK_EQ(check.KeyCount(L"history"), 0);
    CHECK(!FileExists(tf::DataDir() + AuditHistoryFileName()));
    CHECK(!FileExists(tf::TestDir() + AuditHistoryFileName()));
}
