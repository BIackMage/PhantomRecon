// The weekly check-up: the scheduled task's command line (normal, no history,
// portable, a 1.0.0 task), the notification text for each kind of week, the
// --notify-on-change decision, and the console options that go with them.

#include "TestFramework.h"

#include "../AuditHistory.h"
#include "../Baseline.h"
#include "../CheckCatalog.h"
#include "../CliNotification.h"
#include "../CliRunner.h"
#include "../FileIO.h"
#include "../JsonReader.h"
#include "../ScheduledScan.h"
#include "../StringConv.h"

#include <windows.h>
#include <shellapi.h>
#include <map>
#include <string>
#include <vector>

#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const wchar_t kPrevTime[] = L"2026-10-20T12:00:00Z";
static const wchar_t kNowTime[] = L"2026-10-27T12:00:00Z";

static std::vector<std::wstring> WeeklyCatalogIds(bool scored)
{
    std::vector<std::wstring> ids;
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (info.scored == scored) ids.push_back(info.id);
    }
    return ids;
}

static AuditRecord WeeklyRecord(const std::wstring& when, int score, const std::map<std::wstring, std::wstring>& statuses)
{
    AuditRecord r;
    r.firstSeen = when;
    r.lastSeen = when;
    r.version = L"1.0.0";
    r.score = score;
    r.label = HardeningLabel(score);
    r.statuses = statuses;
    return r;
}

// "since 20 Oct" (or "20 Oct 2026" in another year), as the notification writes it.
static std::wstring PrevDate()
{
    return HistoryDateText(kPrevTime, false);
}

// An audit with history, compared with the given previous record.
static NotificationFacts AuditFacts(const AuditRecord& previous, const AuditRecord& current, int exitCode)
{
    NotificationFacts f;
    f.exitCode = exitCode;
    f.hasAudit = true;
    f.score = current.score;
    f.hasHistory = true;
    f.comparison = CompareWithPrevious(current, previous);
    return f;
}

static void AddCalmScan(NotificationFacts& f)
{
    f.hasScan = true;
    f.scanPrograms = 40;
}

static bool IsAscii(const std::wstring& text)
{
    for (wchar_t ch : text) {
        if (ch >= 0x80) return false;
    }
    return true;
}

// Split a command line the way the console program receives it.
static std::vector<std::wstring> SplitCommandLine(const std::wstring& commandLine)
{
    std::vector<std::wstring> args;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(commandLine.c_str(), &argc);
    if (!argv) return args;
    for (int i = 0; i < argc; ++i) args.push_back(argv[i]);
    LocalFree(argv);
    return args;
}

static std::wstring ReadWhole(const std::wstring& path)
{
    std::wstring text;
    ReadTextFile(path, text);
    return text;
}

// ---------------------------------------------------------------------------
// The task's command line
// ---------------------------------------------------------------------------
TEST(Weekly_TaskCommandLine)
{
    const std::wstring exe = L"D:\\apps\\Phantom Recon\\PhantomReconCli.exe";
    const std::wstring baseline = L"D:\\apps\\Phantom Recon\\phantom_recon_baseline.prbl";
    const std::wstring reports = L"D:\\apps\\Phantom Recon\\reports";
    const std::wstring expectedArgs =
        L"--fast --audit --baseline \"D:\\apps\\Phantom Recon\\phantom_recon_baseline.prbl\" "
        L"--report \"D:\\apps\\Phantom Recon\\reports\\weekly_report.html\" "
        L"--csv \"D:\\apps\\Phantom Recon\\reports\\weekly_scan.csv\" --notify-on-change --quiet";

    // Normal mode, history on: the exact command Task Scheduler gets.
    WeeklyTaskPlan plan = PlanWeeklyTask(exe, baseline, reports, true, false);
    CHECK(plan.ok);
    CHECK(plan.error.empty());
    CHECK_EQ(plan.exePath, exe);
    CHECK_EQ(plan.arguments, expectedArgs);
    CHECK_EQ(plan.commandLine, L"\"" + exe + L"\" " + expectedArgs);
    CHECK_EQ(WeeklyScanArguments(baseline, reports, true), expectedArgs);
    CHECK_EQ(WeeklyTaskCommandLine(exe, expectedArgs), plan.commandLine);

    // The console program reads it back as one Fast Scan plus the audit, quiet, notifying on change.
    std::vector<std::wstring> argv = SplitCommandLine(plan.commandLine);
    REQUIRE(argv.size() == 11);
    CHECK_EQ(argv[0], exe);
    CliOptions o = ParseCliArguments(std::vector<std::wstring>(argv.begin() + 1, argv.end()));
    CHECK(o.error.empty());
    CHECK(o.fastScan);
    CHECK(o.audit);
    CHECK(o.notifyOnChange);
    CHECK(!o.notify);
    CHECK(o.quiet);
    CHECK(!o.noHistory);
    CHECK_EQ(o.baselinePath, baseline);
    CHECK_EQ(o.htmlPath, reports + L"\\weekly_report.html");
    CHECK_EQ(o.csvPath, reports + L"\\weekly_scan.csv");

    // History off in the settings: the task keeps none either.
    WeeklyTaskPlan off = PlanWeeklyTask(exe, baseline, reports, false, false);
    CHECK(off.ok);
    CHECK_EQ(off.arguments, expectedArgs + L" --no-history");
    std::vector<std::wstring> offArgv = SplitCommandLine(off.commandLine);
    REQUIRE(offArgv.size() == 12);
    CliOptions offOptions = ParseCliArguments(std::vector<std::wstring>(offArgv.begin() + 1, offArgv.end()));
    CHECK(offOptions.error.empty());
    CHECK(offOptions.noHistory);
    CHECK(offOptions.audit);

    // A reports folder given with a trailing backslash: no doubled backslash and no
    // escaped closing quote.
    WeeklyTaskPlan slash = PlanWeeklyTask(exe, baseline, reports + L"\\", true, false);
    CHECK_EQ(slash.arguments, expectedArgs);

    // Portable mode: no task, no command line, and the reason.
    WeeklyTaskPlan portable = PlanWeeklyTask(exe, baseline, reports, true, true);
    CHECK(!portable.ok);
    CHECK(portable.error.find(L"Portable mode") != std::wstring::npos);
    CHECK(portable.commandLine.empty());
    CHECK(portable.arguments.empty());

    // Nothing to run or nothing to compare with: refused too.
    CHECK(!PlanWeeklyTask(L"", baseline, reports, true, false).ok);
    CHECK(!PlanWeeklyTask(exe, L"", reports, true, false).ok);

    // A task created by 1.0.0 (Fast Scan only, --notify) still parses and runs as before.
    std::vector<std::wstring> old = SplitCommandLine(
        L"\"D:\\apps\\PhantomReconCli.exe\" --fast --baseline \"D:\\apps\\phantom_recon_baseline.prbl\" "
        L"--report \"D:\\apps\\reports\\weekly_report.html\" --csv \"D:\\apps\\reports\\weekly_scan.csv\" --notify --quiet");
    REQUIRE(old.size() == 10);
    CliOptions oldOptions = ParseCliArguments(std::vector<std::wstring>(old.begin() + 1, old.end()));
    CHECK(oldOptions.error.empty());
    CHECK(oldOptions.fastScan);
    CHECK(oldOptions.notify);
    CHECK(!oldOptions.notifyOnChange);
    CHECK(!oldOptions.audit);
}

// ---------------------------------------------------------------------------
// The notification text
// ---------------------------------------------------------------------------
TEST(Weekly_NotificationText)
{
    std::vector<std::wstring> s = WeeklyCatalogIds(true);
    std::vector<std::wstring> u = WeeklyCatalogIds(false);
    REQUIRE(s.size() >= 3);
    REQUIRE(u.size() >= 2);
    const std::wstring d = PrevDate();
    REQUIRE(!d.empty());
    const std::wstring calmScan = L" Scan: nothing new, changed or missing.";

    // First audit recorded: the score and the scan only.
    {
        NotificationFacts f;
        f.hasAudit = true;
        f.score = 65;
        f.hasHistory = true;
        AddCalmScan(f);
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: all clear"));
        CHECK_EQ(n.text, L"Hardening score 65/100." + calmScan);
    }
    // No change since the state was first seen.
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 65, { { s[0], CHECK_PASS }, { s[1], CHECK_FAIL } });
        AuditRecord cur = prev;
        cur.firstSeen = cur.lastSeen = kNowTime;
        NotificationFacts f = AuditFacts(prev, cur, 1);
        AddCalmScan(f);
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: please review"));   // the FAIL is still there
        CHECK_EQ(n.text, L"No change since " + d + L" (score 65)." + calmScan);
    }
    // New problems and a lower score are the headline; the scan follows.
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 65, { { s[0], CHECK_PASS }, { s[1], CHECK_PASS }, { s[2], CHECK_FAIL } });
        AuditRecord cur = WeeklyRecord(kNowTime, 61, { { s[0], CHECK_FAIL }, { s[1], CHECK_WARNING }, { s[2], CHECK_FAIL } });
        NotificationFacts f = AuditFacts(prev, cur, 1);
        f.hasScan = true;
        f.scanAdded = 1;
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: something got worse"));
        CHECK_EQ(n.text, L"2 new problems since " + d + L" (score 61, down 4). Open Phantom Recon to see them. "
                         L"Scan: 1 new, 0 changed, 0 missing.");
    }
    // One new problem and one check worse, same score.
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 60, { { s[0], CHECK_PASS }, { s[1], CHECK_WARNING } });
        AuditRecord cur = WeeklyRecord(kNowTime, 60, { { s[0], CHECK_WARNING }, { s[1], CHECK_FAIL } });
        CliNotification n = BuildCliNotification(AuditFacts(prev, cur, 1));
        CHECK_EQ(n.text, L"1 new problem and 1 check worse since " + d + L" (score 60). Open Phantom Recon to see them.");
    }
    // Score down with no check moving into a problem (a check new in this version fails).
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 65, { { s[0], CHECK_PASS } });
        AuditRecord cur = WeeklyRecord(kNowTime, 61, { { s[0], CHECK_PASS }, { s[1], CHECK_FAIL } });
        CliNotification n = BuildCliNotification(AuditFacts(prev, cur, 1));
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: something got worse"));
        CHECK_EQ(n.text, L"Score 61, down 4 since " + d + L". Open Phantom Recon to see why.");
    }
    // Only activity checks changed: one short sentence after "no new problems".
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 65, { { s[0], CHECK_PASS }, { u[0], CHECK_PASS }, { u[1], CHECK_PASS } });
        AuditRecord cur = WeeklyRecord(kNowTime, 65, { { s[0], CHECK_PASS }, { u[0], CHECK_WARNING }, { u[1], CHECK_PASS } });
        NotificationFacts f = AuditFacts(prev, cur, 0);
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: all clear"));
        CHECK_EQ(n.text, L"No new problems since " + d + L" (score 65). Recent activity changed in 1 unscored check.");
        cur.statuses[u[1]] = CHECK_WARNING;
        CHECK_EQ(NotificationAuditSentence(AuditFacts(prev, cur, 0)),
                 L"No new problems since " + d + L" (score 65). Recent activity changed in 2 unscored checks.");
    }
    // Fixed and better.
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 60, { { s[0], CHECK_FAIL }, { s[1], CHECK_FAIL } });
        AuditRecord cur = WeeklyRecord(kNowTime, 70, { { s[0], CHECK_PASS }, { s[1], CHECK_WARNING } });
        CHECK_EQ(BuildCliNotification(AuditFacts(prev, cur, 0)).text,
                 L"1 fixed and 1 check better since " + d + L" (score 70, up 10).");
    }
    // History off: the comparison is ignored, only the score is said.
    {
        AuditRecord prev = WeeklyRecord(kPrevTime, 65, { { s[0], CHECK_PASS } });
        AuditRecord cur = WeeklyRecord(kNowTime, 61, { { s[0], CHECK_FAIL } });
        NotificationFacts f = AuditFacts(prev, cur, 1);
        f.hasHistory = false;
        AddCalmScan(f);
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: please review"));
        CHECK_EQ(n.text, L"Hardening score 61/100." + calmScan);
    }
    // The scan failed (no baseline); the audit still reports.
    {
        NotificationFacts f;
        f.exitCode = 2;
        f.error = L"no usable baseline at D:\\apps\\demo.prbl. Take one with --baseline-scan first.";
        f.hasAudit = true;
        f.score = 65;
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.title, std::wstring(L"Phantom Recon: the run failed"));
        CHECK_EQ(n.text, std::wstring(L"Error: no usable baseline at D:\\apps\\demo.prbl. Take one with --baseline-scan first. "
                                      L"Hardening score 65/100."));
        // An error without a full stop gets one; exit code 2 without a message still says so.
        f.error = L"could not write D:\\apps\\r.html";
        f.hasAudit = false;
        CHECK_EQ(BuildCliNotification(f).text, std::wstring(L"Error: could not write D:\\apps\\r.html."));
        f.error.clear();
        CHECK_EQ(BuildCliNotification(f).text, std::wstring(L"Error: the run did not finish."));
    }
    // Scan sentences: a baseline, changes with high-risk files.
    {
        NotificationFacts f;
        f.hasScan = true;
        f.baselineScan = true;
        f.scanPrograms = 12;
        f.scanAdded = 12;
        CHECK_EQ(NotificationScanSentence(f), std::wstring(L"Baseline taken: 12 files."));
        f.baselineScan = false;
        f.scanAdded = 0;
        f.scanChanged = 2;
        f.scanMissing = 1;
        f.scanHighRisk = 1;
        CHECK_EQ(NotificationScanSentence(f), std::wstring(L"Scan: 0 new, 2 changed, 1 missing. 1 scored 7 or more."));
        CHECK_EQ(NotificationScanSentence(NotificationFacts()), std::wstring(L""));
        CHECK_EQ(NotificationAuditSentence(NotificationFacts()), std::wstring(L""));
    }
    // Within the balloon's limits, ASCII, and never empty.
    {
        NotificationFacts f;
        f.exitCode = 2;
        f.error = std::wstring(400, L'x');
        f.hasAudit = true;
        f.score = 50;
        CliNotification n = BuildCliNotification(f);
        CHECK_EQ(n.text.size(), kNotificationTextMaxChars);
        CHECK(n.text.compare(n.text.size() - 3, 3, L"...") == 0);
        CHECK(n.title.size() <= kNotificationTitleMaxChars);
        CHECK(IsAscii(n.text));
        // A surrogate pair at the cut is not split.
        f.error = std::wstring(244, L'y') + L"\xD83D\xDE00" + std::wstring(50, L'z');
        n = BuildCliNotification(f);
        CHECK(n.text.size() <= kNotificationTextMaxChars);
        CHECK(n.text[n.text.size() - 4] != 0xD83D);
        CHECK_EQ(BuildCliNotification(NotificationFacts()).text, std::wstring(L"Done."));
    }
}

// ---------------------------------------------------------------------------
// --notify-on-change: when to speak
// ---------------------------------------------------------------------------
TEST(Weekly_NotifyOnChangeDecisions)
{
    std::vector<std::wstring> s = WeeklyCatalogIds(true);
    std::vector<std::wstring> u = WeeklyCatalogIds(false);
    REQUIRE(s.size() >= 2);
    REQUIRE(!u.empty());
    AuditRecord base = WeeklyRecord(kPrevTime, 65, { { s[0], CHECK_PASS }, { s[1], CHECK_WARNING }, { u[0], CHECK_PASS } });
    auto with = [&](int score, const std::wstring& id, const std::wstring& status) {
        AuditRecord r = base;
        r.firstSeen = r.lastSeen = kNowTime;
        r.score = score;
        r.statuses[id] = status;
        return AuditFacts(base, r, 1);
    };
    auto onChange = [](const NotificationFacts& f) { return ShouldShowNotification(f, true); };

    NotificationFacts calm = with(65, s[0], CHECK_PASS);
    CHECK(calm.comparison.sameState);
    CHECK(!onChange(calm));
    CHECK(ShouldShowNotification(calm, false));                // --notify: always

    CHECK(onChange(with(61, s[0], CHECK_FAIL)));         // new problem (and lower score)
    CHECK(onChange(with(65, s[0], CHECK_WARNING)));      // new problem, same score
    CHECK(onChange(with(65, s[1], CHECK_FAIL)));         // worse
    CHECK(onChange(with(60, s[0], CHECK_PASS)));         // only a lower score
    CHECK(!onChange(with(65, u[0], CHECK_WARNING)));     // activity only
    CHECK(!onChange(with(70, s[1], CHECK_PASS)));        // fixed, higher score
    CHECK(!RunGotWorse(with(70, s[1], CHECK_PASS)));

    NotificationFacts first;                                   // first audit recorded
    first.hasAudit = true;
    first.hasHistory = true;
    first.score = 40;
    CHECK(!onChange(first));

    NotificationFacts off = with(50, s[0], CHECK_FAIL);        // history off: no comparison to judge
    off.hasHistory = false;
    CHECK(!onChange(off));

    NotificationFacts scan;
    scan.hasScan = true;
    CHECK(!onChange(scan));                               // nothing new or changed
    scan.scanMissing = 3;
    scan.scanHighRisk = 1;
    CHECK(!onChange(scan));                               // missing and old high-risk files only
    scan.scanAdded = 1;
    CHECK(onChange(scan));                                // a new file
    scan.scanAdded = 0;
    scan.scanChanged = 1;
    CHECK(onChange(scan));                                // a changed file
    scan.baselineScan = true;
    CHECK(!onChange(scan));                               // a baseline compares nothing

    NotificationFacts failed;
    failed.exitCode = 2;
    CHECK(onChange(failed));
    CHECK(RunFailed(failed));
    NotificationFacts errorOnly;
    errorOnly.exitCode = 1;
    errorOnly.error = L"could not write D:\\apps\\r.csv";
    CHECK(onChange(errorOnly));
}

// ---------------------------------------------------------------------------
// Console options
// ---------------------------------------------------------------------------
TEST(Weekly_NotifyArguments)
{
    CHECK(ParseCliArguments({ L"--audit", L"--notify-on-change" }).notifyOnChange);
    CHECK(ParseCliArguments({ L"--audit", L"--notify-on-change" }).error.empty());
    CHECK(ParseCliArguments({ L"--fast", L"--notify-on-change", L"--quiet" }).error.empty());
    CHECK(ParseCliArguments({ L"--full", L"D:\\apps", L"--notify" }).error.empty());
    CHECK(ParseCliArguments({ L"--diff", L"a.prbl", L"b.prbl", L"--notify-on-change" }).error.empty());
    CHECK(ParseCliArguments({ L"--baseline-scan", L"D:\\apps", L"--notify" }).error.empty());

    // Both at once: pick one.
    CHECK(!ParseCliArguments({ L"--audit", L"--notify", L"--notify-on-change" }).error.empty());
    // Nothing to report: each needs --audit or a scan.
    CHECK(!ParseCliArguments({ L"--notify-on-change" }).error.empty());
    CHECK(!ParseCliArguments({ L"--notify-on-change", L"--quiet" }).error.empty());
    for (const wchar_t* flag : { L"--notify", L"--notify-on-change" }) {
        CliOptions h = ParseCliArguments({ L"--history", flag });
        CHECK(h.error.find(L"needs") != std::wstring::npos || h.error.find(L"add --audit") != std::wstring::npos);
        CHECK(h.error.find(flag) != std::wstring::npos);
        CHECK(!ParseCliArguments({ L"--schedule-weekly", flag }).error.empty());
        CHECK(!ParseCliArguments({ L"--make-samples", L"D:\\demo", flag }).error.empty());
        CHECK(!ParseCliArguments({ L"--findings-md", L"D:\\f.md", flag }).error.empty());
        CHECK(!ParseCliArguments({ L"--unschedule-weekly", flag }).error.empty());
    }
    CHECK(ParseCliArguments({ L"--schedule-weekly", L"--no-history" }).error.empty());

    std::wstring usage = CliUsageText();
    CHECK(usage.find(L"--notify-on-change") != std::wstring::npos);
    CHECK(usage.find(L"need --audit or a scan") != std::wstring::npos);
    CHECK(usage.find(L"--fast and --audit") != std::wstring::npos);
    CHECK(IsAscii(usage));
}

// A failed run always notifies, with either option, and a parse error too.
TEST(Weekly_FailedRunNotifies)
{
    std::wstring title, text;
    int notifications = 0;
    CliEnvironment env;
    env.out = [](const std::wstring&) {};
    env.notify = [&](const std::wstring& t, const std::wstring& x) { title = t; text = x; ++notifications; };
    env.defaultBaselinePath = tf::TestDir() + L"weekly-missing.prbl";
    env.defaultReportsDir = tf::TestDir() + L"reports";

    CHECK_EQ(RunCli(ParseCliArguments({ L"--fast", L"--notify-on-change", L"--quiet" }), env), 2);
    CHECK_EQ(notifications, 1);
    CHECK_EQ(title, std::wstring(L"Phantom Recon: the run failed"));
    CHECK(text.rfind(L"Error: no usable baseline", 0) == 0);

    notifications = 0;
    CHECK_EQ(RunCli(ParseCliArguments({ L"--fast", L"--notify-on-change", L"--bogus" }), env), 2);
    CHECK_EQ(notifications, 1);
    CHECK(text.find(L"--bogus") != std::wstring::npos);
}

// --diff as a cheap scan: calm stays quiet, a new file speaks; --notify always speaks.
static BaselineEntry WeeklyEntry(const std::wstring& path)
{
    BaselineEntry e;
    e.path = path;
    e.fileSize = 100;
    e.md5 = L"0123456789abcdef0123456789abcdef";
    e.sha256 = std::wstring(64, L'c');
    e.signature = L"Unsigned";
    e.malwareScore = 1.0;
    return e;
}

TEST(Weekly_ScanNotifyOnChange)
{
    Baseline older, newer;
    older.AddEntry(WeeklyEntry(L"D:\\apps\\demo.exe"));
    newer.AddEntry(WeeklyEntry(L"D:\\apps\\demo.exe"));
    newer.AddEntry(WeeklyEntry(L"D:\\apps\\added.exe"));
    std::wstring oldPath = tf::TestDir() + L"weekly-old.prbl";
    std::wstring newPath = tf::TestDir() + L"weekly-new.prbl";
    REQUIRE(older.SaveToFile(oldPath));
    REQUIRE(newer.SaveToFile(newPath));

    std::wstring title, text, captured;
    int notifications = 0;
    CliEnvironment env;
    env.out = [&](const std::wstring& t) { captured += t; };
    env.notify = [&](const std::wstring& t, const std::wstring& x) { title = t; text = x; ++notifications; };

    CHECK_EQ(RunCli(ParseCliArguments({ L"--diff", oldPath, oldPath, L"--notify-on-change" }), env), 0);
    CHECK_EQ(notifications, 0);
    CHECK(captured.find(L"No notification: nothing got worse") != std::wstring::npos);

    CHECK_EQ(RunCli(ParseCliArguments({ L"--diff", oldPath, newPath, L"--notify-on-change", L"--quiet" }), env), 1);
    CHECK_EQ(notifications, 1);
    CHECK_EQ(title, std::wstring(L"Phantom Recon: something got worse"));
    CHECK_EQ(text, std::wstring(L"Scan: 1 new, 0 changed, 0 missing."));

    captured.clear();
    CHECK_EQ(RunCli(ParseCliArguments({ L"--diff", oldPath, oldPath, L"--notify" }), env), 0);
    CHECK_EQ(notifications, 2);
    CHECK_EQ(title, std::wstring(L"Phantom Recon: all clear"));
    CHECK_EQ(text, std::wstring(L"Scan: nothing new, changed or missing."));
    CHECK(captured.find(L"Notification: Phantom Recon: all clear") != std::wstring::npos);
}

// Real audits with history in the test folder: the first stays quiet, a seeded
// earlier record without one of today's problems makes the next one speak.
static std::vector<std::wstring> JsonIds(const JsonValue* history, const char* key)
{
    std::vector<std::wstring> ids;
    const JsonValue* a = history ? history->Find(key) : nullptr;
    if (a && a->IsArray()) {
        for (const JsonValue& item : a->items) ids.push_back(Utf8ToWide(item.text));
    }
    return ids;
}

TEST(Weekly_AuditNotifyOnChange)
{
    std::wstring path = tf::TestDir() + L"weekly-history.jsonl";
    std::wstring title, text, captured;
    int notifications = 0;
    CliEnvironment env;
    env.out = [&](const std::wstring& t) { captured += t; };
    env.notify = [&](const std::wstring& t, const std::wstring& x) { title = t; text = x; ++notifications; };
    env.defaultBaselinePath = tf::TestDir() + L"weekly-none.prbl";
    env.defaultReportsDir = tf::TestDir() + L"reports";
    env.historyPath = path;

    // First audit recorded: nothing to compare with, so nothing got worse.
    int code = RunCli(ParseCliArguments({ L"--audit", L"--notify-on-change" }), env);
    CHECK(code == 0 || code == 1);
    CHECK_EQ(notifications, 0);
    CHECK(captured.find(L"No notification") != std::wstring::npos);

    // Seed the history with one earlier record in which a problem of today was a PASS.
    std::vector<AuditRecord> records;
    REQUIRE(LoadAuditHistory(path, records));
    REQUIRE(records.size() == 1);
    AuditRecord seeded = records.back();
    std::wstring problemId;
    for (const auto& entry : seeded.statuses) {
        const CheckInfo* info = FindCheckInfo(entry.first);
        if (info && info->scored && (entry.second == CHECK_FAIL || entry.second == CHECK_WARNING)) {
            problemId = entry.first;
            break;
        }
    }
    if (problemId.empty()) {
        tf::Fail(__FILE__, __LINE__, "this PC has no FAIL or WARNING among the scored checks; the seeded test cannot run");
        return;
    }
    seeded.statuses[problemId] = CHECK_PASS;
    seeded.firstSeen = seeded.lastSeen = kPrevTime;
    REQUIRE(SaveAuditHistory(path, { seeded }));

    std::wstring json2 = tf::TestDir() + L"weekly-a2.json";
    code = RunCli(ParseCliArguments({ L"--audit", L"--notify-on-change", L"--quiet", L"--json", json2 }), env);
    CHECK(code == 0 || code == 1);
    JsonValue root;
    std::string why;
    REQUIRE(ParseJson(WideToUtf8(ReadWhole(json2)), root, why));
    std::vector<std::wstring> newProblems = JsonIds(root.Find("history"), "newProblems");
    bool listed = false;
    for (const std::wstring& id : newProblems) listed = listed || id == problemId;
    CHECK(listed);
    CHECK_EQ(notifications, 1);
    CHECK_EQ(title, std::wstring(L"Phantom Recon: something got worse"));
    CHECK(text.find(L"new problem") != std::wstring::npos);
    CHECK(text.find(L"since " + PrevDate()) != std::wstring::npos);
    CHECK(text.find(L"Open Phantom Recon to see them.") != std::wstring::npos);

    // Again at once: it speaks exactly when the report says something got worse.
    std::wstring json3 = tf::TestDir() + L"weekly-a3.json";
    RunCli(ParseCliArguments({ L"--audit", L"--notify-on-change", L"--quiet", L"--json", json3 }), env);
    REQUIRE(ParseJson(WideToUtf8(ReadWhole(json3)), root, why));
    const JsonValue* h = root.Find("history");
    REQUIRE(h && h->Find("scoreChange"));
    bool worse = !JsonIds(h, "newProblems").empty() || !JsonIds(h, "worse").empty() || h->Find("scoreChange")->number < 0;
    CHECK_EQ(notifications, worse ? 2 : 1);
}
