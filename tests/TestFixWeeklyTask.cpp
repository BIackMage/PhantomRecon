// Review fixes for the weekly check-up's scheduled task (ScheduledScan.cpp).

#include "TestFramework.h"

#include "ScheduledScan.h"

#include <string>
#include <vector>

// Task Scheduler expands %NAME% in a task's program, arguments and working folder when
// it starts the task (seen on Windows 11: a task given --findings-md "...\a%OS%b\f.md"
// wrote ...\aWindows_NTb\f.md). A path with two % signs could therefore name another
// file at run time than the one the user was shown, so the plan refuses it. One % sign
// alone cannot form a name and stays allowed.
TEST(FixWeekly_PercentPairInAPathIsRefused)
{
    const std::wstring exe = L"D:\\apps\\Phantom Recon\\PhantomReconCli.exe";
    const std::wstring baseline = L"D:\\apps\\Phantom Recon\\phantom_recon_baseline.prbl";
    const std::wstring reports = L"D:\\apps\\Phantom Recon\\reports";

    struct Case {
        std::wstring exe, baseline, reports;
        std::wstring badPath;
    };
    std::vector<Case> refused = {
        { L"D:\\apps\\%OS%\\PhantomReconCli.exe", baseline, reports, L"D:\\apps\\%OS%\\PhantomReconCli.exe" },
        { exe, L"D:\\data\\a%USERNAME%b\\demo.prbl", reports, L"D:\\data\\a%USERNAME%b\\demo.prbl" },
        { exe, baseline, L"D:\\reports\\%Q1%", L"D:\\reports\\%Q1%" },
        { exe, baseline, L"D:\\reports\\50% off, 20% more", L"D:\\reports\\50% off, 20% more" },
    };
    for (const Case& c : refused) {
        WeeklyTaskPlan plan = PlanWeeklyTask(c.exe, c.baseline, c.reports, true, false);
        if (plan.ok) tf::Fail(__FILE__, __LINE__, "a task was planned for a path with two % signs: " + tf::Narrow(c.badPath));
        CHECK(plan.commandLine.empty());
        CHECK(plan.arguments.empty());
        CHECK(plan.error.find(c.badPath) != std::wstring::npos);
        CHECK(plan.error.find(L"%") != std::wstring::npos);
    }

    // One % sign: no name can form, the task is planned as usual.
    WeeklyTaskPlan single = PlanWeeklyTask(exe, baseline, L"D:\\reports\\100% done", true, false);
    CHECK(single.ok);
    CHECK(single.arguments.find(L"D:\\reports\\100% done\\weekly_report.html") != std::wstring::npos);

    // Portable mode still wins over the path check.
    WeeklyTaskPlan portable = PlanWeeklyTask(exe, baseline, L"D:\\reports\\%Q1%", true, true);
    CHECK(!portable.ok);
    CHECK(portable.error.find(L"Portable mode") != std::wstring::npos);
}
