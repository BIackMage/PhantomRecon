#pragma once

#include <string>

// ---------------------------------------------------------------------------
// ScheduledScan: one visible, user-level Task Scheduler entry (the weekly
// check-up). Every Sunday it runs the console program as the signed-in user,
// never elevated: a Fast Scan against the baseline plus the security audit, an
// HTML report and a CSV, and a desktop notification only when something got
// worse (--notify-on-change). The audit adds a record to the audit history unless
// history is off, in which case the task gets --no-history.
//
// Created only when the user asks for it from the menu or the command line,
// removable the same way. Never created in portable mode, never created without a
// baseline that loads. Registering again replaces the task of the same name (so a
// task made by 1.0.0, which ran only the Fast Scan with --notify, becomes the new
// one); a 1.0.0 task left alone keeps working, since its arguments are still valid.
// ---------------------------------------------------------------------------

std::wstring WeeklyScanTaskName();

// The arguments the task runs (exposed for tests).
std::wstring WeeklyScanArguments(const std::wstring& baselinePath, const std::wstring& reportsDir, bool auditHistory);

// The task as it would be created. Pure: no files read. Refused in portable mode, and
// when a path holds two % signs (Task Scheduler would expand %NAME% in it at run time).
struct WeeklyTaskPlan {
    bool         ok = false;
    std::wstring error;          // why no task can be made (portable mode, no program)
    std::wstring exePath;
    std::wstring arguments;
    std::wstring commandLine;    // "exePath" arguments: exactly what Task Scheduler runs
};

WeeklyTaskPlan PlanWeeklyTask(const std::wstring& exePath, const std::wstring& baselinePath, const std::wstring& reportsDir,
                              bool auditHistory, bool portable);

// "C:\x\PhantomReconCli.exe" plus " " plus the arguments.
std::wstring WeeklyTaskCommandLine(const std::wstring& exePath, const std::wstring& arguments);

// Refuses (false, reason in error, nothing created) when baselinePath is not a
// baseline that loads, since every weekly run would then fail, and in portable mode.
// commandLine receives the command the task runs.
bool RegisterWeeklyScan(const std::wstring& exePath, const std::wstring& baselinePath, const std::wstring& reportsDir,
                        bool auditHistory, std::wstring& commandLine, std::wstring& error);
bool RemoveWeeklyScan(std::wstring& error);
bool IsWeeklyScanRegistered();

// The program and arguments of the registered task. False when there is no task or
// its action cannot be read.
bool ReadWeeklyScanCommand(std::wstring& exePath, std::wstring& arguments);
