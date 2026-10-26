#pragma once

#include <string>

// ---------------------------------------------------------------------------
// ScheduledScan: one visible, user-level Task Scheduler entry that runs a
// Fast Scan every Sunday and writes an HTML report. Created only when the user
// asks for it from the menu or the command line, removable the same way.
// Never created in portable mode.
// ---------------------------------------------------------------------------

std::wstring WeeklyScanTaskName();

// The command line the task runs (exposed for tests and for the menu tooltip).
std::wstring WeeklyScanArguments(const std::wstring& baselinePath, const std::wstring& reportsDir);

bool RegisterWeeklyScan(const std::wstring& exePath, const std::wstring& baselinePath,
                        const std::wstring& reportsDir, std::wstring& error);
bool RemoveWeeklyScan(std::wstring& error);
bool IsWeeklyScanRegistered();
