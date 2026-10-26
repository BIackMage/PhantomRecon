#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// Additional security checks (Phase 1.5)
// Separated from SecurityChecks.h/cpp to keep modules small.
// ---------------------------------------------------------------------------

// Startup programs in Run/RunOnce registry keys and Startup folders
SecurityCheckResult CheckStartupPrograms();

// Scheduled tasks that may indicate persistence
SecurityCheckResult CheckScheduledTasks();

// PowerShell execution policy and logging configuration
SecurityCheckResult CheckPowerShellPolicy();

// Windows Firewall status across all profiles (Domain, Private, Public)
SecurityCheckResult CheckWindowsFirewall();

// Audit policy configuration (are key events being logged?)
SecurityCheckResult CheckAuditPolicy();

// Windows Update status (is the service running, when was last update?)
SecurityCheckResult CheckWindowsUpdateStatus();
