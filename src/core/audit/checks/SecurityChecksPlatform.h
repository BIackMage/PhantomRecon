#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// SecurityChecksPlatform.cpp: Windows platform protections. Each check reads
// settings and hands the facts to PlatformRules.cpp for the verdict.
// ---------------------------------------------------------------------------

SecurityCheckResult CheckMemoryIntegrity();     // hard.hvci
SecurityCheckResult CheckDriverBlocklist();     // hard.driverblocklist
SecurityCheckResult CheckSmartAppControl();     // hard.smartapp
SecurityCheckResult CheckExploitProtection();   // hard.exploitprot
SecurityCheckResult CheckScreenLock();          // acct.screenlock
SecurityCheckResult CheckSystemRestore();       // backup.restore
