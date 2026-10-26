#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// Every check function, grouped by the file that implements it. The audit
// runner (AuditRunner.cpp) registers them in report order.
// ---------------------------------------------------------------------------

// SecurityChecksExtra.cpp
SecurityCheckResult CheckPowerShellLogging();
SecurityCheckResult CheckWindowsFirewall();
SecurityCheckResult CheckEventLogSettings();
SecurityCheckResult CheckWindowsUpdateStatus();

// SecurityChecksDefender.cpp
SecurityCheckResult CheckDefenderRealtime();
SecurityCheckResult CheckDefenderTamper();
SecurityCheckResult CheckDefenderCloud();
SecurityCheckResult CheckDefenderSignatures();
SecurityCheckResult CheckDefenderExclusions();
SecurityCheckResult CheckDefenderAsr();
SecurityCheckResult CheckSmartScreen();
SecurityCheckResult CheckControlledFolderAccess();

// SecurityChecksHardening.cpp
SecurityCheckResult CheckBitLocker();
SecurityCheckResult CheckTpm();
SecurityCheckResult CheckSecureBoot();
SecurityCheckResult CheckUac();
SecurityCheckResult CheckAutoPlay();
SecurityCheckResult CheckWindowsScriptHost();
SecurityCheckResult CheckPowerShellV2();
SecurityCheckResult CheckOfficeMacros();
SecurityCheckResult CheckLsaProtection();
SecurityCheckResult CheckSmbV1();
SecurityCheckResult CheckRemoteDesktop();
SecurityCheckResult CheckWinRm();
SecurityCheckResult CheckRemoteRegistry();
SecurityCheckResult CheckPrintSpooler();

// SecurityChecksAccounts.cpp
SecurityCheckResult CheckGuestAccount();
SecurityCheckResult CheckBuiltinAdministrator();
SecurityCheckResult CheckLocalAccounts();
SecurityCheckResult CheckPasswordPolicy();

// SecurityChecksAudit.cpp
SecurityCheckResult CheckAuditSubcategories();

// SecurityChecksTasks.cpp
SecurityCheckResult CheckScheduledTasks();

// SecurityChecksNetwork.cpp
SecurityCheckResult CheckListeningPorts();
SecurityCheckResult CheckHostsFile();
SecurityCheckResult CheckDnsSettings();

// SecurityChecksSoftware.cpp
SecurityCheckResult CheckOutdatedSoftware();
SecurityCheckResult CheckRootCertificates();

// SecurityChecksPaths.cpp
SecurityCheckResult CheckDllSearchPaths();
SecurityCheckResult CheckGppPasswords();

// SecurityChecksPersistence.cpp
SecurityCheckResult CheckPersistence(const AuditContext& context);

// SecurityChecksProcesses.cpp
SecurityCheckResult CheckRunningPrograms(const AuditContext& context);
