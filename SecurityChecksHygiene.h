#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// SecurityChecksHygiene.cpp: settings that quietly weaken a PC: WDigest keeping
// sign-in passwords in memory, Windows Update paused or deferred, Remote Assistance
// offers, cached domain sign-ins, the inline mode of Windows' built-in sudo, and
// DNS over HTTPS. Everything is read from the registry and the file system, as a
// normal user where Windows allows it; nothing is changed and no other computer is
// contacted. Verdicts come from HygieneRules.cpp.
// ---------------------------------------------------------------------------

SecurityCheckResult CheckWDigest();              // cred.wdigest
SecurityCheckResult CheckUpdatePause();          // wu.paused
SecurityCheckResult CheckRemoteAssistance();     // net.remoteassist
SecurityCheckResult CheckCachedLogons();         // cred.cachedlogons
SecurityCheckResult CheckSudo();                 // hard.sudo
SecurityCheckResult CheckDnsOverHttps();         // net.doh
