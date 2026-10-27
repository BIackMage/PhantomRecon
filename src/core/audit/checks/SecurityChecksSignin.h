#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// SecurityChecksSignin.cpp: how this PC signs people in. Automatic sign-in with a
// stored password, and the old LAN Manager and NTLM sign-in protocols. A stored
// password is never read: only whether the value exists. Verdicts come from
// HostRules.cpp.
// ---------------------------------------------------------------------------

SecurityCheckResult CheckAutoLogon();        // acct.autologon
SecurityCheckResult CheckNtlmSettings();     // cred.ntlm
