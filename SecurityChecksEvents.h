#pragma once

#include <map>
#include <string>

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// SecurityChecksEvents: the "Recent activity" checks. They read this PC's own
// event logs (never another computer's) and report what happened lately. They
// describe events, not settings, so the catalog marks them as not scored.
// The verdicts come from EventRules; these functions gather the facts.
// ---------------------------------------------------------------------------

// events.logcleared: Security log cleared (1102) or any log cleared (System 104), 30 days.
SecurityCheckResult CheckEventsLogCleared();

// events.newservices: services installed (System 7045), 14 days.
SecurityCheckResult CheckEventsNewServices();

// events.newaccounts: local accounts created (4720), members added to Administrators (4732), 30 days.
SecurityCheckResult CheckEventsNewAccounts();

// events.failedlogons: failed sign-ins (4625) and lockouts (4740), 7 days.
SecurityCheckResult CheckEventsFailedLogons();

// events.defender: Microsoft Defender detections (1116, 1117) and real-time protection off (5001), 30 days.
SecurityCheckResult CheckEventsDefender();

// SID text ("S-1-5-21-...-1001") to account name for every local account of this PC,
// read from its own account database. events.newaccounts names members by it.
std::map<std::wstring, std::wstring> LocalAccountSids();
