#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// SecurityChecksDrivers.cpp: driver services registered with the Service Control
// Manager, judged by the file each one names on disk. Only the configuration is
// read: nothing is started or stopped, and loaded kernel modules and their
// addresses are never listed. Verdicts come from HostRules.cpp.
// ---------------------------------------------------------------------------

SecurityCheckResult CheckDriverServices();   // svc.drivers
