#pragma once

#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// SecurityChecksWireless.cpp: saved Wi-Fi networks, read through the Native
// Wifi API. Key material is never requested, kept or shown.
// ---------------------------------------------------------------------------

SecurityCheckResult CheckOpenWifi();   // net.wifiopen
