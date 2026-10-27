#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// DeviceGuard: one read of Win32_DeviceGuard (ROOT\Microsoft\Windows\DeviceGuard),
// shared by the Credential Guard and memory integrity checks. Read-only.
//
// SecurityServicesConfigured / SecurityServicesRunning hold service numbers:
// 1 Credential Guard, 2 memory integrity (hypervisor-protected code integrity),
// 3 System Guard Secure Launch, 4 SMM firmware measurement, 5 and 6 kernel-mode
// hardware-enforced stack protection, 7 hypervisor-enforced paging translation.
// ---------------------------------------------------------------------------

const int kDeviceGuardCredentialGuard = 1;
const int kDeviceGuardMemoryIntegrity = 2;

struct DeviceGuardStatus {
    bool             ok = false;      // the class answered with a row
    std::wstring     error;           // why not, when !ok
    std::vector<int> configured;      // SecurityServicesConfigured
    std::vector<int> running;         // SecurityServicesRunning
    int              vbsStatus = -1;  // VirtualizationBasedSecurityStatus: 0 off, 1 enabled not running, 2 running; -1 unknown
};

// A WMI array as WmiQuery returns it ("2\n7") to numbers. Entries that are not
// numbers are skipped.
std::vector<int> ParseDeviceGuardList(const std::wstring& text);

bool DeviceGuardHas(const std::vector<int>& services, int service);

// Asks WMI. Works without administrator rights on Windows 10 and 11.
DeviceGuardStatus ReadDeviceGuardStatus();
