#include "pch.h"
#include "DeviceGuard.h"

#include "TextUtils.h"
#include "WmiQuery.h"

#include <algorithm>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[DeviceGuard] " + msg + L"\n").c_str());
}

std::vector<int> ParseDeviceGuardList(const std::wstring& text)
{
    std::vector<int> out;
    for (const std::wstring& part : SplitAnyW(text, L"\n,; ")) {
        if (part.empty() || part.size() > 9) continue;
        bool digits = std::all_of(part.begin(), part.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; });
        if (!digits) continue;
        out.push_back(_wtoi(part.c_str()));
    }
    return out;
}

bool DeviceGuardHas(const std::vector<int>& services, int service)
{
    return std::find(services.begin(), services.end(), service) != services.end();
}

DeviceGuardStatus ReadDeviceGuardStatus()
{
    DeviceGuardStatus status;
    WmiResult wmi = WmiQuery(L"ROOT\\Microsoft\\Windows\\DeviceGuard",
        L"SELECT SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard",
        { L"SecurityServicesConfigured", L"SecurityServicesRunning", L"VirtualizationBasedSecurityStatus" });
    if (!wmi.ok || wmi.rows.empty()) {
        status.error = wmi.ok ? std::wstring(L"Win32_DeviceGuard returned no data") : wmi.error;
        DebugLog(L"Device Guard unavailable: " + status.error);
        return status;
    }
    status.ok = true;
    const WmiRow& row = wmi.rows[0];
    auto configured = row.find(L"SecurityServicesConfigured");
    auto running = row.find(L"SecurityServicesRunning");
    auto vbs = row.find(L"VirtualizationBasedSecurityStatus");
    if (configured != row.end()) status.configured = ParseDeviceGuardList(configured->second);
    if (running != row.end()) status.running = ParseDeviceGuardList(running->second);
    if (vbs != row.end() && !TrimW(vbs->second).empty()) status.vbsStatus = _wtoi(vbs->second.c_str());

    std::wstring runningText;
    for (int s : status.running) runningText += std::to_wstring(s) + L" ";
    DebugLog(L"Device Guard: VBS status " + std::to_wstring(status.vbsStatus) + L", running services [ " + runningText + L"]");
    return status;
}
