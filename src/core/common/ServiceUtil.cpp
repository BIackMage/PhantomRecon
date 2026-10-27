#include "pch.h"
#include "ServiceUtil.h"

#include "AppPaths.h"
#include "TextUtils.h"

#pragma comment(lib, "advapi32.lib")

std::wstring ExtractServiceExePath(const std::wstring& imagePathIn)
{
    std::wstring imagePath = TrimW(imagePathIn);
    if (imagePath.empty()) return L"";

    std::wstring path;
    if (imagePath[0] == L'"') {
        size_t endQuote = imagePath.find(L'"', 1);
        path = (endQuote != std::wstring::npos) ? imagePath.substr(1, endQuote - 1) : imagePath.substr(1);
    }
    else {
        // Unquoted: cut after the first .exe / .sys / .dll occurrence.
        std::wstring lower = ToLowerW(imagePath);
        size_t best = std::wstring::npos;
        size_t bestLen = 0;
        const wchar_t* exts[] = { L".exe", L".sys", L".dll" };
        for (const wchar_t* ext : exts) {
            size_t pos = lower.find(ext);
            if (pos != std::wstring::npos && (best == std::wstring::npos || pos < best)) {
                best = pos;
                bestLen = wcslen(ext);
            }
        }
        if (best != std::wstring::npos) {
            path = imagePath.substr(0, best + bestLen);
        }
        else {
            size_t space = imagePath.find(L' ');
            path = (space != std::wstring::npos) ? imagePath.substr(0, space) : imagePath;
        }
    }

    path = ExpandEnvironment(path);

    // Kernel-style prefixes used by drivers and some services
    if (StartsWithI(path, L"\\SystemRoot\\")) {
        wchar_t windir[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", windir, MAX_PATH);
        path = std::wstring(windir) + path.substr(11);
    }
    else if (StartsWithI(path, L"\\??\\")) {
        path = path.substr(4);
    }
    else if (StartsWithI(path, L"system32\\")) {
        wchar_t windir[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", windir, MAX_PATH);
        path = std::wstring(windir) + L"\\" + path;
    }
    return path;
}

static bool FillConfig(SC_HANDLE hService, ServiceInfo& info)
{
    DWORD needed = 0;
    QueryServiceConfigW(hService, NULL, 0, &needed);
    if (needed == 0) return false;
    std::vector<BYTE> buffer(needed);
    LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
    if (!QueryServiceConfigW(hService, config, needed, &needed)) return false;

    if (config->lpBinaryPathName) {
        info.binaryPathRaw = config->lpBinaryPathName;
        info.exePath = ExtractServiceExePath(info.binaryPathRaw);
    }
    if (config->lpServiceStartName) info.account = config->lpServiceStartName;
    if (config->lpDisplayName && info.displayName.empty()) info.displayName = config->lpDisplayName;
    info.startType = config->dwStartType;
    info.serviceType = config->dwServiceType;
    info.configRead = true;
    return true;
}

std::vector<ServiceInfo> EnumerateServices(std::wstring* error)
{
    return EnumerateServicesOfType(SERVICE_WIN32, error);
}

std::vector<ServiceInfo> EnumerateServicesOfType(DWORD serviceType, std::wstring* error)
{
    std::vector<ServiceInfo> out;
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCM) {
        if (error) *error = L"Could not open the Service Control Manager (error " + std::to_wstring(GetLastError()) + L")";
        OutputDebugStringW((L"[ServiceUtil] OpenSCManager failed for service type " + std::to_wstring(serviceType) + L"\n").c_str());
        return out;
    }

    DWORD bytesNeeded = 0;
    DWORD count = 0;
    DWORD resume = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &count, &resume, NULL);

    std::vector<BYTE> buffer;
    bool more = true;
    resume = 0;
    while (more) {
        buffer.assign(static_cast<size_t>(bytesNeeded) + 4096, 0);
        DWORD needed = 0;
        count = 0;
        BOOL ok = EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL,
            buffer.data(), static_cast<DWORD>(buffer.size()), &needed, &count, &resume, NULL);
        more = !ok && GetLastError() == ERROR_MORE_DATA;
        if (!ok && !more) {
            if (error) *error = L"EnumServicesStatusEx failed (error " + std::to_wstring(GetLastError()) + L")";
            break;
        }

        LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
        for (DWORD i = 0; i < count; ++i) {
            ServiceInfo info;
            info.name = services[i].lpServiceName ? services[i].lpServiceName : L"";
            info.displayName = services[i].lpDisplayName ? services[i].lpDisplayName : L"";
            info.state = services[i].ServiceStatusProcess.dwCurrentState;
            info.processId = services[i].ServiceStatusProcess.dwProcessId;
            info.serviceType = services[i].ServiceStatusProcess.dwServiceType;

            SC_HANDLE hService = OpenServiceW(hSCM, info.name.c_str(), SERVICE_QUERY_CONFIG);
            if (hService) {
                FillConfig(hService, info);
                CloseServiceHandle(hService);
            }
            out.push_back(info);
        }
        if (more) bytesNeeded = needed;
    }

    CloseServiceHandle(hSCM);
    return out;
}

bool QueryServiceByName(const std::wstring& name, ServiceInfo& out)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = OpenServiceW(hSCM, name.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    out = ServiceInfo();
    out.name = name;
    FillConfig(hService, out);

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&ssp), sizeof(ssp), &needed)) {
        out.state = ssp.dwCurrentState;
        out.processId = ssp.dwProcessId;
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

std::wstring ServiceStartTypeName(DWORD startType)
{
    switch (startType) {
    case SERVICE_BOOT_START:   return L"Boot";
    case SERVICE_SYSTEM_START: return L"System";
    case SERVICE_AUTO_START:   return L"Automatic";
    case SERVICE_DEMAND_START: return L"Manual";
    case SERVICE_DISABLED:     return L"Disabled";
    default:                   return L"Unknown";
    }
}

std::wstring ServiceStateName(DWORD state)
{
    switch (state) {
    case SERVICE_RUNNING:          return L"Running";
    case SERVICE_STOPPED:          return L"Stopped";
    case SERVICE_START_PENDING:    return L"Starting";
    case SERVICE_STOP_PENDING:     return L"Stopping";
    case SERVICE_PAUSED:           return L"Paused";
    case SERVICE_PAUSE_PENDING:    return L"Pausing";
    case SERVICE_CONTINUE_PENDING: return L"Resuming";
    default:                       return L"Unknown";
    }
}
