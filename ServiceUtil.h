#pragma once

#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// ServiceUtil: one enumeration of Win32 services shared by every check that
// cares about services (unquoted paths, writable binaries, DLL search folders,
// persistence, spooler / WinRM / Remote Registry state).
// ---------------------------------------------------------------------------

struct ServiceInfo {
    std::wstring name;
    std::wstring displayName;
    std::wstring binaryPathRaw;   // ImagePath exactly as configured
    std::wstring exePath;         // program part of the ImagePath, expanded
    std::wstring account;         // ServiceStartName (LocalSystem, NT AUTHORITY\LocalService, ...)
    DWORD        startType = 0;   // SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED, ...
    DWORD        state = 0;       // SERVICE_RUNNING, SERVICE_STOPPED, ...
    DWORD        serviceType = 0;
    DWORD        processId = 0;
    bool         configRead = false;   // QueryServiceConfig answered (this account may read the configuration)
};

// All Win32 services. Empty (and error set) if the SCM cannot be opened.
std::vector<ServiceInfo> EnumerateServices(std::wstring* error = nullptr);

// All services of one kind: SERVICE_WIN32, SERVICE_DRIVER, ... Only reads the
// configuration; nothing is started, stopped or changed. Empty (and error set) if the
// SCM cannot be opened or the enumeration fails.
std::vector<ServiceInfo> EnumerateServicesOfType(DWORD serviceType, std::wstring* error = nullptr);

// One service by name. False if missing.
bool QueryServiceByName(const std::wstring& name, ServiceInfo& out);

// Extract the program path from a service ImagePath (handles quotes, arguments,
// \SystemRoot\ and \??\ prefixes, environment variables).
std::wstring ExtractServiceExePath(const std::wstring& imagePath);

std::wstring ServiceStartTypeName(DWORD startType);
std::wstring ServiceStateName(DWORD state);
