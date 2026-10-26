#include "pch.h"
#include "SystemInfo.h"

#include <sstream>

std::wstring GetComputerNameString()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
    if (!GetComputerNameW(name, &size)) {
        return L"Unknown";
    }
    return std::wstring(name);
}

std::wstring GetProcessorInfo()
{
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);

    std::wstringstream ss;
    ss << L"Processor: ";
    switch (sysInfo.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: ss << L"AMD64 (x64)"; break;
    case PROCESSOR_ARCHITECTURE_ARM:   ss << L"ARM";         break;
    case PROCESSOR_ARCHITECTURE_ARM64: ss << L"ARM64";       break;
    case PROCESSOR_ARCHITECTURE_IA64:  ss << L"IA64";        break;
    case PROCESSOR_ARCHITECTURE_INTEL: ss << L"Intel";       break;
    default:                           ss << L"Unknown";     break;
    }
    ss << L", Cores: " << sysInfo.dwNumberOfProcessors;
    return ss.str();
}

std::wstring GetRamInfo()
{
    MEMORYSTATUSEX memInfo = {};
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);

    std::wstringstream ss;
    ss << L"RAM: " << (memInfo.ullTotalPhys / (1024ULL * 1024ULL)) << L" MB";
    return ss.str();
}

std::wstring GetDiskSpaceInfo()
{
    ULARGE_INTEGER freeBytesAvailable = {};
    ULARGE_INTEGER totalBytes = {};
    ULARGE_INTEGER totalFreeBytes = {};
    GetDiskFreeSpaceExW(NULL, &freeBytesAvailable, &totalBytes, &totalFreeBytes);

    const ULONGLONG gib = 1024ULL * 1024ULL * 1024ULL;
    std::wstringstream ss;
    ss << L"Disk Space: " << (totalBytes.QuadPart / gib) << L" GB"
       << L" (Used: " << ((totalBytes.QuadPart - totalFreeBytes.QuadPart) / gib) << L" GB"
       << L", Free: " << (totalFreeBytes.QuadPart / gib) << L" GB)";
    return ss.str();
}

std::wstring BuildSystemInfoText()
{
    std::wstringstream ss;
    ss << L"Computer: " << GetComputerNameString() << L"\n";
    ss << GetProcessorInfo() << L"\n";
    ss << GetRamInfo() << L"\n";
    ss << GetDiskSpaceInfo() << L"\n";
    return ss.str();
}
