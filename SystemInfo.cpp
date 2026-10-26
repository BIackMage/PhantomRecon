#include "pch.h"
#include "SystemInfo.h"

#include "RegUtil.h"

#include <lm.h>
#include <userenv.h>
#include <sstream>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

std::wstring GetComputerNameString()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
    if (!GetComputerNameW(name, &size)) return L"Unknown";
    return std::wstring(name);
}

std::wstring GetProcessorInfo()
{
    SYSTEM_INFO sysInfo = {};
    GetNativeSystemInfo(&sysInfo);

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
    ss << GetWindowsVersionText() << L"\n";
    ss << GetProcessorInfo() << L"\n";
    ss << GetRamInfo() << L"\n";
    ss << GetDiskSpaceInfo() << L"\n";
    return ss.str();
}

DWORD GetWindowsBuildNumber()
{
    std::wstring build = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    return static_cast<DWORD>(_wtoi(build.c_str()));
}

std::wstring GetWindowsVersionText()
{
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::wstring product = RegReadString(HKEY_LOCAL_MACHINE, key, L"ProductName");
    std::wstring display = RegReadString(HKEY_LOCAL_MACHINE, key, L"DisplayVersion");
    DWORD build = GetWindowsBuildNumber();
    // ProductName still says "Windows 10" on Windows 11; the build number tells them apart.
    if (build >= 22000 && product.find(L"Windows 10") != std::wstring::npos) {
        product.replace(product.find(L"Windows 10"), 10, L"Windows 11");
    }
    std::wstringstream ss;
    ss << L"OS: " << (product.empty() ? L"Windows" : product);
    if (!display.empty()) ss << L" " << display;
    ss << L" (build " << build << L")";
    return ss.str();
}

bool IsProcessElevated()
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool SetProcessPrivilege(const wchar_t* privilegeName, bool enable)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);
    return ok && err == ERROR_SUCCESS;
}

std::wstring GetCurrentUserNameString()
{
    wchar_t name[256] = {};
    DWORD size = 256;
    if (!GetUserNameW(name, &size)) return L"";
    return name;
}

std::wstring GetUserProfileDirectory()
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return buf;
    return L"";
}

std::wstring GetJoinedDomainName()
{
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    if (NetGetJoinInformation(NULL, &name, &status) != NERR_Success) return L"";
    if (name) NetApiBufferFree(name);
    if (status != NetSetupDomainName) return L"";

    wchar_t dns[256] = {};
    DWORD size = 256;
    if (GetComputerNameExW(ComputerNameDnsDomain, dns, &size) && dns[0]) return dns;
    return L"";
}

long long FileTimeToUnix(const FILETIME& ft)
{
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    if (li.QuadPart < 116444736000000000ULL) return 0;
    return static_cast<long long>((li.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

std::wstring FormatFileTime(const FILETIME& ft)
{
    FILETIME local;
    SYSTEMTIME st = {};
    if (!FileTimeToLocalFileTime(&ft, &local) || !FileTimeToSystemTime(&local, &st)) return L"";
    wchar_t buf[40];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}

std::wstring FormatUnixTime(long long unixSeconds)
{
    ULARGE_INTEGER li;
    li.QuadPart = static_cast<ULONGLONG>(unixSeconds) * 10000000ULL + 116444736000000000ULL;
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;
    return FormatFileTime(ft);
}
